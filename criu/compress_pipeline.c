/*
 * compress_pipeline.c — parallel compress + S3 multipart upload pipeline.
 *
 * Architecture (see compress_pipeline.h for the contract):
 *
 *   submit() -->  [compress queue] --> N compress workers --> [writer queue]
 *                                                              --> writer
 *                                                                   |
 *                                                              [part buffer 8MB]
 *                                                                   |
 *                                                            [upload queue]
 *                                                                   |
 *                                                             M upload workers
 *                                                                   |
 *                                                             etags[part_num]
 *
 * The compress workers produce frames out of order; the writer thread blocks
 * until the next in-order frame is available (condvar indexed by seq number),
 * then appends it to the current part buffer and logs it into the
 * ZSTD_seekable frame log. When the part buffer fills up, the writer enqueues
 * it to the upload pool and swaps in a fresh buffer. At finalize, the writer
 * serializes the seek table into the last part and signals the upload pool
 * end-of-input.
 *
 * Back-pressure: bounded queues limit concurrent raw IOVs and compressed
 * parts in flight. submit() will block on a full compress queue.
 */

#define pr_fmt(fmt) "compress_pipeline: " fmt

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zstd.h>

#include "zstd_seekable.h"

#include "compress_pipeline.h"
#include "log.h"
#include "object-storage.h"
#include "xmalloc.h"

#define PART_SIZE	(8UL * 1024 * 1024)
#define ETAG_LEN	128

/* ------------------------------------------------------------------------- *
 * Frame record flowing through compress + writer stages.
 * ------------------------------------------------------------------------- */

struct frame_rec {
	unsigned int seq;	/* submit order */
	void *raw;		/* owned raw bytes */
	size_t raw_len;

	void *comp;		/* owned compressed bytes (filled by worker) */
	size_t comp_len;

	struct frame_rec *next;	/* for queue and writer waitlist */
};

/* ------------------------------------------------------------------------- *
 * Bounded FIFO queue.
 * ------------------------------------------------------------------------- */

struct q {
	struct frame_rec *head, *tail;
	int count;
	int cap;
	bool closed;
	pthread_mutex_t lock;
	pthread_cond_t not_empty;
	pthread_cond_t not_full;
};

static void q_init(struct q *q, int cap)
{
	q->head = q->tail = NULL;
	q->count = 0;
	q->cap = cap;
	q->closed = false;
	pthread_mutex_init(&q->lock, NULL);
	pthread_cond_init(&q->not_empty, NULL);
	pthread_cond_init(&q->not_full, NULL);
}

static void q_destroy(struct q *q)
{
	pthread_mutex_destroy(&q->lock);
	pthread_cond_destroy(&q->not_empty);
	pthread_cond_destroy(&q->not_full);
}

static int q_push(struct q *q, struct frame_rec *f)
{
	pthread_mutex_lock(&q->lock);
	while (q->count >= q->cap && !q->closed)
		pthread_cond_wait(&q->not_full, &q->lock);
	if (q->closed) {
		pthread_mutex_unlock(&q->lock);
		return -1;
	}
	f->next = NULL;
	if (q->tail)
		q->tail->next = f;
	else
		q->head = f;
	q->tail = f;
	q->count++;
	pthread_cond_signal(&q->not_empty);
	pthread_mutex_unlock(&q->lock);
	return 0;
}

static struct frame_rec *q_pop(struct q *q)
{
	struct frame_rec *f;

	pthread_mutex_lock(&q->lock);
	while (q->count == 0 && !q->closed)
		pthread_cond_wait(&q->not_empty, &q->lock);
	if (q->count == 0) {
		pthread_mutex_unlock(&q->lock);
		return NULL;
	}
	f = q->head;
	q->head = f->next;
	if (!q->head)
		q->tail = NULL;
	q->count--;
	pthread_cond_signal(&q->not_full);
	pthread_mutex_unlock(&q->lock);
	return f;
}

static void q_close(struct q *q)
{
	pthread_mutex_lock(&q->lock);
	q->closed = true;
	pthread_cond_broadcast(&q->not_empty);
	pthread_cond_broadcast(&q->not_full);
	pthread_mutex_unlock(&q->lock);
}

/* ------------------------------------------------------------------------- *
 * Writer waitlist: frames arrive out-of-order; writer consumes in seq order.
 * Implemented as a sorted singly-linked list keyed on seq, O(n) insert but
 * n is bounded by the compress-queue depth so fine in practice.
 * ------------------------------------------------------------------------- */

struct waitlist {
	struct frame_rec *head;
	unsigned int next_expected;
	bool closed;
	pthread_mutex_t lock;
	pthread_cond_t cond;
};

static void waitlist_init(struct waitlist *wl)
{
	wl->head = NULL;
	wl->next_expected = 0;
	wl->closed = false;
	pthread_mutex_init(&wl->lock, NULL);
	pthread_cond_init(&wl->cond, NULL);
}

static void waitlist_destroy(struct waitlist *wl)
{
	pthread_mutex_destroy(&wl->lock);
	pthread_cond_destroy(&wl->cond);
}

static void waitlist_put(struct waitlist *wl, struct frame_rec *f)
{
	struct frame_rec **p;

	pthread_mutex_lock(&wl->lock);
	for (p = &wl->head; *p && (*p)->seq < f->seq; p = &(*p)->next)
		;
	f->next = *p;
	*p = f;
	/*
	 * Always signal: writer may be waiting for a gap that this insert
	 * still doesn't fill, but cheap signals are fine.
	 */
	pthread_cond_signal(&wl->cond);
	pthread_mutex_unlock(&wl->lock);
}

/*
 * Get the frame at next_expected, blocking until it arrives. Returns NULL
 * if the waitlist is closed and no more frames will come.
 */
static struct frame_rec *waitlist_pop_in_order(struct waitlist *wl)
{
	struct frame_rec *f;

	pthread_mutex_lock(&wl->lock);
	while (!wl->closed && (!wl->head || wl->head->seq != wl->next_expected))
		pthread_cond_wait(&wl->cond, &wl->lock);
	if (!wl->head || wl->head->seq != wl->next_expected) {
		pthread_mutex_unlock(&wl->lock);
		return NULL;
	}
	f = wl->head;
	wl->head = f->next;
	wl->next_expected++;
	pthread_mutex_unlock(&wl->lock);
	return f;
}

static void waitlist_close(struct waitlist *wl)
{
	pthread_mutex_lock(&wl->lock);
	wl->closed = true;
	pthread_cond_broadcast(&wl->cond);
	pthread_mutex_unlock(&wl->lock);
}

/* ------------------------------------------------------------------------- *
 * Part record flowing into upload queue.
 * ------------------------------------------------------------------------- */

struct part_rec {
	int part_num;		/* S3 multipart part_number (1-based) */
	void *data;		/* owned */
	size_t len;
	struct part_rec *next;
};

struct upload_q {
	struct part_rec *head, *tail;
	int count;
	int cap;
	bool closed;
	pthread_mutex_t lock;
	pthread_cond_t not_empty;
	pthread_cond_t not_full;
};

static void upq_init(struct upload_q *q, int cap)
{
	q->head = q->tail = NULL;
	q->count = 0;
	q->cap = cap;
	q->closed = false;
	pthread_mutex_init(&q->lock, NULL);
	pthread_cond_init(&q->not_empty, NULL);
	pthread_cond_init(&q->not_full, NULL);
}

static void upq_destroy(struct upload_q *q)
{
	pthread_mutex_destroy(&q->lock);
	pthread_cond_destroy(&q->not_empty);
	pthread_cond_destroy(&q->not_full);
}

static __attribute__((unused))
int upq_push(struct upload_q *q, struct part_rec *p)
{
	pthread_mutex_lock(&q->lock);
	while (q->count >= q->cap && !q->closed)
		pthread_cond_wait(&q->not_full, &q->lock);
	if (q->closed) {
		pthread_mutex_unlock(&q->lock);
		return -1;
	}
	p->next = NULL;
	if (q->tail)
		q->tail->next = p;
	else
		q->head = p;
	q->tail = p;
	q->count++;
	pthread_cond_signal(&q->not_empty);
	pthread_mutex_unlock(&q->lock);
	return 0;
}

static struct part_rec *upq_pop(struct upload_q *q)
{
	struct part_rec *p;

	pthread_mutex_lock(&q->lock);
	while (q->count == 0 && !q->closed)
		pthread_cond_wait(&q->not_empty, &q->lock);
	if (q->count == 0) {
		pthread_mutex_unlock(&q->lock);
		return NULL;
	}
	p = q->head;
	q->head = p->next;
	if (!q->head)
		q->tail = NULL;
	q->count--;
	pthread_cond_signal(&q->not_full);
	pthread_mutex_unlock(&q->lock);
	return p;
}

static void upq_close(struct upload_q *q)
{
	pthread_mutex_lock(&q->lock);
	q->closed = true;
	pthread_cond_broadcast(&q->not_empty);
	pthread_cond_broadcast(&q->not_full);
	pthread_mutex_unlock(&q->lock);
}

/* ------------------------------------------------------------------------- *
 * Pipeline.
 * ------------------------------------------------------------------------- */

struct compress_pipeline {
	char object_key[512];
	char upload_id[256];
	int level;

	/* Compress stage */
	int n_compress;
	pthread_t *compress_threads;
	struct q compress_in;
	struct waitlist writer_in;

	/* Writer stage — runs on the main thread during finalize(), not a
	 * dedicated thread. See writer_drain() for the rationale. */
	unsigned int n_frames_submitted;
	ZSTD_frameLog *frame_log;

	/* Upload stage */
	int n_upload;
	pthread_t *upload_threads;
	struct upload_q upload_in;

	/* etag table (grown as part_num increases) */
	pthread_mutex_t etags_lock;
	char **etags;
	int etags_cap;
	int n_parts;

	/* Error propagation */
	pthread_mutex_t err_lock;
	int err;
};

/* Record the first error; subsequent callers overwrite silently. */
static void pipe_set_error(struct compress_pipeline *p, int err)
{
	pthread_mutex_lock(&p->err_lock);
	if (!p->err)
		p->err = err;
	pthread_mutex_unlock(&p->err_lock);
}

int compress_pipeline_error(struct compress_pipeline *p)
{
	int e;
	pthread_mutex_lock(&p->err_lock);
	e = p->err;
	pthread_mutex_unlock(&p->err_lock);
	return e;
}

/* ----- Compress worker ----- */

static void *compress_worker(void *arg)
{
	struct compress_pipeline *p = arg;
	ZSTD_CCtx *ctx = ZSTD_createCCtx();
	struct frame_rec *f;

	if (!ctx) {
		pr_err("ZSTD_createCCtx failed\n");
		pipe_set_error(p, -1);
		return NULL;
	}
	ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, p->level);

	while ((f = q_pop(&p->compress_in)) != NULL) {
		size_t bound = ZSTD_compressBound(f->raw_len);
		size_t rc;

		f->comp = xmalloc(bound);
		if (!f->comp) {
			pipe_set_error(p, -1);
			break;
		}
		rc = ZSTD_compress2(ctx, f->comp, bound, f->raw, f->raw_len);
		if (ZSTD_isError(rc)) {
			pr_err("ZSTD_compress2: %s\n", ZSTD_getErrorName(rc));
			pipe_set_error(p, -1);
			break;
		}
		f->comp_len = rc;
		/* raw bytes aren't needed anymore — writer only wants comp */
		xfree(f->raw);
		f->raw = NULL;
		waitlist_put(&p->writer_in, f);
	}

	ZSTD_freeCCtx(ctx);
	return NULL;
}

/* ----- Upload worker ----- */

static void etags_reserve(struct compress_pipeline *p, int need)
{
	if (need <= p->etags_cap)
		return;
	{
		int cap = p->etags_cap ? p->etags_cap : 16;
		char **nt;
		while (cap < need)
			cap *= 2;
		nt = xrealloc(p->etags, cap * sizeof(*nt));
		if (!nt) {
			pipe_set_error(p, -1);
			return;
		}
		memset(nt + p->etags_cap, 0,
		       (cap - p->etags_cap) * sizeof(*nt));
		p->etags = nt;
		p->etags_cap = cap;
	}
}

/*
 * Upload worker threads are currently dormant (writer uploads
 * synchronously to keep all S3 requests on one thread — see
 * writer_upload_part for the rationale). The threads still start up
 * and sit on upq_pop() just so the pipeline shutdown logic stays the
 * same; they exit immediately once upq_close() is called at end-of-stream.
 */
static void *upload_worker(void *arg)
{
	struct compress_pipeline *p = arg;
	struct part_rec *rec;

	while ((rec = upq_pop(&p->upload_in)) != NULL) {
		/* No records should ever land here now. */
		xfree(rec->data);
		xfree(rec);
	}
	return NULL;
}

/* ----- Writer thread ----- */

/*
 * Grow a heap buffer to hold at least `need` bytes. Returns 0 on success
 * or -1 on allocation failure.
 */
static int ensure_cap(void **buf, size_t *cap, size_t need)
{
	size_t new_cap = *cap ? *cap : PART_SIZE;
	void *nb;

	if (need <= *cap)
		return 0;
	while (new_cap < need)
		new_cap *= 2;
	nb = xrealloc(*buf, new_cap);
	if (!nb)
		return -1;
	*buf = nb;
	*cap = new_cap;
	return 0;
}

/*
 * Unused now that writer flushes synchronously; kept to minimize diff.
 * Will be removed when the upload_q scaffolding is garbage-collected.
 */
static __attribute__((unused))
int writer_flush_part(struct compress_pipeline *p, void **part_buf,
		      size_t *part_used, size_t *part_cap,
		      int *part_num)
{
	(void)p; (void)part_buf; (void)part_used; (void)part_cap; (void)part_num;
	return 0;
}

/*
 * Synchronous upload from the writer thread. Calling multipart upload
 * from multiple worker threads concurrently destabilizes libcurl's
 * per-process state in CRIU (we saw parasite RPCs break with
 * "Trimmed message received"); keeping all S3 requests on a single
 * thread fixes it. Compress parallelism is still preserved via the
 * N compress workers, which don't touch libcurl at all.
 */
static int writer_upload_part(struct compress_pipeline *p, int *part_num,
			      void *data, size_t len)
{
	char etag[ETAG_LEN];
	int rc;

	rc = object_storage_multipart_upload_part(p->object_key,
						  p->upload_id,
						  ++(*part_num),
						  data, len,
						  etag, sizeof(etag));
	if (rc < 0) {
		pr_err("multipart upload part %d failed\n", *part_num);
		return -1;
	}
	pthread_mutex_lock(&p->etags_lock);
	etags_reserve(p, *part_num);
	if (p->etags) {
		xfree(p->etags[*part_num - 1]);
		p->etags[*part_num - 1] = xstrdup(etag);
		if (*part_num > p->n_parts)
			p->n_parts = *part_num;
	}
	pthread_mutex_unlock(&p->etags_lock);
	return 0;
}

/*
 * Drain the waitlist of compressed frames, buffering into 8 MB parts and
 * uploading them synchronously.
 *
 * This runs on the main thread during compress_pipeline_finalize(), not in
 * a dedicated writer thread. We used to have a writer thread but its
 * pthread_key destructor calling curl_easy_cleanup during thread exit
 * deterministically broke the parasite's tsock on workloads with
 * compress-workers > ~3 (parasite saw "Trimmed message received (12/0)").
 * Keeping libcurl usage on the main thread — the only thread that ever
 * interacts with the parasite RPC socket — avoids the whole class of
 * libcurl/OpenSSL cross-thread cleanup interactions.
 *
 * Compression parallelism is still preserved via the N compress workers;
 * only the final part-accumulation and upload serialize here.
 */
static void writer_drain(struct compress_pipeline *p)
{
	void *part_buf;
	size_t part_cap = PART_SIZE;
	size_t part_used = 0;
	int part_num = 0;
	struct frame_rec *f;

	part_buf = xmalloc(part_cap);
	if (!part_buf) {
		pipe_set_error(p, -1);
		return;
	}

	while ((f = waitlist_pop_in_order(&p->writer_in)) != NULL) {
		/* Append compressed frame to current part. */
		if (ensure_cap(&part_buf, &part_cap,
			       part_used + f->comp_len) < 0) {
			pipe_set_error(p, -1);
			break;
		}
		memcpy((char *)part_buf + part_used, f->comp, f->comp_len);
		part_used += f->comp_len;

		/* Log frame into the seekable frame log. */
		{
			size_t rc = ZSTD_seekable_logFrame(p->frame_log,
							   (unsigned)f->comp_len,
							   (unsigned)f->raw_len,
							   0);
			if (ZSTD_isError(rc)) {
				pr_err("ZSTD_seekable_logFrame: %s\n",
				       ZSTD_getErrorName(rc));
				pipe_set_error(p, -1);
				xfree(f->comp);
				xfree(f);
				break;
			}
		}

		xfree(f->comp);
		xfree(f);

		/* Flush if part is full (synchronous upload). */
		while (part_used >= PART_SIZE) {
			if (writer_upload_part(p, &part_num,
					       part_buf, PART_SIZE) < 0) {
				pipe_set_error(p, -1);
				goto out;
			}
			/* Shift leftover bytes to the head of part_buf. */
			memmove(part_buf, (char *)part_buf + PART_SIZE,
				part_used - PART_SIZE);
			part_used -= PART_SIZE;
		}
	}

	/*
	 * End of input. Append the seek table to the last part buffer. The
	 * seekable format's writeSeekTable is a streaming API — call it
	 * repeatedly until it returns 0.
	 */
	{
		size_t remaining = 1;
		ZSTD_outBuffer out;

		while (remaining > 0) {
			if (ensure_cap(&part_buf, &part_cap,
				       part_used + 4096) < 0) {
				pipe_set_error(p, -1);
				goto out;
			}
			out.dst = (char *)part_buf + part_used;
			out.size = part_cap - part_used;
			out.pos = 0;
			remaining = ZSTD_seekable_writeSeekTable(p->frame_log,
								 &out);
			if (ZSTD_isError(remaining)) {
				pr_err("ZSTD_seekable_writeSeekTable: %s\n",
				       ZSTD_getErrorName(remaining));
				pipe_set_error(p, -1);
				goto out;
			}
			part_used += out.pos;
		}
	}

	/* Flush final (possibly small) part synchronously. */
	if (part_used > 0) {
		if (writer_upload_part(p, &part_num, part_buf, part_used) < 0)
			pipe_set_error(p, -1);
	}

out:
	xfree(part_buf);
	upq_close(&p->upload_in);
}

/* ------------------------------------------------------------------------- *
 * Public API.
 * ------------------------------------------------------------------------- */

struct compress_pipeline *compress_pipeline_create(const char *object_key,
						   const char *upload_id,
						   int level,
						   int n_compress_workers,
						   int m_upload_workers)
{
	struct compress_pipeline *p;
	int i;

	p = xzalloc(sizeof(*p));
	if (!p)
		return NULL;

	strncpy(p->object_key, object_key, sizeof(p->object_key) - 1);
	strncpy(p->upload_id, upload_id, sizeof(p->upload_id) - 1);
	p->level = level > 0 ? level : 1;
	p->n_compress = n_compress_workers > 0 ? n_compress_workers : 4;
	p->n_upload = m_upload_workers > 0 ? m_upload_workers : 4;

	q_init(&p->compress_in, p->n_compress * 2);
	waitlist_init(&p->writer_in);
	upq_init(&p->upload_in, p->n_upload * 2);
	pthread_mutex_init(&p->etags_lock, NULL);
	pthread_mutex_init(&p->err_lock, NULL);

	/* checksumFlag=0: see compression.c rationale for monolithic. */
	p->frame_log = ZSTD_seekable_createFrameLog(0);
	if (!p->frame_log)
		goto err;

	p->compress_threads = xzalloc(p->n_compress * sizeof(pthread_t));
	p->upload_threads = xzalloc(p->n_upload * sizeof(pthread_t));
	if (!p->compress_threads || !p->upload_threads)
		goto err;

	/*
	 * CRIU dumps rely on fragile signal handling between the main process
	 * and the parasite that lives in the target. Worker threads created
	 * here inherit the process signal mask; if a signal CRIU is waiting
	 * to deliver to itself gets routed to one of our compress threads
	 * instead, the parasite RPC hangs (we saw this as
	 * "Trimmed message received (12/0)"). Block every signal in the
	 * workers before launching them.
	 */
	{
		sigset_t block_all, old;
		sigfillset(&block_all);
		pthread_sigmask(SIG_SETMASK, &block_all, &old);

		for (i = 0; i < p->n_compress; i++) {
			if (pthread_create(&p->compress_threads[i], NULL,
					   compress_worker, p) != 0) {
				pr_err("pthread_create compress_worker\n");
				pthread_sigmask(SIG_SETMASK, &old, NULL);
				goto err;
			}
		}
		/*
		 * The writer role is handled by the main thread during
		 * compress_pipeline_finalize(). No separate writer or upload
		 * worker thread is launched: a background thread doing
		 * curl_easy_cleanup on its pthread_key destructor
		 * deterministically broke the parasite RPC socket for any
		 * --compress-workers above ~3 (see writer_drain comment).
		 * All libcurl activity is pinned to the main thread.
		 */
		(void)upload_worker;
		(void)etags_reserve;
		p->n_upload = 0;

		pthread_sigmask(SIG_SETMASK, &old, NULL);
	}
	return p;

err:
	compress_pipeline_destroy(p);
	return NULL;
}

int compress_pipeline_submit(struct compress_pipeline *p,
			     const void *data, size_t len)
{
	struct frame_rec *f;

	if (compress_pipeline_error(p))
		return -1;

	f = xzalloc(sizeof(*f));
	if (!f)
		return -1;
	f->raw = xmalloc(len);
	if (!f->raw) {
		xfree(f);
		return -1;
	}
	memcpy(f->raw, data, len);
	f->raw_len = len;
	f->seq = p->n_frames_submitted++;

	if (q_push(&p->compress_in, f) < 0) {
		xfree(f->raw);
		xfree(f);
		return -1;
	}
	return 0;
}

int compress_pipeline_finalize(struct compress_pipeline *p,
			       char ***out_etags, int *out_n_parts)
{
	int i;

	/* No more submits: close compress queue so workers drain. */
	q_close(&p->compress_in);

	/*
	 * Wait for compress workers to finish, then close writer input.
	 * Zero each handle as we join so compress_pipeline_destroy() below
	 * doesn't double-join the same tid — pthread_join on an
	 * already-joined thread is undefined behavior and crashed for us
	 * at --compress-workers >= 5 on a 4-CPU box.
	 */
	for (i = 0; i < p->n_compress; i++) {
		pthread_join(p->compress_threads[i], NULL);
		p->compress_threads[i] = 0;
	}
	waitlist_close(&p->writer_in);

	/*
	 * Drain the waitlist + upload all parts + seek table from the main
	 * thread. Done inline (not a separate thread) to keep every libcurl
	 * call on the thread that also drives parasite RPC; see writer_drain().
	 */
	writer_drain(p);

	/* Wait for upload workers (dormant — kept for shutdown symmetry). */
	for (i = 0; i < p->n_upload; i++)
		pthread_join(p->upload_threads[i], NULL);

	if (compress_pipeline_error(p))
		return -1;

	/* Hand off etag array. */
	*out_etags = p->etags;
	*out_n_parts = p->n_parts;
	p->etags = NULL;
	p->etags_cap = 0;
	p->n_parts = 0;

	return 0;
}

void compress_pipeline_destroy(struct compress_pipeline *p)
{
	int i;

	if (!p)
		return;

	/* Best-effort: if the caller destroys mid-stream, close everything. */
	q_close(&p->compress_in);
	if (p->compress_threads) {
		for (i = 0; i < p->n_compress; i++)
			if (p->compress_threads[i])
				pthread_join(p->compress_threads[i], NULL);
		xfree(p->compress_threads);
	}
	waitlist_close(&p->writer_in);
	upq_close(&p->upload_in);
	if (p->upload_threads) {
		for (i = 0; i < p->n_upload; i++)
			if (p->upload_threads[i])
				pthread_join(p->upload_threads[i], NULL);
		xfree(p->upload_threads);
	}

	q_destroy(&p->compress_in);
	waitlist_destroy(&p->writer_in);
	upq_destroy(&p->upload_in);
	pthread_mutex_destroy(&p->etags_lock);
	pthread_mutex_destroy(&p->err_lock);

	if (p->frame_log)
		ZSTD_seekable_freeFrameLog(p->frame_log);

	if (p->etags) {
		for (i = 0; i < p->etags_cap; i++)
			xfree(p->etags[i]);
		xfree(p->etags);
	}

	xfree(p);
}
