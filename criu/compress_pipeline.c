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
#include "upload_pool.h"
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

	/* Writer stage — runs in its own thread spawned at create() time.
	 *
	 * The writer thread owns the upload_pool: it creates it on entry,
	 * drives CURLM, submits SG parts as compress workers produce frames,
	 * and runs upload_pool_wait() / get_etags() on exit. This lets
	 * compress and S3 upload overlap (raw path already overlapped via
	 * inline _flush_object_storage_part; compressed path used to
	 * stall all uploads until finalize). All libcurl/CURLM calls stay
	 * on this single thread so no cross-thread libcurl interaction. */
	unsigned int n_frames_submitted;
	ZSTD_frameLog *frame_log;
	pthread_t writer_thread;
	int writer_thread_started;

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

	/*
	 * Accumulated compress-side stats. Protected by stat_lock (workers run
	 * in parallel). Logged once in compress_pipeline_destroy so we can
	 * see for a whole dump how many frames were produced, the aggregate
	 * uncompressed-byte throughput of the compress stage, and the
	 * ratio achieved. Same key "compress_stats:" that
	 * `parse_ablation.py` picks up alongside decompress_stats.
	 */
	pthread_mutex_t stat_lock;
	unsigned long stat_frames;
	unsigned long long stat_bytes_in;   /* uncompressed */
	unsigned long long stat_bytes_out;  /* compressed */
	unsigned long long stat_compress_ns;
};

/* Monotonic ns helper (same as compression.c's). */
#include <time.h>
static inline unsigned long long _mono_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

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
		unsigned long long t0;

		f->comp = xmalloc(bound);
		if (!f->comp) {
			pipe_set_error(p, -1);
			break;
		}
		t0 = _mono_ns();
		rc = ZSTD_compress2(ctx, f->comp, bound, f->raw, f->raw_len);
		if (ZSTD_isError(rc)) {
			pr_err("ZSTD_compress2: %s\n", ZSTD_getErrorName(rc));
			pipe_set_error(p, -1);
			break;
		}
		f->comp_len = rc;

		pthread_mutex_lock(&p->stat_lock);
		p->stat_frames++;
		p->stat_bytes_in += f->raw_len;
		p->stat_bytes_out += rc;
		p->stat_compress_ns += _mono_ns() - t0;
		pthread_mutex_unlock(&p->stat_lock);

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

/*
 * Submit a SG list of compressed-frame chunks as one S3 multipart part.
 * Pool takes ownership of the chunks array AND each chunks[i].data on
 * success or failure (upload_pool_submit_sg contract). The chunk-list
 * pointer/counters are zeroed out so the caller can keep filling a
 * fresh batch.
 */
static int writer_sg_submit(struct upload_pool *pool, int part_num,
			    struct upload_sg_chunk **chunks_inout,
			    int *n_inout, int *cap_inout,
			    size_t *sum_inout)
{
	int rc = upload_pool_submit_sg(pool, part_num,
				       *chunks_inout, *n_inout, *sum_inout);
	*chunks_inout = NULL;
	*n_inout = 0;
	*cap_inout = 0;
	*sum_inout = 0;
	return rc;
}

/*
 * Append one chunk (compressed frame body) to the in-progress chunk list.
 * Grows the array geometrically. Caller transfers ownership of `data`
 * to the chunks list — pool will xfree it once the part lands.
 */
static int writer_sg_append(struct upload_sg_chunk **chunks,
			    int *n, int *cap, size_t *sum,
			    void *data, size_t len)
{
	if (*n >= *cap) {
		int new_cap = *cap ? *cap * 2 : 32;
		struct upload_sg_chunk *nc = xrealloc(*chunks,
			new_cap * sizeof(**chunks));
		if (!nc)
			return -1;
		*chunks = nc;
		*cap = new_cap;
	}
	(*chunks)[*n].data = data;
	(*chunks)[*n].len = len;
	(*n)++;
	*sum += len;
	return 0;
}

/*
 * Drain the waitlist of compressed frames, assemble PART_SIZE-aligned
 * scatter-gather batches, and feed them to the CURLM upload_pool. The
 * frame buffers are forwarded zero-copy: each frame's compressed bytes
 * become a chunk in the SG list that libcurl reads through directly
 * (_upload_sg_read_callback in object-storage.c), so writer never needs
 * to memcpy frames into a monolithic part_buf.
 *
 * Runs in its own thread spawned by compress_pipeline_create(). The
 * thread owns the upload_pool: it creates it on entry, drives CURLM
 * via upload_pool_submit_sg as compress workers produce frames, and
 * runs upload_pool_wait/get_etags on exit. Compress workers push to
 * writer_in waitlist concurrently; this thread pops in seq order and
 * submits each PART_SIZE chunk batch as soon as it's full.
 *
 * Why a separate thread: previously this ran on the main thread inside
 * compress_pipeline_finalize() — i.e. only after all compress workers
 * had joined. That serialized compress and upload, so wall =
 * T_compress + T_upload_drain even though raw path overlaps both
 * (raw _flush_object_storage_part submits to upload_pool inline as
 * 8 MB part_buf fills up). Moving writer to a thread lets compressed
 * dumps achieve the same compress/upload overlap as raw.
 *
 * Why this is NOT the previous failed parallel writer: that one
 * memcpy'd frames into a contiguous part_buf in the writer thread
 * before submitting, which added ~700 ms of memcpy on 7 GB compressed
 * (mc-16gb) and caused a +3.4 % regression. This one keeps the SG
 * path (zero-copy) and only changes WHEN the upload_pool is driven.
 *
 * libcurl/CURLM is touched ONLY here. Main thread never calls libcurl
 * for compressed-mode uploads, so the historical "pthread_key
 * destructor → curl_easy_cleanup → parasite tsock break" failure mode
 * does not apply (single owning thread, libcurl state not shared).
 */
static void writer_drain(struct compress_pipeline *p)
{
	struct upload_pool *pool = NULL;
	struct upload_sg_chunk *chunks = NULL;
	int n_chunks = 0;
	int cap_chunks = 0;
	size_t chunk_sum = 0;
	int part_num = 0;
	struct frame_rec *f;
	int m_workers;
	const char **pool_etags = NULL;
	int n_pool_etags = 0;
	int failed_part = 0;
	int i;
	void *seek_buf = NULL;
	size_t seek_cap = 0, seek_used = 0;

	m_workers = p->n_upload > 0 ? p->n_upload : 4;
	pool = upload_pool_create(p->object_key, p->upload_id, m_workers);
	if (!pool) {
		pr_err("writer_drain: upload_pool_create failed\n");
		pipe_set_error(p, -1);
		goto cleanup;
	}

	while ((f = waitlist_pop_in_order(&p->writer_in)) != NULL) {
		if (writer_sg_append(&chunks, &n_chunks, &cap_chunks,
				     &chunk_sum, f->comp, f->comp_len) < 0) {
			pipe_set_error(p, -1);
			xfree(f->comp);
			xfree(f);
			break;
		}
		/* Pool now owns f->comp; don't free it via f. */

		{
			size_t rc = ZSTD_seekable_logFrame(p->frame_log,
							   (unsigned)f->comp_len,
							   (unsigned)f->raw_len,
							   0);
			if (ZSTD_isError(rc)) {
				pr_err("ZSTD_seekable_logFrame: %s\n",
				       ZSTD_getErrorName(rc));
				pipe_set_error(p, -1);
				xfree(f);
				break;
			}
		}
		xfree(f);  /* frame record; data still in chunks[] */

		if (chunk_sum >= PART_SIZE) {
			if (writer_sg_submit(pool, ++part_num,
					     &chunks, &n_chunks,
					     &cap_chunks, &chunk_sum) < 0) {
				pr_err("writer_drain: chunk-part submit failed\n");
				pipe_set_error(p, -1);
				goto cleanup;
			}
		}
	}

	/* Serialize seek table into a heap buffer; appended as the last
	 * chunk of the final part so the file ends with the seekable
	 * footer S3 readers expect. */
	{
		size_t remaining = 1;
		ZSTD_outBuffer out;

		seek_cap = 64 * 1024;
		seek_buf = xmalloc(seek_cap);
		if (!seek_buf) {
			pipe_set_error(p, -1);
			goto cleanup;
		}
		while (remaining > 0) {
			if (seek_used + 4096 > seek_cap) {
				void *nb = xrealloc(seek_buf, seek_cap * 2);
				if (!nb) {
					pipe_set_error(p, -1);
					goto cleanup;
				}
				seek_buf = nb;
				seek_cap *= 2;
			}
			out.dst = (char *)seek_buf + seek_used;
			out.size = seek_cap - seek_used;
			out.pos = 0;
			remaining = ZSTD_seekable_writeSeekTable(p->frame_log,
								 &out);
			if (ZSTD_isError(remaining)) {
				pr_err("ZSTD_seekable_writeSeekTable: %s\n",
				       ZSTD_getErrorName(remaining));
				pipe_set_error(p, -1);
				goto cleanup;
			}
			seek_used += out.pos;
		}
	}

	if (seek_used > 0) {
		if (writer_sg_append(&chunks, &n_chunks, &cap_chunks,
				     &chunk_sum, seek_buf, seek_used) < 0) {
			pipe_set_error(p, -1);
			xfree(seek_buf);
			goto cleanup;
		}
		seek_buf = NULL;  /* now owned by chunks[] */
	}

	if (n_chunks > 0 || part_num == 0) {
		if (writer_sg_submit(pool, ++part_num,
				     &chunks, &n_chunks,
				     &cap_chunks, &chunk_sum) < 0) {
			pr_err("writer_drain: final part submit failed\n");
			pipe_set_error(p, -1);
			goto cleanup;
		}
	}

	if (upload_pool_wait(pool, &failed_part) < 0) {
		pr_err("writer_drain: upload_pool_wait failed (part %d)\n",
		       failed_part);
		pipe_set_error(p, -1);
		goto cleanup;
	}

	if (upload_pool_get_etags(pool, &pool_etags, &n_pool_etags) < 0) {
		pr_err("writer_drain: upload_pool_get_etags failed\n");
		pipe_set_error(p, -1);
		goto cleanup;
	}

	pthread_mutex_lock(&p->etags_lock);
	etags_reserve(p, n_pool_etags);
	if (p->etags) {
		for (i = 0; i < n_pool_etags; i++) {
			if (pool_etags[i]) {
				xfree(p->etags[i]);
				p->etags[i] = xstrdup(pool_etags[i]);
			}
		}
		p->n_parts = n_pool_etags;
	}
	pthread_mutex_unlock(&p->etags_lock);

cleanup:
	if (chunks) {
		for (i = 0; i < n_chunks; i++) {
			if (chunks[i].data)
				xfree(chunks[i].data);
		}
		xfree(chunks);
	}
	if (seek_buf)
		xfree(seek_buf);
	if (pool)
		upload_pool_destroy(pool);
	upq_close(&p->upload_in);
}

static void *writer_thread_fn(void *arg)
{
	struct compress_pipeline *p = arg;
	writer_drain(p);
	return NULL;
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
	pthread_mutex_init(&p->stat_lock, NULL);

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
		 * Writer thread: owns the upload_pool, drives all CURLM
		 * activity. Spawned now (not at finalize) so compress and
		 * upload can overlap during the dump phase. See writer_drain
		 * comment for the rationale and the failed-pwriter contrast.
		 */
		if (pthread_create(&p->writer_thread, NULL,
				   writer_thread_fn, p) != 0) {
			pr_err("pthread_create writer_thread\n");
			pthread_sigmask(SIG_SETMASK, &old, NULL);
			goto err;
		}
		p->writer_thread_started = 1;

		(void)upload_worker;
		(void)etags_reserve;

		pthread_sigmask(SIG_SETMASK, &old, NULL);
	}
	return p;

err:
	compress_pipeline_destroy(p);
	return NULL;
}

/*
 * Ownership note: `data` must be a heap-allocated buffer (xmalloc/xzalloc)
 * that the caller is handing off to the pipeline. On success, the
 * compress worker xfree()s it after reading. On failure, this function
 * xfree()s it before returning -1. The caller must NOT free the buffer
 * itself either way. This avoids the previous per-frame memcpy that
 * was capping input throughput around 1.3 GB/s.
 */
int compress_pipeline_submit(struct compress_pipeline *p,
			     void *data, size_t len)
{
	struct frame_rec *f;

	if (compress_pipeline_error(p)) {
		xfree(data);
		return -1;
	}

	f = xzalloc(sizeof(*f));
	if (!f) {
		xfree(data);
		return -1;
	}
	f->raw = data;
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
	 * Wait for compress workers to finish, then close writer input so
	 * the writer thread sees end-of-stream and serializes the seek
	 * table + final part. Zero each handle as we join so destroy()
	 * doesn't double-join (UB).
	 */
	for (i = 0; i < p->n_compress; i++) {
		pthread_join(p->compress_threads[i], NULL);
		p->compress_threads[i] = 0;
	}
	waitlist_close(&p->writer_in);

	/*
	 * Writer thread does the rest: drains remaining waitlist, builds
	 * seek table into the final part, upload_pool_wait, get_etags.
	 */
	if (p->writer_thread_started) {
		pthread_join(p->writer_thread, NULL);
		p->writer_thread_started = 0;
	}

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
	if (p->writer_thread_started) {
		pthread_join(p->writer_thread, NULL);
		p->writer_thread_started = 0;
	}
	upq_close(&p->upload_in);
	if (p->upload_threads) {
		for (i = 0; i < p->n_upload; i++)
			if (p->upload_threads[i])
				pthread_join(p->upload_threads[i], NULL);
		xfree(p->upload_threads);
	}

	/*
	 * Per-pipeline compress stats. n_compress workers ran in parallel;
	 * compress_ms is the wall sum across them (actual elapsed time is
	 * compress_ms / n_compress in an ideal case). bytes_out/in ratio is
	 * what landed on S3. Log shape kept in sync with decompress_stats:
	 * so parse_ablation.py can pick both up with the same grep.
	 */
	if (p->stat_frames > 0) {
		double compress_ms = p->stat_compress_ns / 1e6;
		double ratio = p->stat_bytes_in
			? (double)p->stat_bytes_out / (double)p->stat_bytes_in
			: 0.0;
		double mbps = compress_ms > 0
			? (p->stat_bytes_in / 1048576.0) / (compress_ms / 1000.0)
			: 0.0;
		pr_info("compress_stats: key=%s n_workers=%d frames=%lu "
			"bytes_in=%llu bytes_out=%llu ratio=%.3f "
			"compress_ms_sum=%.1f compress_mbps_per_worker=%.0f\n",
			p->object_key, p->n_compress, p->stat_frames,
			p->stat_bytes_in, p->stat_bytes_out, ratio,
			compress_ms, mbps);
	}

	q_destroy(&p->compress_in);
	waitlist_destroy(&p->writer_in);
	upq_destroy(&p->upload_in);
	pthread_mutex_destroy(&p->etags_lock);
	pthread_mutex_destroy(&p->err_lock);
	pthread_mutex_destroy(&p->stat_lock);

	if (p->frame_log)
		ZSTD_seekable_freeFrameLog(p->frame_log);

	if (p->etags) {
		for (i = 0; i < p->etags_cap; i++)
			xfree(p->etags[i]);
		xfree(p->etags);
	}

	xfree(p);
}
