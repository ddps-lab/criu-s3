/*
 * Asynchronous prefetch implementation for IOV-based lazy pages
 *
 * This module implements intelligent prefetching strategies including:
 * - Pattern-based prediction (sequential, stride, backward, random)
 * - Ahead-of-fault prefetching
 * - Background prefetching of unrestored IOVs
 * - Multi-threaded worker pool with priority queues
 * - Adaptive configuration based on cache hit rates
 */

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>

#include "obstor_xfer.h"
#include "log.h"
#include "xmalloc.h"
#include "object-storage.h"
#include "cr_options.h"
#include "servicefd.h"
#include "image.h"
#include "common/list.h"
#include "rbtree.h"
#include "util.h"
#include "page-xfer.h"
#include "page.h"
#include "compression.h"

#undef LOG_PREFIX
#define LOG_PREFIX "prefetch: "

/* ========== Configuration and Constants ========== */

#define DEFAULT_AHEAD_IOVS 32  /* Coverage-first: ahead determines hit potential */

/* ========== Type Definitions ========== */

/* Pattern types for access prediction */

/* Pattern detection information */

/*
 * IOV state machine.
 *
 * All transitions protected by iov_meta_lock unless noted.
 *
 * NOT_REQUESTED ──[prequeue]──→ QUEUED ──[worker dequeue]──→ FETCHING
 *       ↑                                                       │
 *       │                           ┌───────────────────────────┤
 *       │                    [fetch fail]              [fetch ok]
 *       │                           │                       │
 *       ├───────────── NOT_REQUESTED                    CACHED
 *       │                                                   │
 *       │                                            [fault hit]
 *       │                                                   ↓
 *       │                                              RESTORED (terminal)
 *       │
 *       └──[eviction]── NOT_REQUESTED
 *
 * FAULTED: fault handler started sync fetch (UFFDIO_COPY pending).
 *          Worker skips install if state is FAULTED or RESTORED.
 * RESTORED: UFFDIO_COPY completed. Terminal. No further transitions.
 */
enum iov_state {
	IOV_NOT_REQUESTED,   /* Initial or post-eviction/failure */
	IOV_QUEUED,          /* In prefetch queue, waiting for worker */
	IOV_FETCHING,        /* Worker is actively fetching from S3 */
	IOV_CACHED,          /* Data in page cache, awaiting UFFDIO_COPY */
	IOV_RESTORED,        /* Installed in address space (terminal) */
	IOV_FAULTED          /* Sync fetch started, worker should skip */
};

/* IOV metadata for tracking state */
struct iov_meta {
	unsigned long iov_start;
	unsigned long iov_end;
	unsigned long file_offset;

	enum iov_state state;
	bool is_hot;         /* Hot VMA from checkpoint metadata */

	int iov_index;       /* Index in IOV array (within owning context) */
	void *lpi;           /* Owning lazy_pages_info context */
	unsigned int pages_img_id; /* Pages image identity for S3 fetch */
	struct rb_node node; /* Red-black tree node */
};

/* Adaptive configuration */

/* Prefetch request in priority queue */
struct prefetch_request {
	void *lpi;  /* lazy_pages_info pointer */
	unsigned long iov_start;
	unsigned long iov_end;
	unsigned long file_offset;
	unsigned int pages_img_id;  /* For constructing object key */
	int iov_index;
	int priority;
	struct list_head list;
};

/* ========== Global State ========== */

/* IOV metadata tracking */
static struct rb_root iov_meta_tree = RB_ROOT;
static pthread_mutex_t iov_meta_lock = PTHREAD_MUTEX_INITIALIZER;
static int total_iovs = 0;
static struct iov_meta **iov_index_map = NULL;  /* Fast index lookup */

/*
 * Broadcast whenever a worker transitions any iov to IOV_RESTORED or
 * reverts IOV_FETCHING → IOV_NOT_REQUESTED. Fault handlers that caught
 * an IOV mid-fetch (state == IOV_FETCHING) wait on this cond with a
 * bounded timeout and re-check the specific iov's state after every
 * wake. A single global cond is sufficient — broadcast cost is a few
 * µs and the fault rate is O(tens) per restore.
 */
static pthread_cond_t iov_restored_cond = PTHREAD_COND_INITIALIZER;

/* Pattern detection */

/* Adaptive configuration */

/* Worker pool and priority queues */
static pthread_t *worker_threads = NULL;
static int num_workers = 0;
static bool workers_running = false;

static struct list_head queue_high = LIST_HEAD_INIT(queue_high);     /* >= 70 */
static struct list_head queue_medium = LIST_HEAD_INIT(queue_medium); /* 40-69 */
static struct list_head queue_low = LIST_HEAD_INIT(queue_low);       /* < 40 */
static int queue_size = 0;  /* Maintained counter, avoids O(n) iteration */
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

/* Statistics */
static struct prefetch_stats stats;
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

/* ----------------------------------------------------------------------- *
 * Per-pages_img_id compressed-mode cache.
 *
 * When the S3 pages-*.img was dumped with --compress, workers need to
 * route fetches through decompress_range() rather than issuing raw Range
 * GETs for `batch.base_offset .. base_offset + total_bytes`. Two tiers:
 *
 *  1) xfer_compress_entry — shared, one per pages_img_id. After the
 *     initial probe it holds only immutable metadata (object_key,
 *     total_size, is_compressed flag, shared read-only cookie). All
 *     workers read from it without locking post-probe.
 *
 *  2) worker_dctx — thread-local decompress_ctx cache keyed by
 *     pages_img_id. Each worker lazily constructs its own ZSTD_seekable
 *     instance so that decompress_range() runs without cross-worker
 *     serialization. ZSTD_seekable's DCtx + cursor state isn't
 *     thread-safe, so the fix is per-thread instances rather than a
 *     big shared mutex.
 *
 * The shared probe_lock is held only for the duration of the initial
 * S3-size probe; once e->probed==true, late arrivals observe is_compressed
 * without taking the lock.
 * ----------------------------------------------------------------------- */

struct xfer_compress_entry {
	unsigned int pages_img_id;
	bool probed;			/* true after probe attempt */
	bool is_compressed;		/* probe result: seekable magic found */
	char object_key[PATH_MAX];
	unsigned long total_size;	/* file length in bytes (post-probe) */
	void *cookie;			/* xfer_decomp_cookie, shared read-only */
	pthread_mutex_t probe_lock;	/* held only during initial probe */
	struct xfer_compress_entry *next;
};

static struct xfer_compress_entry *xfer_compress_list;
static pthread_mutex_t xfer_compress_list_lock = PTHREAD_MUTEX_INITIALIZER;

/* Per-worker decompress_ctx cache — each worker owns one linked list and
 * never shares its decompress_ctx instances with other workers. */
struct worker_dctx_entry {
	unsigned int pages_img_id;
	struct decompress_ctx *d;
	struct worker_dctx_entry *next;
};

static struct worker_dctx_entry **worker_dctx_heads;	/* [num_workers] */
static int worker_dctx_nheads;

/* Cookie identical in shape to s3_decomp_cookie in pagemap.c but scoped
 * to this module to keep compilation units independent.
 *
 * tail_buf caches only the zstd-seekable seek-table region at EOF
 * (exact size, not a fixed window). ZSTD_seekable's init walks the
 * table and serves every read from tail_buf (zero network). Decompress
 * of a frame body issues one Range GET per frame; no state is shared
 * across workers beyond this read-only tail.
 */
#define XFER_ZSTD_FOOTER_LEN 9
#define XFER_ZSTD_SKIP_HDR_LEN 8
#define XFER_ZSTD_ENTRY_LEN_BASE 8
#define XFER_ZSTD_ENTRY_LEN_CS 12
#define XFER_COMP_TAIL_MAX (16UL << 20)

struct xfer_decomp_cookie {
	char object_key[PATH_MAX];
	unsigned long total_size;
	void *tail_buf;
	unsigned long tail_start;
	size_t tail_len;
};

static inline uint32_t xfer_read_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Parse the 9-byte footer of a seekable-format object to derive the
 * exact byte count the seek table occupies. Returns 0 on parse error. */
static size_t xfer_seek_table_size(const char *object_key, unsigned long total_size)
{
	uint8_t footer[XFER_ZSTD_FOOTER_LEN];
	unsigned long got = 0;
	uint32_t num_frames;
	uint8_t descriptor, entry_size;
	size_t needed;

	if (total_size < XFER_ZSTD_FOOTER_LEN + XFER_ZSTD_SKIP_HDR_LEN)
		return 0;
	if (object_storage_fetch_range_short(object_key,
					     total_size - XFER_ZSTD_FOOTER_LEN,
					     XFER_ZSTD_FOOTER_LEN,
					     footer, &got,
					     OBJSTOR_SRC_PREFETCH) != 0 ||
	    got != XFER_ZSTD_FOOTER_LEN)
		return 0;

	num_frames = xfer_read_le32(footer);
	descriptor = footer[4];
	entry_size = (descriptor & 0x80) ? XFER_ZSTD_ENTRY_LEN_CS
					 : XFER_ZSTD_ENTRY_LEN_BASE;

	needed = XFER_ZSTD_SKIP_HDR_LEN + (size_t)num_frames * entry_size + XFER_ZSTD_FOOTER_LEN;
	if (needed > XFER_COMP_TAIL_MAX || needed > total_size)
		return 0;
	return needed;
}

static int xfer_decomp_read_cb(void *cookie, off_t offset, size_t length,
			       void *out)
{
	struct xfer_decomp_cookie *c = cookie;
	unsigned long got = 0;
	unsigned long uoff = (unsigned long)offset;
	int rc;

	/* Tail cache hit: seek-table & trailing frame reads from memory. */
	if (c->tail_buf && c->tail_len > 0 &&
	    uoff >= c->tail_start &&
	    uoff + length <= c->tail_start + c->tail_len) {
		memcpy(out, (char *)c->tail_buf + (uoff - c->tail_start), length);
		return 0;
	}

	/* Miss — actual frame body. One Range GET. */
	rc = object_storage_fetch_range_short(c->object_key, uoff,
					      (unsigned long)length, out, &got,
					      OBJSTOR_SRC_PREFETCH);
	if (rc != 0)
		return -1;
	if (got != length)
		memset((char *)out + got, 0, length - got);
	return 0;
}

/*
 * Look up (and lazily probe) the shared metadata entry for a given
 * pages_img_id. Returns the entry with e->probed==true on success.
 * is_compressed reflects the probe outcome; false means the image is raw
 * and callers should take the direct-fetch path.
 */
static struct xfer_compress_entry *
xfer_obtain_compress_entry(unsigned int pages_img_id, const char *object_key)
{
	struct xfer_compress_entry *e;

	pthread_mutex_lock(&xfer_compress_list_lock);
	for (e = xfer_compress_list; e; e = e->next) {
		if (e->pages_img_id == pages_img_id) {
			pthread_mutex_unlock(&xfer_compress_list_lock);
			/*
			 * Another worker may still be in the probe critical
			 * section. Block on probe_lock so we only return
			 * once probed / is_compressed are final.
			 */
			pthread_mutex_lock(&e->probe_lock);
			pthread_mutex_unlock(&e->probe_lock);
			return e;
		}
	}

	/* Not seen before — create an un-probed placeholder. */
	e = xzalloc(sizeof(*e));
	if (!e) {
		pthread_mutex_unlock(&xfer_compress_list_lock);
		return NULL;
	}
	e->pages_img_id = pages_img_id;
	snprintf(e->object_key, sizeof(e->object_key), "%s", object_key);
	pthread_mutex_init(&e->probe_lock, NULL);
	/* Hold probe_lock before publishing so late lookups block until
	 * the probe completes. */
	pthread_mutex_lock(&e->probe_lock);
	e->next = xfer_compress_list;
	xfer_compress_list = e;
	pthread_mutex_unlock(&xfer_compress_list_lock);

	/*
	 * Probe the image for zstd seekable magic. On success record
	 * total_size + is_compressed + shared cookie and let each worker
	 * build its own decompress_ctx on demand. On failure leave
	 * is_compressed=false so the raw-fetch branch is taken.
	 *
	 * HEAD gives the total length in one request; a 4-byte trailing
	 * Range GET then confirms the seekable magic. O(1) RTTs instead of
	 * the O(log N) geometric probe we used before.
	 */
	{
		uint8_t tail[4];
		unsigned long tail_got = 0;
		unsigned long size = 0;
		int rc;

		rc = object_storage_head_object(object_key, &size);
		if (rc != 0 || size < 4) {
			e->probed = true;
			goto done;
		}

		if (object_storage_fetch_range_short(object_key,
						     (off_t)size - 4, 4,
						     tail, &tail_got,
						     OBJSTOR_SRC_PREFETCH) != 0 ||
		    tail_got != 4 ||
		    decompress_probe(tail, 4) != 1) {
			e->probed = true;
			goto done;
		}

		{
			struct xfer_decomp_cookie *c = xzalloc(sizeof(*c));
			unsigned long got = 0;
			if (!c) {
				e->probed = true;
				goto done;
			}
			snprintf(c->object_key, sizeof(c->object_key), "%s",
				 object_key);
			c->total_size = size;

			/*
			 * Cache exactly the seek-table bytes. decompress_create_lazy()
			 * parses the frame table from this during init and never
			 * reads through the tail cache again — frame bodies go
			 * straight through the read callback to S3 on demand.
			 */
			c->tail_len = xfer_seek_table_size(object_key, size);
			if (c->tail_len == 0) {
				pr_err("obstor_xfer: seek-table footer parse failed\n");
				xfree(c);
				e->probed = true;
				goto done;
			}
			c->tail_start = size - c->tail_len;
			c->tail_buf = xmalloc(c->tail_len);
			if (!c->tail_buf) {
				pr_err("obstor_xfer: tail xmalloc(%zu) failed\n", c->tail_len);
				xfree(c);
				e->probed = true;
				goto done;
			}
			if (object_storage_fetch_range_short(object_key,
							     c->tail_start,
							     c->tail_len,
							     c->tail_buf, &got,
							     OBJSTOR_SRC_PREFETCH) != 0 ||
			    got != c->tail_len) {
				pr_err("obstor_xfer: tail fetch failed (got=%lu/%zu)\n",
				       got, c->tail_len);
				xfree(c->tail_buf);
				xfree(c);
				e->probed = true;
				goto done;
			}

			e->cookie = c;
			e->total_size = size;
			e->is_compressed = true;
			pr_info("obstor_xfer: detected compressed pages-%u (total=%lu bytes, cached tail=%zu)\n",
				pages_img_id, size, c->tail_len);
		}
		e->probed = true;
	}
done:
	pthread_mutex_unlock(&e->probe_lock);
	return e;
}

/*
 * Return this worker's private decompress_ctx for the given entry,
 * constructing one on first use. NULL means the worker should fall back
 * to a raw fetch (either entry is not compressed, or ZSTD init failed).
 *
 * The caller must have verified e->is_compressed before calling.
 */
static struct decompress_ctx *
worker_get_decompress(int worker_id, struct xfer_compress_entry *e)
{
	struct worker_dctx_entry *w;

	if (worker_id < 0 || worker_id >= worker_dctx_nheads)
		return NULL;

	for (w = worker_dctx_heads[worker_id]; w; w = w->next) {
		if (w->pages_img_id == e->pages_img_id)
			return w->d;
	}

	w = xzalloc(sizeof(*w));
	if (!w)
		return NULL;
	w->pages_img_id = e->pages_img_id;
	w->d = decompress_create_lazy(NULL, 0, (off_t)e->total_size,
				      xfer_decomp_read_cb, e->cookie);
	if (!w->d) {
		xfree(w);
		return NULL;
	}
	w->next = worker_dctx_heads[worker_id];
	worker_dctx_heads[worker_id] = w;
	return w->d;
}

/* global_lpi and global_pages_img_id removed — now stored per-IOV in iov_meta */

/* ========== Controller Infrastructure ========== */

#include "hash-table.h"

/* Hash table for O(1) IOV index -> request lookup */
static struct hash_table request_hash_table;

/* Controller statistics */
struct controller_stats {
	unsigned long faults_processed;
	unsigned long queue_removes;
	unsigned long priority_promotions;
	unsigned long obsolete_prevented;  /* Removed before worker fetched */
	unsigned long hot_vma_faults;      /* Faults on hot VMA pages */
	unsigned long cold_vma_faults;     /* Faults on non-hot VMA pages */
	unsigned long hot_vma_prefetched;  /* Hot VMA IOVs prefetched before fault */
};
static struct controller_stats controller_stats;
static pthread_mutex_t controller_stats_lock = PTHREAD_MUTEX_INITIALIZER;

/* Controller tuning */
#define PROMOTE_DISTANCE 32          /* Fixed: promote next N IOVs on fault */

/* ========== IOV Metadata Functions ========== */

/* Compare function for RB-tree insertion */
/*
 * Search for IOV metadata containing the given address.
 * When called with an exact iov_start, returns exact match.
 * When called with a fault address (may be inside IOV), performs range search.
 */
static struct iov_meta *iov_meta_search(unsigned long addr)
{
	struct rb_node *node = iov_meta_tree.rb_node;
	struct iov_meta *candidate = NULL;

	while (node) {
		struct iov_meta *meta = rb_entry(node, struct iov_meta, node);

		if (addr < meta->iov_start) {
			node = node->rb_left;
		} else if (addr >= meta->iov_end) {
			node = node->rb_right;
		} else {
			/* addr >= iov_start && addr < iov_end → inside this IOV */
			return meta;
		}
	}

	return candidate; /* NULL if not found */
}

/*
 * Exact-match lookup: returns the iov_meta whose iov_start equals `addr`,
 * never the one that just *contains* addr. Use this from main-loop
 * helpers (is_restored / is_pending) so that a remnant of a split IOV
 * never accidentally latches onto a different (larger) IOV's state.
 */
static struct iov_meta *iov_meta_get_exact_locked(unsigned long iov_start)
{
	struct rb_node *node = iov_meta_tree.rb_node;

	while (node) {
		struct iov_meta *meta = rb_entry(node, struct iov_meta, node);

		if (iov_start < meta->iov_start)
			node = node->rb_left;
		else if (iov_start > meta->iov_start)
			node = node->rb_right;
		else
			return meta;
	}
	return NULL;
}

/* Insert IOV metadata into RB-tree */
static int iov_meta_insert(struct iov_meta *new_meta)
{
	struct rb_node **link = &iov_meta_tree.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		struct iov_meta *meta = rb_entry(*link, struct iov_meta, node);
		parent = *link;

		if (new_meta->iov_start < meta->iov_start)
			link = &(*link)->rb_left;
		else if (new_meta->iov_start > meta->iov_start)
			link = &(*link)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&new_meta->node, parent, link);
	rb_insert_color(&new_meta->node, &iov_meta_tree);

	return 0;
}

/*
 * Initialize IOV metadata from IOV array.
 * ACCUMULATES across multiple calls (one per restored process).
 * Each IOV carries its owning lpi and pages_img_id for context safety.
 */
int prefetch_init_iovs(void *lpi, unsigned int pages_img_id, struct iov_info *iovs, int num_iovs)
{
	int i;
	int base_index;

	pthread_mutex_lock(&iov_meta_lock);

	/*
	 * Accumulate: extend iov_index_map instead of resetting.
	 * Each process's IOVs get indices [base_index .. base_index + num_iovs).
	 */
	base_index = total_iovs;

	if (num_iovs > 0) {
		struct iov_meta **new_map;
		int new_total = total_iovs + num_iovs;

		new_map = xzalloc(sizeof(struct iov_meta *) * new_total);
		if (!new_map) {
			pthread_mutex_unlock(&iov_meta_lock);
			pr_err("Failed to allocate IOV index map\n");
			return -ENOMEM;
		}

		/* Copy existing entries */
		if (iov_index_map && total_iovs > 0)
			memcpy(new_map, iov_index_map, sizeof(struct iov_meta *) * total_iovs);

		xfree(iov_index_map);
		iov_index_map = new_map;
		total_iovs = new_total;
	}

	/* Create metadata for each IOV */
	for (i = 0; i < num_iovs; i++) {
		struct iov_meta *meta;
		int global_idx;

		meta = xzalloc(sizeof(struct iov_meta));
		if (!meta) {
			pr_err("Failed to allocate IOV metadata for index %d\n", i);
			pthread_mutex_unlock(&iov_meta_lock);
			return -ENOMEM;
		}

		global_idx = base_index + i;
		meta->iov_start = iovs[i].iov_start;
		meta->iov_end = iovs[i].iov_end;
		meta->file_offset = iovs[i].file_offset;
		meta->state = IOV_NOT_REQUESTED;
		meta->is_hot = false;
		meta->iov_index = global_idx;
		meta->lpi = lpi;
		meta->pages_img_id = pages_img_id;

		/* Insert into RB-tree (keyed by iov_start) */
		if (iov_meta_insert(meta) < 0) {
			xfree(meta);
			pthread_mutex_unlock(&iov_meta_lock);
			pr_err("Failed to insert IOV metadata for index %d\n", global_idx);
			return -EEXIST;
		}

		/* Add to index map */
		iov_index_map[global_idx] = meta;
	}

	pthread_mutex_unlock(&iov_meta_lock);

	pr_info("IOV metadata accumulated: +%d IOVs (total: %d, base_index: %d)\n",
		num_iovs, total_iovs, base_index);

	/* Initialize hash table and controller stats only on first call */
	if (base_index == 0) {
		hash_table_init(&request_hash_table);
		memset(&controller_stats, 0, sizeof(controller_stats));
		pr_info("CONTROLLER: Hash table initialized\n");
	}

	return 0;
}

/* Get or create IOV metadata by iov_start */
struct iov_meta *iov_meta_get(unsigned long iov_start)
{
	struct iov_meta *meta;

	pthread_mutex_lock(&iov_meta_lock);
	meta = iov_meta_search(iov_start);
	pthread_mutex_unlock(&iov_meta_lock);

	return meta;
}

/* Get or create IOV metadata by index */
struct iov_meta *iov_meta_get_by_index(int index)
{
	struct iov_meta *meta = NULL;

	pthread_mutex_lock(&iov_meta_lock);

	if (index >= 0 && index < total_iovs && iov_index_map)
		meta = iov_index_map[index];

	pthread_mutex_unlock(&iov_meta_lock);

	return meta;
}


/* Mark IOV as having experienced a fault (on-demand path) */
void iov_meta_mark_fault(unsigned long iov_start)
{
	struct iov_meta *meta;

	pthread_mutex_lock(&iov_meta_lock);
	meta = iov_meta_search(iov_start);
	if (meta && meta->state < IOV_CACHED)
		meta->state = IOV_FAULTED;
	pthread_mutex_unlock(&iov_meta_lock);
}

/* Mark IOV as cached (worker completed fetch) */
void iov_meta_mark_cached(unsigned long iov_start)
{
	struct iov_meta *meta;

	pthread_mutex_lock(&iov_meta_lock);
	meta = iov_meta_search(iov_start);
	if (meta)
		meta->state = IOV_CACHED;
	pthread_mutex_unlock(&iov_meta_lock);
}

/* Mark IOV as restored (UFFDIO_COPY completed) */
void iov_meta_mark_restored(unsigned long iov_start)
{
	struct iov_meta *meta;

	pthread_mutex_lock(&iov_meta_lock);
	meta = iov_meta_search(iov_start);
	if (meta)
		meta->state = IOV_RESTORED;
	pthread_mutex_unlock(&iov_meta_lock);
}

/* Get IOV index by address (searches RB-tree) */
int iov_meta_get_index_by_addr(unsigned long addr)
{
	struct iov_meta *meta;
	int index = -1;

	pthread_mutex_lock(&iov_meta_lock);

	/* Search for IOV containing this address */
	meta = iov_meta_search(addr);
	if (meta)
		index = meta->iov_index;

	pthread_mutex_unlock(&iov_meta_lock);

	return index;
}

/* ========== Pattern Detection (Phase 3) ========== */

/* Add IOV index to access history */

/* Analyze access pattern from recent history */

/* ========== Adaptive Configuration (Phase 3) ========== */

/* Adapt configuration based on performance metrics */

/* ========== Prefetch Strategies (Phase 4) ========== */

/* Pattern-based prefetch strategy */

/* Ahead-of-fault prefetch strategy */

/* Background unrestored prefetch strategy */

/* ========== Worker Pool (Phase 5) ========== */

/* Dequeue highest priority request — caller must hold queue_lock. */
static struct prefetch_request *dequeue_request_locked(void)
{
	struct prefetch_request *req = NULL;

	if (!list_empty(&queue_high)) {
		req = list_first_entry(&queue_high, struct prefetch_request, list);
	} else if (!list_empty(&queue_medium)) {
		req = list_first_entry(&queue_medium, struct prefetch_request, list);
	} else if (!list_empty(&queue_low)) {
		req = list_first_entry(&queue_low, struct prefetch_request, list);
	}

	if (req) {
		list_del(&req->list);
		queue_size--;
	}
	return req;
}

/* dequeue_request() (the unlocked wrapper) is unused now that workers go
 * through dequeue_batch(); keep dequeue_request_locked() for the batch
 * implementation and drop the wrapper to silence -Wunused-function. */

/* ========== Phase 6: Batch coalescing ==========
 *
 * dequeue_batch() pops one head request from the highest-priority non-empty
 * queue, then walks forward by iov_index using the hash table, batching
 * together adjacent requests that satisfy ALL of:
 *
 *   - same pages_img_id (same dump file)
 *   - same priority class as the head (high / medium / low)
 *   - contiguous file_offset (no gap)
 *   - contiguous virtual range (next->iov_start == prev->iov_end)
 *   - cumulative bytes ≤ max_bytes (default 64 MB, configurable)
 *
 * The whole pop is performed under queue_lock so no other worker can claim
 * the same range concurrently. Each popped request is removed from the hash
 * table as well. Per-IOV state (IOV_FETCHING) is set under iov_meta_lock by
 * the worker AFTER this function returns.
 *
 * Returns the number of requests in the batch (≥ 1 on success, 0 if no work).
 */

#define OBSTOR_BATCH_MAX_IOVS 256  /* Hard cap to keep arrays small */

struct obstor_batch {
	int n_iovs;
	struct prefetch_request *reqs[OBSTOR_BATCH_MAX_IOVS];
	unsigned long total_bytes;
	unsigned long base_offset; /* file_offset of head IOV */
	unsigned long base_vaddr;  /* iov_start of head IOV */
	unsigned int pages_img_id;
	int head_priority;
};

static int dequeue_batch(struct obstor_batch *b, unsigned long max_bytes)
{
	struct prefetch_request *head;
	int next_idx;

	memset(b, 0, sizeof(*b));

	pthread_mutex_lock(&queue_lock);

	head = dequeue_request_locked();
	if (!head) {
		pthread_mutex_unlock(&queue_lock);
		return 0;
	}

	hash_table_remove(&request_hash_table, head->iov_index);

	b->reqs[0] = head;
	b->n_iovs = 1;
	b->total_bytes = head->iov_end - head->iov_start;
	b->base_offset = head->file_offset;
	b->base_vaddr = head->iov_start;
	b->pages_img_id = head->pages_img_id;
	b->head_priority = head->priority;

	if (max_bytes == 0 || b->total_bytes >= max_bytes)
		goto out;

	/* Walk forward looking for adjacent requests in the hash table.
	 * Uses iov_index ordering, which mirrors the original VMA walk
	 * order from collect_iovs(); adjacent indices map to adjacent
	 * file_offsets in the typical case.
	 *
	 * We intentionally do NOT check priority_class here: priority only
	 * determines which queue the head is dequeued from. Once we have a
	 * head, any adjacent IOV (file_offset + vaddr strictly contiguous)
	 * should be batched regardless of its own priority class — a mixed-
	 * priority Range GET still installs all slices correctly. Excluding
	 * on priority fragmented batches badly in workloads with lots of
	 * PROMOTE events (e.g. compressed lazy-pages where every fault
	 * promotes 32 neighbours → queue_low walk breaks every few IOVs). */
	next_idx = head->iov_index + 1;
	while (b->n_iovs < OBSTOR_BATCH_MAX_IOVS) {
		struct prefetch_request *next;
		unsigned long next_size;
		unsigned long expected_offset;
		unsigned long expected_vaddr;

		next = hash_table_lookup(&request_hash_table, next_idx);
		if (!next)
			break;
		if (next->pages_img_id != b->pages_img_id)
			break;

		expected_offset = b->base_offset + b->total_bytes;
		expected_vaddr = b->base_vaddr + b->total_bytes;
		if (next->file_offset != expected_offset)
			break;
		if (next->iov_start != expected_vaddr)
			break;

		next_size = next->iov_end - next->iov_start;
		if (b->total_bytes + next_size > max_bytes)
			break;

		/* Eligible — pop it */
		list_del(&next->list);
		hash_table_remove(&request_hash_table, next_idx);
		queue_size--;

		b->reqs[b->n_iovs++] = next;
		b->total_bytes += next_size;
		next_idx++;
	}

out:
	pthread_mutex_unlock(&queue_lock);

	/*
	 * Mark every request in the batch as IOV_FETCHING *before* the S3
	 * fetch starts. Previously this transition happened inside
	 * worker_install_one(), i.e. after the fetch had already returned,
	 * so meta->state stayed IOV_QUEUED for the entire ~70ms S3 window
	 * and the fault path could not tell the difference between
	 * "still sitting in queue" and "worker is actively fetching this".
	 *
	 * With the transition here, a fault handler that races a worker on
	 * the same IOV can observe IOV_FETCHING and wait on a condvar for
	 * the worker to finish (see obstor_xfer_iov_wait_restored). Waiting
	 * on IOV_QUEUED is deliberately NOT supported — that risks
	 * head-of-line blocking behind a stale queue entry.
	 */
	{
		int i;
		pthread_mutex_lock(&iov_meta_lock);
		for (i = 0; i < b->n_iovs; i++) {
			struct iov_meta *meta = iov_meta_get_exact_locked(b->reqs[i]->iov_start);
			if (meta && meta->state == IOV_QUEUED)
				meta->state = IOV_FETCHING;
		}
		pthread_mutex_unlock(&iov_meta_lock);
	}

	return b->n_iovs;
}

/*
 * Fixed default for prefetch_workers when --prefetch-workers is not
 * given (or passed as 0). Previously we tried to infer this from
 * /sys/class/net/<iface>/speed, but on cloud providers (AWS ENA, GCP
 * gVNIC, Azure hv_netvsc) that file is empty, so detection always fell
 * through to this same conservative constant anyway. Worker-count
 * policy now lives in the deployment layer (Kubernetes operator picks
 * N per node instance type; experiment scripts pass --prefetch-workers
 * explicitly). CRIU just ships a reasonable built-in default that
 * behaves on commodity hardware and a 10 Gbps-class cloud NIC.
 * See issues/phase6-worker-count-notes.md.
 */
#define OBSTOR_DEFAULT_WORKERS 8

/*
 * Per-IOV install for one batch element. Looks up the meta by exact
 * iov_start (so a remnant or unrelated containing iov never hijacks our
 * decision), refuses to install if the meta is already in a terminal
 * state set by another path, then UFFDIO_COPYs the slice and updates
 * meta + stats. Returns 1 if the iov was installed (or already done by
 * someone else), 0 if it failed and the main loop should retry it.
 *
 * Caller must NOT hold iov_meta_lock; this function takes it internally.
 */
static int worker_install_one(int worker_id,
			      struct prefetch_request *req,
			      void *slice_buf,
			      unsigned long slice_size)
{
	struct iov_meta *meta;
	int nr_pages = (int)(slice_size / page_size());
	int orig_nr = nr_pages;
	int irc;

	/*
	 * Re-verify meta state right before install. IOV_FETCHING is set
	 * in dequeue_batch now, so we expect to see it here — but between
	 * dequeue and arriving at this point the fault path may have
	 * stamped IOV_FAULTED or (via the race check) an install may
	 * already be done. Treat those as "someone else owns it".
	 */
	pthread_mutex_lock(&iov_meta_lock);
	meta = iov_meta_get_exact_locked(req->iov_start);
	if (meta) {
		if (meta->state == IOV_RESTORED) {
			pthread_mutex_unlock(&iov_meta_lock);
			pr_debug("obstor_xfer: Worker %d: IOV[%d] already restored, skip\n",
				 worker_id, req->iov_index);
			return 1;
		}
		if (meta->state == IOV_FAULTED) {
			pthread_mutex_unlock(&iov_meta_lock);
			pr_debug("obstor_xfer: Worker %d: IOV[%d] FAULTED, skip\n",
				 worker_id, req->iov_index);
			pthread_mutex_lock(&stats_lock);
			stats.failed++;
			pthread_mutex_unlock(&stats_lock);
			return 1;
		}
	}
	pthread_mutex_unlock(&iov_meta_lock);

	irc = obstor_xfer_install_pages(req->lpi, req->iov_start, &nr_pages, slice_buf);

	if (irc == 0 && nr_pages == orig_nr) {
		/* Full success — mark RESTORED and wake any fault waiter */
		pthread_mutex_lock(&iov_meta_lock);
		meta = iov_meta_get_exact_locked(req->iov_start);
		if (meta)
			meta->state = IOV_RESTORED;
		pthread_cond_broadcast(&iov_restored_cond);
		pthread_mutex_unlock(&iov_meta_lock);

		pthread_mutex_lock(&stats_lock);
		stats.completed++;
		stats.bytes_prefetched += slice_size;
		if (meta && meta->is_hot)
			controller_stats.hot_vma_prefetched++;
		pthread_mutex_unlock(&stats_lock);

		PREFETCH_WORKER_DONE_LOG(worker_id, req->iov_index, 0);
		pr_debug("obstor_xfer: Worker %d: Installed IOV[%d] (%d pages)\n",
			 worker_id, req->iov_index, orig_nr);
		return 1;
	}

	/* Partial or failed install: revert state, count as partial failure,
	 * let the main-loop sequential fallback handle this iov later. */
	pr_warn("obstor_xfer: Worker %d: install partial %d/%d ret=%d for IOV[%d], "
		"reverting to NOT_REQUESTED\n",
		worker_id, nr_pages, orig_nr, irc, req->iov_index);

	pthread_mutex_lock(&iov_meta_lock);
	meta = iov_meta_get_exact_locked(req->iov_start);
	if (meta && meta->state == IOV_FETCHING)
		meta->state = IOV_NOT_REQUESTED;
	/* Wake any fault waiter — they must fall back now. */
	pthread_cond_broadcast(&iov_restored_cond);
	pthread_mutex_unlock(&iov_meta_lock);

	pthread_mutex_lock(&stats_lock);
	stats.failed++;
	stats.batch_partial_failures++;
	pthread_mutex_unlock(&stats_lock);
	return 0;
}

/* Worker thread function */
static void *prefetch_worker(void *arg)
{
	int worker_id = (int)(long)arg;
	struct obstor_batch batch;

	pr_debug("Worker %d started\n", worker_id);

	while (workers_running) {
		struct prefetch_request *head;
		void *data = NULL;
		int ret = -1;
		int n;
		int i;
		struct timespec ts;
		char object_key[PATH_MAX];
		char image_name[64];
		unsigned long offset_in_buf;

		/* Wait for work or timeout */
		pthread_mutex_lock(&queue_lock);
		while (workers_running &&
		       list_empty(&queue_high) &&
		       list_empty(&queue_medium) &&
		       list_empty(&queue_low)) {
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += 1;  /* 1 second timeout */
			pthread_cond_timedwait(&queue_cond, &queue_lock, &ts);
		}
		pthread_mutex_unlock(&queue_lock);

		if (!workers_running)
			break;

		/* Atomic batch dequeue: head + adjacent contiguous IOVs */
		n = dequeue_batch(&batch, opts.prefetch_batch_bytes);
		if (n == 0)
			continue;

		head = batch.reqs[0];

		PREFETCH_WORKER_START_LOG(worker_id, head->iov_index);
		pr_debug("obstor_xfer: Worker %d: batch of %d IOVs (%lu bytes), "
			 "head IOV[%d] [0x%lx-...]\n",
			 worker_id, n, batch.total_bytes,
			 head->iov_index, head->iov_start);

		data = xmalloc(batch.total_bytes);
		if (!data) {
			pr_err("Worker %d: Failed to allocate %lu byte batch buffer\n",
			       worker_id, batch.total_bytes);
			goto release_batch;
		}

		if (opts.enable_object_storage) {
			struct xfer_compress_entry *ce;

			snprintf(image_name, sizeof(image_name), "pages-%u.img", batch.pages_img_id);
			if (opts.object_storage_object_prefix && strlen(opts.object_storage_object_prefix) > 0)
				snprintf(object_key, sizeof(object_key), "%s%s",
					 opts.object_storage_object_prefix, image_name);
			else
				snprintf(object_key, sizeof(object_key), "%s", image_name);

			pr_debug("obstor_xfer: Worker %d: Fetching %s offset=%lu size=%lu (n=%d)\n",
				 worker_id, object_key, batch.base_offset, batch.total_bytes, n);

			ce = xfer_obtain_compress_entry(batch.pages_img_id, object_key);
			if (ce && ce->is_compressed) {
				/*
				 * Compressed mode: batch.base_offset is an
				 * uncompressed offset. Each worker holds its
				 * own ZSTD_seekable, so decompress_range() runs
				 * in parallel across workers with zero cross-
				 * worker locking.
				 */
				struct decompress_ctx *d =
					worker_get_decompress(worker_id, ce);
				if (d) {
					ret = decompress_range(d,
							       (off_t)batch.base_offset,
							       batch.total_bytes, data);
				} else {
					ret = -1;
				}
				if (ret != 0) {
					PREFETCH_WORKER_ERROR_LOG(worker_id, head->iov_index, ret);
					pr_err("obstor_xfer: Worker %d: compressed fetch failed "
					       "%s off=%lu size=%lu ret=%d\n",
					       worker_id, object_key,
					       batch.base_offset, batch.total_bytes, ret);
				}
			} else {
				ret = object_storage_fetch_range(object_key,
								 batch.base_offset,
								 batch.total_bytes, data,
								 OBJSTOR_SRC_PREFETCH);
				if (ret != 0) {
					PREFETCH_WORKER_ERROR_LOG(worker_id, head->iov_index, ret);
					pr_err("obstor_xfer: Worker %d: batch fetch failed %s ret=%d\n",
					       worker_id, object_key, ret);
				}
			}
		}

		/* Stats: count this as one batch (always, even on failure) */
		pthread_mutex_lock(&stats_lock);
		if (n > 1) {
			stats.batches_issued++;
			stats.batched_iovs += n;
			stats.batched_bytes += batch.total_bytes;
		}
		pthread_mutex_unlock(&stats_lock);

		if (ret == 0) {
			offset_in_buf = 0;
			for (i = 0; i < n; i++) {
				struct prefetch_request *r = batch.reqs[i];
				unsigned long slice_size = r->iov_end - r->iov_start;
				worker_install_one(worker_id, r, (char *)data + offset_in_buf, slice_size);
				offset_in_buf += slice_size;
			}
		} else {
			/* Whole batch fetch failed: revert each iov's state so
			 * the main-loop fallback handles them, and wake any
			 * fault waiters so they fall back to sync fetch. */
			pthread_mutex_lock(&iov_meta_lock);
			for (i = 0; i < n; i++) {
				struct prefetch_request *r = batch.reqs[i];
				struct iov_meta *m = iov_meta_get_exact_locked(r->iov_start);
				if (m && m->state == IOV_FETCHING)
					m->state = IOV_NOT_REQUESTED;
			}
			pthread_cond_broadcast(&iov_restored_cond);
			pthread_mutex_unlock(&iov_meta_lock);

			pthread_mutex_lock(&stats_lock);
			stats.failed += n;
			pthread_mutex_unlock(&stats_lock);
		}

release_batch:
		if (data) {
			xfree(data);
			data = NULL;
		}
		for (i = 0; i < n; i++)
			xfree(batch.reqs[i]);
	}

	pr_debug("Worker %d exiting\n", worker_id);
	return NULL;
}

/* ========== Main API Implementation (Phase 6) ========== */

/* Initialize prefetch system */
int prefetch_init(int num_worker_threads)
{
	int ret;
	int i;

	if (num_worker_threads <= 0) {
		num_worker_threads = OBSTOR_DEFAULT_WORKERS;
		pr_info("obstor_xfer: no --prefetch-workers given; using default %d\n",
			num_worker_threads);
	}

	pr_info("Initializing prefetch system with %d workers (batch_bytes=%lu)\n",
		num_worker_threads, opts.prefetch_batch_bytes);

	/* Reset statistics */
	memset(&stats, 0, sizeof(stats));

	/* Initialize queues (already initialized statically) */

	/* Create worker threads */
	num_workers = num_worker_threads;
	worker_threads = xmalloc(num_workers * sizeof(pthread_t));
	if (!worker_threads) {
		pr_err("Failed to allocate worker thread array\n");
		return -ENOMEM;
	}

	/* Allocate per-worker decompress caches (zero-initialized). Each
	 * worker builds its own ZSTD_seekable lazily on first compressed
	 * fetch, and only ever touches worker_dctx_heads[worker_id]. */
	worker_dctx_heads = xzalloc(num_workers * sizeof(*worker_dctx_heads));
	if (!worker_dctx_heads) {
		pr_err("Failed to allocate worker decompress caches\n");
		xfree(worker_threads);
		worker_threads = NULL;
		return -ENOMEM;
	}
	worker_dctx_nheads = num_workers;

	workers_running = true;

	for (i = 0; i < num_workers; i++) {
		ret = pthread_create(&worker_threads[i], NULL, prefetch_worker, (void *)(long)i);
		if (ret) {
			int j;
			pr_err("Failed to create worker thread %d: %d\n", i, ret);
			workers_running = false;

			/* Wait for already-created threads */
			for (j = 0; j < i; j++)
				pthread_join(worker_threads[j], NULL);

			xfree(worker_threads);
			return -ret;
		}
	}

	pr_info("Prefetch system initialized successfully\n");
	return 0;
}

/* Cleanup prefetch system */
void prefetch_cleanup(void)
{
	int i;

	pr_info("Cleaning up prefetch system\n");

	/* Stop workers */
	workers_running = false;

	/* Wake up all workers */
	pthread_mutex_lock(&queue_lock);
	pthread_cond_broadcast(&queue_cond);
	pthread_mutex_unlock(&queue_lock);

	/* Wait for workers to exit */
	if (worker_threads) {
		for (i = 0; i < num_workers; i++)
			pthread_join(worker_threads[i], NULL);

		xfree(worker_threads);
		worker_threads = NULL;
	}

	/*
	 * Tear down the compressed-mode caches. Workers are already joined,
	 * so per-worker decompress_ctx instances can be destroyed first,
	 * followed by the shared metadata + cookie.
	 */
	if (worker_dctx_heads) {
		for (i = 0; i < worker_dctx_nheads; i++) {
			struct worker_dctx_entry *w, *wnext;
			for (w = worker_dctx_heads[i]; w; w = wnext) {
				wnext = w->next;
				if (w->d)
					decompress_free(w->d);
				xfree(w);
			}
			worker_dctx_heads[i] = NULL;
		}
		xfree(worker_dctx_heads);
		worker_dctx_heads = NULL;
		worker_dctx_nheads = 0;
	}
	{
		struct xfer_compress_entry *e, *tmp;
		pthread_mutex_lock(&xfer_compress_list_lock);
		for (e = xfer_compress_list; e; e = tmp) {
			tmp = e->next;
			if (e->cookie) {
				struct xfer_decomp_cookie *c = e->cookie;
				if (c->tail_buf)
					xfree(c->tail_buf);
				xfree(c);
			}
			pthread_mutex_destroy(&e->probe_lock);
			xfree(e);
		}
		xfer_compress_list = NULL;
		pthread_mutex_unlock(&xfer_compress_list_lock);
	}

	/* Free remaining requests */
	pthread_mutex_lock(&queue_lock);
	{
		struct prefetch_request *req, *tmp;
		list_for_each_entry_safe(req, tmp, &queue_high, list) {
			list_del(&req->list);
			xfree(req);
		}
		list_for_each_entry_safe(req, tmp, &queue_medium, list) {
			list_del(&req->list);
			xfree(req);
		}
		list_for_each_entry_safe(req, tmp, &queue_low, list) {
			list_del(&req->list);
			xfree(req);
		}
	}
	pthread_mutex_unlock(&queue_lock);

	/* Free IOV metadata */
	pthread_mutex_lock(&iov_meta_lock);
	{
		struct rb_node *node;
		while ((node = rb_first(&iov_meta_tree))) {
			struct iov_meta *meta = rb_entry(node, struct iov_meta, node);
			rb_erase(node, &iov_meta_tree);
			xfree(meta);
		}
	}

	if (iov_index_map) {
		xfree(iov_index_map);
		iov_index_map = NULL;
	}

	total_iovs = 0;

	pthread_mutex_unlock(&iov_meta_lock);

	/* Cleanup hash table */
	hash_table_cleanup(&request_hash_table);

	/* Print summary stats */
	pthread_mutex_lock(&stats_lock);
	pr_info("PREFETCH requests=%lu completed=%lu failed=%lu bytes=%lu\n",
		stats.total_requests, stats.completed, stats.failed, stats.bytes_prefetched);
	pr_info("FAULT_WAIT attempted=%lu absorbed=%lu timed_out=%lu not_fetching=%lu\n",
		stats.fault_wait_attempted, stats.fault_wait_absorbed,
		stats.fault_wait_timed_out, stats.fault_wait_not_fetching);
	pthread_mutex_unlock(&stats_lock);

	pthread_mutex_lock(&controller_stats_lock);
	pr_info("CONTROLLER faults=%lu removes=%lu promotes=%lu obsolete=%lu hot_faults=%lu cold_faults=%lu hot_prefetched=%lu\n",
		controller_stats.faults_processed,
		controller_stats.queue_removes,
		controller_stats.priority_promotions,
		controller_stats.obsolete_prevented,
		controller_stats.hot_vma_faults,
		controller_stats.cold_vma_faults,
		controller_stats.hot_vma_prefetched);
	pthread_mutex_unlock(&controller_stats_lock);

	pr_info("Prefetch system cleaned up\n");
}

/*
 * Load hot VMA metadata from hot-vmas.json in images directory.
 * Marks IOVs overlapping with hot VMA ranges as is_hot=true.
 * Tries local file first, then S3 fallback.
 * Returns number of hot IOVs found, or 0 if file not found.
 */
static int load_hot_vma_metadata(void)
{
	char *data = NULL;
	unsigned long data_len = 0;
	int hot_count = 0;
	int fd;
	char *p;

	/* Try local file first */
	fd = openat(get_service_fd(IMG_FD_OFF), "hot-vmas.json", O_RDONLY);
	if (fd >= 0) {
		off_t fsize = lseek(fd, 0, SEEK_END);
		if (fsize > 0) {
			lseek(fd, 0, SEEK_SET);
			data = xmalloc(fsize + 1);
			if (data) {
				if (read(fd, data, fsize) == fsize)
					data_len = fsize;
				else {
					xfree(data);
					data = NULL;
				}
			}
		}
		close(fd);
	}

	/* S3 fallback */
	if (!data && opts.enable_object_storage) {
		void *s3_data = NULL;
		int ret = object_storage_get_object("hot-vmas.json", &s3_data, &data_len);
		if (ret == 0 && s3_data && data_len > 0) {
			data = xmalloc(data_len + 1);
			if (data) {
				memcpy(data, s3_data, data_len);
			}
			free(s3_data);
		} else {
			if (s3_data)
				free(s3_data);
		}
	}

	if (!data || data_len == 0) {
		pr_info("No hot-vmas.json found, using sequential priority\n");
		return 0;
	}

	data[data_len] = '\0';

	/* Simple parser: find "start": "0x..." and "end": "0x..." in excluded array */
	p = strstr(data, "\"excluded\"");
	if (!p) {
		pr_warn("hot-vmas.json: no 'excluded' field\n");
		xfree(data);
		return 0;
	}

	while ((p = strstr(p, "\"start\"")) != NULL) {
		unsigned long start = 0, end = 0;
		char *s;
		int i;

		/* Parse start */
		s = strstr(p, "0x");
		if (s)
			start = strtoul(s, NULL, 16);
		p = s ? s + 1 : p + 7;

		/* Parse end */
		s = strstr(p, "\"end\"");
		if (!s)
			break;
		s = strstr(s, "0x");
		if (s)
			end = strtoul(s, NULL, 16);
		p = s ? s + 1 : p + 5;

		if (start == 0 || end == 0 || end <= start)
			continue;

		pr_info("Hot VMA range: 0x%lx - 0x%lx (%lu MB)\n",
			start, end, (end - start) / (1024 * 1024));

		/* Mark overlapping IOVs as hot */
		pthread_mutex_lock(&iov_meta_lock);
		for (i = 0; i < total_iovs; i++) {
			struct iov_meta *meta = iov_index_map[i];
			if (!meta)
				continue;
			if (meta->iov_start < end && meta->iov_end > start) {
				meta->is_hot = true;
				hot_count++;
			}
		}
		pthread_mutex_unlock(&iov_meta_lock);
	}

	xfree(data);
	pr_info("Marked %d IOVs as hot from hot-vmas.json\n", hot_count);
	return hot_count;
}

/* Pre-queue all IOVs for controller-based prefetch */
int prefetch_prequeue_all_iovs(void *lpi, unsigned int pages_img_id)
{
	int i, queued = 0, hot_queued = 0;

	if (!iov_index_map || total_iovs == 0) {
		pr_err("CONTROLLER: Cannot pre-queue - IOV metadata not initialized\n");
		return -EINVAL;
	}

	/* Load hot VMA metadata and mark IOVs (if enabled) */
	if (opts.hot_vma_seed)
		load_hot_vma_metadata();

	pr_info("CONTROLLER: Pre-queueing all IOVs (total: %d)\n", total_iovs);

	pthread_mutex_lock(&queue_lock);

	for (i = 0; i < total_iovs; i++) {
		struct iov_meta *meta = iov_index_map[i];
		struct prefetch_request *req;
		unsigned long size;
		int initial_priority;

		if (!meta)
			continue;

		/* Only queue IOVs belonging to this lpi context */
		if (meta->lpi != lpi)
			continue;

		/* Filter small IOVs (< 256KB) */
		size = meta->iov_end - meta->iov_start;
		if (size < 256 * 1024)
			continue;

		/* Create prefetch request */
		req = xzalloc(sizeof(*req));
		if (!req) {
			pr_warn("CONTROLLER: Failed to allocate request for IOV[%d]\n", i);
			continue;
		}

		req->lpi = lpi;
		req->iov_start = meta->iov_start;
		req->iov_end = meta->iov_end;
		req->file_offset = meta->file_offset;
		req->pages_img_id = pages_img_id;
		req->iov_index = i;

		/* Priority based on hot VMA metadata */
		if (meta->is_hot) {
			initial_priority = PRIORITY_PATTERN;  /* 90 = highest */
			list_add_tail(&req->list, &queue_high);
			hot_queued++;
		} else {
			initial_priority = 20;  /* PRIORITY_LOW */
			list_add_tail(&req->list, &queue_low);
		}

		req->priority = initial_priority;
		meta->state = IOV_QUEUED;

		/* Add to hash table for O(1) lookup */
		if (hash_table_insert(&request_hash_table, i, req) < 0) {
			pr_warn("CONTROLLER: Failed to insert IOV[%d] into hash table\n", i);
			list_del(&req->list);
			xfree(req);
			meta->state = IOV_NOT_REQUESTED;
			continue;
		}

		queued++;
	}

	queue_size += queued;
	pthread_mutex_unlock(&queue_lock);

	pr_info("CONTROLLER: Pre-queued %d IOVs (%d hot, %d sequential, filtered %d small)\n",
		queued, hot_queued, queued - hot_queued, total_iovs - queued);

	return queued;
}

/* Queue IOV for prefetch */
int prefetch_queue_iov(void *lpi, unsigned long iov_start, unsigned long iov_end,
		       unsigned long file_offset, enum prefetch_priority priority)
{
	struct prefetch_request *req;
	struct list_head *target_queue;
	struct iov_meta *meta;

	/* Aggressive duplicate filtering: each IOV should only be queued once */
	meta = iov_meta_search(iov_start);
	if (meta) {
		pthread_mutex_lock(&iov_meta_lock);

		/* Skip if already completed */
		if (meta->state >= IOV_CACHED) {
			pthread_mutex_unlock(&iov_meta_lock);
			return 0;
		}

		/* Skip if already being prefetched - no need to re-queue */
		if (meta->state >= IOV_QUEUED) {
			pthread_mutex_unlock(&iov_meta_lock);
			return 0;
		}

		/* Mark as QUEUED immediately to prevent duplicate queuing (race prevention) */
		meta->state = IOV_QUEUED;

		pthread_mutex_unlock(&iov_meta_lock);
	}

	/* Create request */
	req = xzalloc(sizeof(*req));
	if (!req) {
		pr_err("Failed to allocate prefetch request\n");
		/* Rollback prefetching flag on allocation failure */
		if (meta) {
			pthread_mutex_lock(&iov_meta_lock);
			meta->state = IOV_NOT_REQUESTED;
			pthread_mutex_unlock(&iov_meta_lock);
		}
		return -ENOMEM;
	}

	req->lpi = lpi;
	req->iov_start = iov_start;
	req->iov_end = iov_end;
	req->file_offset = file_offset;
	req->pages_img_id = meta ? meta->pages_img_id : 0;
	req->iov_index = meta ? meta->iov_index : -1;
	req->priority = priority;
	INIT_LIST_HEAD(&req->list);

	/* Select queue based on priority */
	if (priority >= 70)
		target_queue = &queue_high;
	else if (priority >= 40)
		target_queue = &queue_medium;
	else
		target_queue = &queue_low;

	/* Add to queue */
	pthread_mutex_lock(&queue_lock);
	list_add_tail(&req->list, target_queue);
	pthread_cond_signal(&queue_cond);
	pthread_mutex_unlock(&queue_lock);

	pthread_mutex_lock(&stats_lock);
	stats.total_requests++;
	pthread_mutex_unlock(&stats_lock);

	/* Log queue event for simulation */
	PREFETCH_QUEUE_LOG(req->iov_index, iov_start, iov_end, priority);

	pr_debug("PREFETCH: Queued IOV [0x%lx-0x%lx] with priority %d\n",
		 iov_start, iov_end, priority);

	return 0;
}

/* Helper: Promote IOV priority in queue - O(1) with hash table */
static int promote_iov_priority(int iov_index, int new_priority)
{
	struct prefetch_request *req;
	int old_priority;

	/* Lookup in hash table - O(1) */
	req = hash_table_lookup(&request_hash_table, iov_index);

	if (!req)
		return -ENOENT;  /* Not in queue (already processed or filtered) */

	if (req->priority >= new_priority)
		return 0;  /* Already high priority */

	old_priority = req->priority;

	/* Remove from current queue */
	list_del(&req->list);

	/* Update priority */
	req->priority = new_priority;

	/* Re-insert to appropriate queue */
	if (new_priority >= 70) {
		list_add_tail(&req->list, &queue_high);
	} else if (new_priority >= 40) {
		list_add_tail(&req->list, &queue_medium);
	} else {
		list_add_tail(&req->list, &queue_low);
	}

	/* Log priority promotion for simulation */
	PREFETCH_CONTROLLER_PROMOTE_LOG(iov_index, old_priority, new_priority);

	return 0;
}

/* Controller: Trigger prefetch on page fault */
void prefetch_on_fault(void *lpi, int iov_index)
{
	struct iov_meta *meta;
	int i;

	PREFETCH_CONTROLLER_FAULT_LOG(iov_index);

	if (iov_index < 0 || iov_index >= total_iovs)
		return;

	/* Mark IOV as faulted (sync path will handle it) */
	pthread_mutex_lock(&iov_meta_lock);
	meta = NULL;
	if (iov_index >= 0 && iov_index < total_iovs)
		meta = iov_index_map[iov_index];
	if (meta && meta->state < IOV_CACHED)
		meta->state = IOV_FAULTED;
	pthread_mutex_unlock(&iov_meta_lock);

	pthread_mutex_lock(&queue_lock);

	/* 1. Remove faulted IOV from queue (if present) */
	{
		struct prefetch_request *faulted_req;
		faulted_req = hash_table_lookup(&request_hash_table, iov_index);
		if (faulted_req) {
			list_del(&faulted_req->list);
			hash_table_remove(&request_hash_table, iov_index);
			xfree(faulted_req);
			queue_size--;
			controller_stats.queue_removes++;
			controller_stats.obsolete_prevented++;
		}
	}

	/*
	 * 2. Promote ahead IOVs: fixed window starting one index past the
	 * faulted IOV. Previously we also evicted the next 8 IOVs from the
	 * async queue under a spatial-locality assumption ("they'll fault
	 * next too, let main-thread sync-fetch them"). Measured on mc4gb
	 * ablation 2026-04-21: the assumption backfires for fault-heavy
	 * paths — every eviction costs one async install and the workload
	 * often ends up fetching the same IOV via a UFFD fault anyway. COMP
	 * 5_full daemon drops 19.3s → 11.6s (−40%) once eviction is off.
	 */
	for (i = 1; i <= PROMOTE_DISTANCE; i++) {
		int ahead_idx = iov_index + i;
		struct prefetch_request *existing;
		if (ahead_idx >= total_iovs)
			break;
		existing = hash_table_lookup(&request_hash_table, ahead_idx);
		if (existing) {
			promote_iov_priority(ahead_idx, PRIORITY_AHEAD);
			controller_stats.priority_promotions++;
		}
	}

	pthread_mutex_unlock(&queue_lock);
	pthread_cond_signal(&queue_cond);

	/* Update stats */
	pthread_mutex_lock(&stats_lock);
	controller_stats.faults_processed++;
	if (meta && meta->is_hot)
		controller_stats.hot_vma_faults++;
	else
		controller_stats.cold_vma_faults++;
	pthread_mutex_unlock(&stats_lock);
}


/* Get prefetch statistics */
void prefetch_get_stats(struct prefetch_stats *out_stats)
{
	pthread_mutex_lock(&stats_lock);
	memcpy(out_stats, &stats, sizeof(stats));
	pthread_mutex_unlock(&stats_lock);
}

/* Reset statistics */
void prefetch_reset_stats(void)
{
	pthread_mutex_lock(&stats_lock);
	memset(&stats, 0, sizeof(stats));
	pthread_mutex_unlock(&stats_lock);

	pr_debug("Prefetch statistics reset\n");
}

/* ===== Main-loop query helpers (Phase 6 direct install) ===== */

/*
 * Exact-start match only: a remnant of a split IOV (whose iov_start no
 * longer equals any meta's iov_start) is treated as "no meta", so the
 * main loop falls through to the sequential fallback rather than
 * latching onto an unrelated containing meta.
 */
bool obstor_xfer_iov_is_restored(unsigned long iov_start)
{
	struct iov_meta *m;
	bool restored = false;

	pthread_mutex_lock(&iov_meta_lock);
	m = iov_meta_get_exact_locked(iov_start);
	if (m && m->state == IOV_RESTORED)
		restored = true;
	pthread_mutex_unlock(&iov_meta_lock);

	return restored;
}

/*
 * "Pending" means a worker is CURRENTLY holding this IOV and is about to
 * complete the fetch-and-install. IOV_QUEUED is deliberately NOT treated
 * as pending: the request object may have been evicted from the priority
 * queue by prefetch_on_fault()'s proximity removal, which leaves the meta
 * state stale. Main-loop xfer_pages() can safely sync-fetch a QUEUED IOV
 * as a fallback — UFFDIO_COPY's EEXIST handling tolerates any race where
 * a worker later tries to install the same range.
 *
 * Uses exact-start match for the same reason as is_restored.
 */
bool obstor_xfer_iov_is_pending(unsigned long iov_start)
{
	struct iov_meta *m;
	bool pending = false;

	pthread_mutex_lock(&iov_meta_lock);
	m = iov_meta_get_exact_locked(iov_start);
	if (m && m->state == IOV_FETCHING)
		pending = true;
	pthread_mutex_unlock(&iov_meta_lock);

	return pending;
}

/*
 * Bounded wait for a worker to finish installing the IOV at iov_start.
 *
 * Only waits if the IOV's current meta state is IOV_FETCHING (i.e. a
 * worker popped it out of the queue and is either fetching from S3 or
 * about to UFFDIO_COPY). Waiting on IOV_QUEUED is deliberately not
 * supported — a queued request may have been evicted by
 * prefetch_on_fault() proximity removal, leaving stale meta, and would
 * risk head-of-line blocking the fault handler.
 *
 * Returns:
 *   0         — IOV reached IOV_RESTORED within the timeout. Caller
 *               should drop the IOV from the lazy list; the page is
 *               already installed.
 *   -EAGAIN   — meta is not IOV_FETCHING (caller should take its own
 *               fast path — sync fetch, zero page, etc.)
 *   -ENOENT   — no meta for this iov_start (split remnant etc.)
 *   -ETIMEDOUT — timeout elapsed while state was still IOV_FETCHING.
 *               Caller should fall back to the sync fetch path.
 */
void obstor_xfer_account_fault_wait(int wait_rc)
{
	pthread_mutex_lock(&stats_lock);
	stats.fault_wait_attempted++;
	switch (wait_rc) {
	case 0:
		stats.fault_wait_absorbed++;
		break;
	case -ETIMEDOUT:
		stats.fault_wait_timed_out++;
		break;
	case -EAGAIN:
	case -ENOENT:
	default:
		stats.fault_wait_not_fetching++;
		break;
	}
	pthread_mutex_unlock(&stats_lock);
}

int obstor_xfer_iov_wait_restored(unsigned long iov_start, unsigned long timeout_ms)
{
	struct iov_meta *m;
	struct timespec deadline;
	int rc = -ETIMEDOUT;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += (long)(timeout_ms / 1000);
	deadline.tv_nsec += (long)((timeout_ms % 1000) * 1000000UL);
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec += 1;
		deadline.tv_nsec -= 1000000000L;
	}

	pthread_mutex_lock(&iov_meta_lock);
	m = iov_meta_get_exact_locked(iov_start);
	if (!m) {
		pthread_mutex_unlock(&iov_meta_lock);
		return -ENOENT;
	}
	if (m->state == IOV_RESTORED) {
		pthread_mutex_unlock(&iov_meta_lock);
		return 0;
	}
	if (m->state != IOV_FETCHING) {
		pthread_mutex_unlock(&iov_meta_lock);
		return -EAGAIN;
	}

	/*
	 * Loop: the cond broadcasts on ANY iov state change, so we may wake
	 * for an unrelated iov. Re-check our specific meta on every wake.
	 * Exit on RESTORED (success), on transition out of FETCHING (worker
	 * reverted → caller falls back), or on timeout.
	 */
	while (m->state == IOV_FETCHING) {
		int cwrc = pthread_cond_timedwait(&iov_restored_cond, &iov_meta_lock, &deadline);

		/* Meta pointer may have been freed during the wait only if the
		 * whole daemon is tearing down — at that point the fault loop
		 * is already exiting. For the normal path we re-fetch by key
		 * in case iov_meta_get_exact_locked semantics ever evolve. */
		m = iov_meta_get_exact_locked(iov_start);
		if (!m) {
			rc = -ENOENT;
			break;
		}
		if (m->state == IOV_RESTORED) {
			rc = 0;
			break;
		}
		if (m->state != IOV_FETCHING) {
			rc = -EAGAIN;
			break;
		}
		if (cwrc == ETIMEDOUT) {
			rc = -ETIMEDOUT;
			break;
		}
		/* Spurious wake or unrelated iov restored — keep waiting. */
	}
	pthread_mutex_unlock(&iov_meta_lock);

	return rc;
}

/* Get idle worker count */
