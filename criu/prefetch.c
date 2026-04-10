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
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>

#include "prefetch.h"
#include "page-cache.h"
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

#undef LOG_PREFIX
#define LOG_PREFIX "prefetch: "

/* ========== Configuration and Constants ========== */

#define DEFAULT_AHEAD_IOVS 32  /* Coverage-first: ahead determines hit potential */

/* ========== Type Definitions ========== */

/* Pattern types for access prediction */

/* Pattern detection information */

/* Explicit IOV state machine */
enum iov_state {
	IOV_NOT_REQUESTED,   /* Initial state after metadata init */
	IOV_QUEUED,          /* In prefetch queue, waiting for worker */
	IOV_FETCHING,        /* Worker is actively fetching from S3 */
	IOV_CACHED,          /* Data in page cache, awaiting UFFDIO_COPY */
	IOV_RESTORED,        /* Installed in address space (terminal) */
	IOV_FAULTED          /* Removed from queue due to on-demand fault */
};

/* IOV metadata for tracking state */
struct iov_meta {
	unsigned long iov_start;
	unsigned long iov_end;
	unsigned long file_offset;

	enum iov_state state;
	bool is_hot;         /* Hot VMA from checkpoint metadata */

	int iov_index;       /* Index in IOV array */
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

/* Pattern detection */

/* Adaptive configuration */

/* Worker pool and priority queues */
static pthread_t *worker_threads = NULL;
static int num_workers = 0;
static bool workers_running = false;

static struct list_head queue_high = LIST_HEAD_INIT(queue_high);     /* >= 70 */
static struct list_head queue_medium = LIST_HEAD_INIT(queue_medium); /* 40-69 */
static struct list_head queue_low = LIST_HEAD_INIT(queue_low);       /* < 40 */
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

/* Statistics */
static struct prefetch_stats stats;
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

/* Saved lpi pointer for strategies */
static void *global_lpi = NULL;
static unsigned int global_pages_img_id = 0;  /* For object storage fetch */

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
	unsigned long proximity_removed;   /* Removed due to proximity to fault */
	unsigned long hot_vma_faults;      /* Faults on hot VMA pages */
	unsigned long cold_vma_faults;     /* Faults on non-hot VMA pages */
	unsigned long hot_vma_prefetched;  /* Hot VMA IOVs prefetched before fault */
};
static struct controller_stats controller_stats;
static pthread_mutex_t controller_stats_lock = PTHREAD_MUTEX_INITIALIZER;

/* Proximity-based removal configuration (base values for adaptive calculation) */
#define PROXIMITY_WINDOW_DEFAULT 8
#define PROXIMITY_WINDOW_SEQUENTIAL 8  /* Base value for formula-based scaling */
#define PROXIMITY_WINDOW_RANDOM 4

/* Adaptive queue management */
#define TARGET_QUEUE_SIZE 64  /* Target queue size for steady state */
#define BASE_PROMOTION_DISTANCE 64  /* Base promotion distance */

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

/* Initialize IOV metadata from IOV array */
int prefetch_init_iovs(void *lpi, unsigned int pages_img_id, struct iov_info *iovs, int num_iovs)
{
	int i;

	pthread_mutex_lock(&iov_meta_lock);

	/* Store global lpi reference and pages_img_id */
	global_lpi = lpi;
	global_pages_img_id = pages_img_id;

	/* Reset tree if already initialized */
	if (!RB_EMPTY_ROOT(&iov_meta_tree)) {
		struct rb_node *node;
		while ((node = rb_first(&iov_meta_tree))) {
			struct iov_meta *meta = rb_entry(node, struct iov_meta, node);
			rb_erase(node, &iov_meta_tree);
			xfree(meta);
		}
	}

	/* Reset index map */
	if (iov_index_map) {
		xfree(iov_index_map);
		iov_index_map = NULL;
	}

	/* Allocate index map */
	total_iovs = num_iovs;
	if (total_iovs > 0) {
		iov_index_map = xzalloc(sizeof(struct iov_meta *) * total_iovs);
		if (!iov_index_map) {
			pthread_mutex_unlock(&iov_meta_lock);
			pr_err("Failed to allocate IOV index map\n");
			return -ENOMEM;
		}
	}

	/* Create metadata for each IOV */
	for (i = 0; i < num_iovs; i++) {
		struct iov_meta *meta = xzalloc(sizeof(struct iov_meta));
		unsigned long size;
		if (!meta) {
			pr_err("Failed to allocate IOV metadata for index %d\n", i);
			pthread_mutex_unlock(&iov_meta_lock);
			return -ENOMEM;
		}

		meta->iov_start = iovs[i].iov_start;
		meta->iov_end = iovs[i].iov_end;
		/* file_offset is already calculated in uffd.c */
		meta->file_offset = iovs[i].file_offset;
		meta->state = IOV_NOT_REQUESTED;
		meta->is_hot = false;
		meta->iov_index = i;

		/* Log IOV info for debugging (especially large IOVs) */
		size = meta->iov_end - meta->iov_start;
		if (size >= 4 * 1024 * 1024 || (i >= 190 && i <= 195)) {
			pr_info("IOV[%d]: [0x%lx-0x%lx] size=%lu KB\n",
				i, meta->iov_start, meta->iov_end, size / 1024);
		}

		/* Insert into RB-tree */
		if (iov_meta_insert(meta) < 0) {
			xfree(meta);
			pthread_mutex_unlock(&iov_meta_lock);
			pr_err("Failed to insert IOV metadata for index %d\n", i);
			return -EEXIST;
		}

		/* Add to index map */
		iov_index_map[i] = meta;
	}

	pthread_mutex_unlock(&iov_meta_lock);

	pr_debug("IOV metadata initialized: %d IOVs\n", num_iovs);

	/* Initialize hash table */
	hash_table_init(&request_hash_table);

	/* Initialize controller stats */
	memset(&controller_stats, 0, sizeof(controller_stats));

	pr_info("CONTROLLER: Hash table initialized\n");

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

/* Dequeue highest priority request */
static struct prefetch_request *dequeue_request(void)
{
	struct prefetch_request *req = NULL;

	pthread_mutex_lock(&queue_lock);

	/* Check high priority queue first */
	if (!list_empty(&queue_high)) {
		req = list_first_entry(&queue_high, struct prefetch_request, list);
		list_del(&req->list);
	} else if (!list_empty(&queue_medium)) {
		req = list_first_entry(&queue_medium, struct prefetch_request, list);
		list_del(&req->list);
	} else if (!list_empty(&queue_low)) {
		req = list_first_entry(&queue_low, struct prefetch_request, list);
		list_del(&req->list);
	}

	pthread_mutex_unlock(&queue_lock);

	return req;
}

/* Worker thread function */
static void *prefetch_worker(void *arg)
{
	int worker_id = (int)(long)arg;

	pr_debug("Worker %d started\n", worker_id);

	while (workers_running) {
		struct prefetch_request *req;
		struct iov_meta *meta;
		unsigned long size;
		void *data;
		int ret;
		struct timespec ts;
		struct timespec worker_start, worker_end;
		double worker_duration_ms;

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

		/* Dequeue request */
		req = dequeue_request();
		if (!req)
			continue;

		/* Remove from hash table (controller uses hash for O(1) lookup) */
		pthread_mutex_lock(&queue_lock);
		hash_table_remove(&request_hash_table, req->iov_index);
		pthread_mutex_unlock(&queue_lock);

		/* Check metadata */
		pthread_mutex_lock(&iov_meta_lock);
		meta = iov_meta_search(req->iov_start);

		if (meta) {
			/* Skip if already in cache */
			if (meta->state >= IOV_CACHED) {
				pthread_mutex_unlock(&iov_meta_lock);
				pr_debug("PREFETCH: Worker %d: IOV[%d] already in cache, skipping\n",
					 worker_id, req->iov_index);
				xfree(req);
				continue;
			}

			/* Set prefetching flag */
			meta->state = IOV_FETCHING;
		}
		pthread_mutex_unlock(&iov_meta_lock);

		/* Log worker start for simulation and record start time */
		clock_gettime(CLOCK_MONOTONIC, &worker_start);
		PREFETCH_WORKER_START_LOG(worker_id, req->iov_index);

		pr_debug("PREFETCH: Worker %d processing IOV [0x%lx-0x%lx] priority=%d\n",
			 worker_id, req->iov_start, req->iov_end, req->priority);

		/* Fetch from object storage */
		size = req->iov_end - req->iov_start;
		data = xmalloc(size);

		if (!data) {
			pr_err("Worker %d: Failed to allocate buffer for IOV\n", worker_id);
			goto next_request;
		}

		/* Fetch from object storage */
		ret = -1;

		if (opts.enable_object_storage) {
			char object_key[PATH_MAX];
			char image_name[64];

			/* Construct image name using pages_img_id */
			snprintf(image_name, sizeof(image_name), "pages-%u.img", req->pages_img_id);

			/* Construct object key with prefix if available */
			if (opts.object_storage_object_prefix && strlen(opts.object_storage_object_prefix) > 0) {
				snprintf(object_key, sizeof(object_key), "%s%s",
					 opts.object_storage_object_prefix, image_name);
			} else {
				snprintf(object_key, sizeof(object_key), "%s", image_name);
			}

			/* Fetch data from S3 */
			pr_debug("PREFETCH: Worker %d: Fetching from S3: %s at offset %lu, size %lu\n",
				 worker_id, object_key, req->file_offset, size);

			ret = object_storage_fetch_range(object_key, req->file_offset, size, data);

			if (ret != 0) {
				PREFETCH_WORKER_ERROR_LOG(worker_id, req->iov_index, ret);
				pr_err("PREFETCH: Worker %d: Failed to fetch from S3: %s (ret=%d)\n",
				       worker_id, object_key, ret);
			}
		}

		if (ret == 0) {
			/* Store in cache (cache makes a deep copy) */
			ret = cache_store_iov(req->iov_start, req->iov_end, req->file_offset,
					      data, size, true);
			xfree(data); /* Always free our buffer after cache_store */
			data = NULL;
			if (ret == 0) {
				/* Update metadata */
				iov_meta_mark_cached(req->iov_start);

				pthread_mutex_lock(&stats_lock);
				stats.cache_stored++;
				stats.bytes_prefetched += size;
				stats.completed++;
				if (req->iov_index >= 0 && req->iov_index < total_iovs &&
				    iov_index_map[req->iov_index] &&
				    iov_index_map[req->iov_index]->is_hot)
					controller_stats.hot_vma_prefetched++;
				pthread_mutex_unlock(&stats_lock);

				/* Calculate worker duration and log completion */
				clock_gettime(CLOCK_MONOTONIC, &worker_end);
				worker_duration_ms = (worker_end.tv_sec - worker_start.tv_sec) * 1000.0 +
						     (worker_end.tv_nsec - worker_start.tv_nsec) / 1000000.0;
				PREFETCH_WORKER_DONE_LOG(worker_id, req->iov_index, worker_duration_ms);

				pr_debug("PREFETCH: Worker %d: Successfully cached IOV\n", worker_id);
			} else {
				pr_err("PREFETCH: Worker %d: Failed to cache IOV\n", worker_id);
				xfree(data); /* cache_store failed, we still own the data */

				pthread_mutex_lock(&stats_lock);
				stats.failed++;
				pthread_mutex_unlock(&stats_lock);
			}
		} else {
			pr_err("PREFETCH: Worker %d: Failed to fetch IOV from storage\n", worker_id);
			xfree(data);
			data = NULL;

			pthread_mutex_lock(&stats_lock);
			stats.failed++;
			pthread_mutex_unlock(&stats_lock);
		}

		xfree(data);

next_request:
		/* Clear prefetching flag */
		pthread_mutex_lock(&iov_meta_lock);
		meta = iov_meta_search(req->iov_start);
		if (meta)
			meta->state = IOV_NOT_REQUESTED;
		pthread_mutex_unlock(&iov_meta_lock);

		xfree(req);
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
		pr_err("Invalid number of workers: %d\n", num_worker_threads);
		return -EINVAL;
	}

	pr_info("Initializing prefetch system with %d workers\n", num_worker_threads);

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
	PREFETCH_STATS_LOG(stats.total_requests, stats.completed, stats.failed,
			   stats.cache_stored, stats.bytes_prefetched);
	pthread_mutex_unlock(&stats_lock);

	pthread_mutex_lock(&controller_stats_lock);
	pr_info("CONTROLLER faults=%lu removes=%lu promotes=%lu obsolete=%lu proximity=%lu hot_faults=%lu cold_faults=%lu hot_prefetched=%lu\n",
		controller_stats.faults_processed,
		controller_stats.queue_removes,
		controller_stats.priority_promotions,
		controller_stats.obsolete_prevented,
		controller_stats.proximity_removed,
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

	if (!global_lpi || !iov_index_map) {
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
	req->pages_img_id = global_pages_img_id;
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
	int current_queue_size;
	int promote_distance;

	PREFETCH_CONTROLLER_FAULT_LOG(iov_index);

	if (iov_index < 0 || iov_index >= total_iovs)
		return;

	/* Mark IOV as faulted (sync path will handle it) */
	pthread_mutex_lock(&iov_meta_lock);
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
			controller_stats.queue_removes++;
			controller_stats.obsolete_prevented++;
		}
	}

	/* 2. Proximity removal: remove next PROXIMITY_WINDOW forward IOVs */
	for (i = 1; i <= PROXIMITY_WINDOW_DEFAULT; i++) {
		int prox_idx = iov_index + i;
		struct prefetch_request *prox_req;
		if (prox_idx >= total_iovs)
			break;
		prox_req = hash_table_lookup(&request_hash_table, prox_idx);
		if (prox_req) {
			list_del(&prox_req->list);
			hash_table_remove(&request_hash_table, prox_idx);
			xfree(prox_req);
			controller_stats.proximity_removed++;
		}
	}

	/* 3. Promote ahead IOVs: queue next promote_distance IOVs */
	current_queue_size = 0;
	{
		struct prefetch_request *tmp;
		list_for_each_entry(tmp, &queue_high, list) current_queue_size++;
		list_for_each_entry(tmp, &queue_medium, list) current_queue_size++;
		list_for_each_entry(tmp, &queue_low, list) current_queue_size++;
	}
	promote_distance = (current_queue_size < TARGET_QUEUE_SIZE / 2) ? 64 : 32;

	for (i = PROXIMITY_WINDOW_DEFAULT + 1; i <= PROXIMITY_WINDOW_DEFAULT + promote_distance; i++) {
		int ahead_idx = iov_index + i;
		struct prefetch_request *existing;
		if (ahead_idx >= total_iovs)
			break;
		existing = hash_table_lookup(&request_hash_table, ahead_idx);
		if (existing) {
			/* Already queued - promote priority */
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

/* Get idle worker count */
