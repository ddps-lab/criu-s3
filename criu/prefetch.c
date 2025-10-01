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
#include "common/list.h"
#include "rbtree.h"
#include "util.h"
#include "page-xfer.h"
#include "page.h"

#undef LOG_PREFIX
#define LOG_PREFIX "prefetch: "

/* ========== Configuration and Constants ========== */

#define PATTERN_HISTORY_SIZE 32
#define PATTERN_ANALYSIS_WINDOW 16
#define ADAPTATION_INTERVAL 100
#define DEFAULT_AHEAD_IOVS 8
#define DEFAULT_BACKGROUND_IOVS 32
#define MIN_AHEAD_IOVS 4
#define MAX_AHEAD_IOVS 64
#define MIN_BACKGROUND_IOVS 0
#define MAX_BACKGROUND_IOVS 128

/* ========== Type Definitions ========== */

/* Pattern types for access prediction */
enum pattern_type {
	PATTERN_SEQUENTIAL,  /* Sequential forward access */
	PATTERN_STRIDE,      /* Fixed stride access */
	PATTERN_BACKWARD,    /* Sequential backward access */
	PATTERN_RANDOM       /* Random/unpredictable access */
};

/* Pattern detection information */
struct pattern_info {
	enum pattern_type type;
	float confidence;  /* 0.0 to 1.0 */
	int stride;        /* For PATTERN_STRIDE */
};

/* IOV metadata for tracking state */
struct iov_meta {
	unsigned long iov_start;
	unsigned long iov_end;
	unsigned long file_offset;

	bool has_fault;      /* Has experienced page fault */
	bool in_cache;       /* Currently in cache */
	bool prefetching;    /* Currently being prefetched */
	bool restored;       /* Has been restored to process */

	int iov_index;       /* Index in IOV array */
	struct rb_node node; /* Red-black tree node */
};

/* Adaptive configuration */
struct prefetch_config {
	int ahead_iovs;
	int background_iovs;
	float cache_hit_rate;
	int idle_workers;
	unsigned long fault_count;
	unsigned long last_adaptation;
};

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
static int access_history[PATTERN_HISTORY_SIZE];
static int history_head = 0;
static int history_count = 0;
static pthread_mutex_t history_lock = PTHREAD_MUTEX_INITIALIZER;

/* Adaptive configuration */
static struct prefetch_config config = {
	.ahead_iovs = DEFAULT_AHEAD_IOVS,
	.background_iovs = DEFAULT_BACKGROUND_IOVS,
	.cache_hit_rate = 0.0,
	.idle_workers = 0,
	.fault_count = 0,
	.last_adaptation = 0
};
static pthread_mutex_t config_lock = PTHREAD_MUTEX_INITIALIZER;

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

/* ========== IOV Metadata Functions (Phase 2) ========== */

/* Compare function for RB-tree insertion */
static struct iov_meta *iov_meta_search(unsigned long iov_start)
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
		if (!meta) {
			pr_err("Failed to allocate IOV metadata for index %d\n", i);
			pthread_mutex_unlock(&iov_meta_lock);
			return -ENOMEM;
		}

		meta->iov_start = iovs[i].iov_start;
		meta->iov_end = iovs[i].iov_end;
		/* file_offset is already calculated in uffd.c */
		meta->file_offset = iovs[i].file_offset;
		meta->has_fault = false;
		meta->in_cache = false;
		meta->prefetching = false;
		meta->restored = false;
		meta->iov_index = i;

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


/* Mark IOV as having experienced a fault */
void iov_meta_mark_fault(unsigned long iov_start)
{
	struct iov_meta *meta;

	pthread_mutex_lock(&iov_meta_lock);
	meta = iov_meta_search(iov_start);
	if (meta)
		meta->has_fault = true;
	pthread_mutex_unlock(&iov_meta_lock);
}

/* Mark IOV as cached */
void iov_meta_mark_cached(unsigned long iov_start)
{
	struct iov_meta *meta;

	pthread_mutex_lock(&iov_meta_lock);
	meta = iov_meta_search(iov_start);
	if (meta) {
		meta->in_cache = true;
		meta->prefetching = false;
	}
	pthread_mutex_unlock(&iov_meta_lock);
}

/* Mark IOV as restored */
void iov_meta_mark_restored(unsigned long iov_start)
{
	struct iov_meta *meta;

	pthread_mutex_lock(&iov_meta_lock);
	meta = iov_meta_search(iov_start);
	if (meta) {
		meta->restored = true;
		meta->in_cache = false;
	}
	pthread_mutex_unlock(&iov_meta_lock);
}

/* ========== Pattern Detection (Phase 3) ========== */

/* Add IOV index to access history */
static void update_access_history(int iov_index)
{
	pthread_mutex_lock(&history_lock);

	access_history[history_head] = iov_index;
	history_head = (history_head + 1) % PATTERN_HISTORY_SIZE;

	if (history_count < PATTERN_HISTORY_SIZE)
		history_count++;

	pthread_mutex_unlock(&history_lock);

	pr_debug("Access history updated: index=%d, count=%d\n", iov_index, history_count);
}

/* Analyze access pattern from recent history */
static struct pattern_info detect_pattern(void)
{
	struct pattern_info info = {
		.type = PATTERN_RANDOM,
		.confidence = 0.0,
		.stride = 0
	};
	int window_size;
	int indices[PATTERN_ANALYSIS_WINDOW];
	int start;
	int i;
	int sequential_count;
	float seq_ratio;
	int backward_count;
	float back_ratio;

	pthread_mutex_lock(&history_lock);

	if (history_count < 2) {
		pthread_mutex_unlock(&history_lock);
		return info;
	}

	/* Get recent accesses (up to PATTERN_ANALYSIS_WINDOW) */
	window_size = (history_count < PATTERN_ANALYSIS_WINDOW) ?
		      history_count : PATTERN_ANALYSIS_WINDOW;
	start = (history_head - window_size + PATTERN_HISTORY_SIZE) % PATTERN_HISTORY_SIZE;

	for (i = 0; i < window_size; i++) {
		indices[i] = access_history[(start + i) % PATTERN_HISTORY_SIZE];
	}

	pthread_mutex_unlock(&history_lock);

	/* Analyze for sequential pattern */
	sequential_count = 0;
	for (i = 1; i < window_size; i++) {
		if (indices[i] == indices[i-1] + 1)
			sequential_count++;
	}

	seq_ratio = (float)sequential_count / (window_size - 1);
	if (seq_ratio > 0.7) {
		info.type = PATTERN_SEQUENTIAL;
		info.confidence = seq_ratio;
		return info;
	}

	/* Analyze for backward pattern */
	backward_count = 0;
	for (i = 1; i < window_size; i++) {
		if (indices[i] == indices[i-1] - 1)
			backward_count++;
	}

	back_ratio = (float)backward_count / (window_size - 1);
	if (back_ratio > 0.7) {
		info.type = PATTERN_BACKWARD;
		info.confidence = back_ratio;
		return info;
	}

	/* Analyze for stride pattern */
	if (window_size >= 3) {
		int deltas[PATTERN_HISTORY_SIZE - 1];  /* Use max possible size */
		int common_stride;
		int stride_count;
		float stride_ratio;
		int j;

		for (i = 1; i < window_size; i++)
			deltas[i-1] = indices[i] - indices[i-1];

		/* Find most common stride */
		common_stride = deltas[0];
		stride_count = 0;

		for (i = 0; i < window_size - 1; i++) {
			int count = 0;
			for (j = 0; j < window_size - 1; j++) {
				if (deltas[j] == deltas[i])
					count++;
			}
			if (count > stride_count) {
				stride_count = count;
				common_stride = deltas[i];
			}
		}

		stride_ratio = (float)stride_count / (window_size - 1);
		if (stride_ratio > 0.6 && common_stride != 0) {
			info.type = PATTERN_STRIDE;
			info.confidence = stride_ratio;
			info.stride = common_stride;
			return info;
		}
	}

	/* Default to random */
	info.type = PATTERN_RANDOM;
	info.confidence = 0.3;

	return info;
}

/* ========== Adaptive Configuration (Phase 3) ========== */

/* Adapt configuration based on performance metrics */
static void adapt_config(void)
{
	struct cache_stats cache_stats;

	pthread_mutex_lock(&config_lock);

	/* Only adapt every ADAPTATION_INTERVAL faults */
	if (config.fault_count - config.last_adaptation < ADAPTATION_INTERVAL) {
		pthread_mutex_unlock(&config_lock);
		return;
	}

	config.last_adaptation = config.fault_count;

	/* Get cache statistics */
	cache_get_stats(&cache_stats);

	if (cache_stats.lookups > 0)
		config.cache_hit_rate = (float)cache_stats.hits / cache_stats.lookups;

	pr_debug("Adapting config: hit_rate=%.2f, idle_workers=%d\n",
		 config.cache_hit_rate, config.idle_workers);

	/* Adjust ahead_iovs based on hit rate */
	if (config.cache_hit_rate > 0.8) {
		/* High hit rate - increase aggressiveness */
		config.ahead_iovs = (config.ahead_iovs + 2 < MAX_AHEAD_IOVS) ?
				    config.ahead_iovs + 2 : MAX_AHEAD_IOVS;
	} else if (config.cache_hit_rate < 0.3) {
		/* Low hit rate - decrease aggressiveness */
		config.ahead_iovs = (config.ahead_iovs - 2 > MIN_AHEAD_IOVS) ?
				    config.ahead_iovs - 2 : MIN_AHEAD_IOVS;
	}

	/* Adjust background_iovs based on idle workers */
	if (config.idle_workers > num_workers / 2) {
		/* Many idle workers - increase background work */
		config.background_iovs = (config.background_iovs + 8 < MAX_BACKGROUND_IOVS) ?
					 config.background_iovs + 8 : MAX_BACKGROUND_IOVS;
	} else if (config.idle_workers < num_workers / 4) {
		/* Few idle workers - decrease background work */
		config.background_iovs = (config.background_iovs - 8 > MIN_BACKGROUND_IOVS) ?
					 config.background_iovs - 8 : MIN_BACKGROUND_IOVS;
	}

	pthread_mutex_unlock(&config_lock);

	pr_info("Config adapted: ahead=%d, background=%d, hit_rate=%.2f\n",
		config.ahead_iovs, config.background_iovs, config.cache_hit_rate);
}

/* ========== Prefetch Strategies (Phase 4) ========== */

/* Pattern-based prefetch strategy */
static int prefetch_pattern_based(void *lpi, int current_iov_index)
{
	struct pattern_info pattern;
	int queued;
	int num_to_prefetch;
	int i;

	queued = 0;
	pattern = detect_pattern();

	pr_debug("Pattern detected: type=%d, confidence=%.2f, stride=%d\n",
		 pattern.type, pattern.confidence, pattern.stride);

	/* Only prefetch if confidence is high enough */
	if (pattern.confidence < 0.5)
		return 0;

	num_to_prefetch = 4;  /* Prefetch 4 IOVs based on pattern */

	for (i = 1; i <= num_to_prefetch; i++) {
		int target_index;
		struct iov_meta *meta;

		switch (pattern.type) {
		case PATTERN_SEQUENTIAL:
			target_index = current_iov_index + i;
			break;
		case PATTERN_BACKWARD:
			target_index = current_iov_index - i;
			break;
		case PATTERN_STRIDE:
			target_index = current_iov_index + (i * pattern.stride);
			break;
		default:
			continue;
		}

		if (target_index < 0 || target_index >= total_iovs)
			continue;

		meta = iov_meta_get_by_index(target_index);
		if (!meta || meta->restored || meta->prefetching)
			continue;

		/* Queue for prefetch */
		if (prefetch_queue_iov(lpi, meta->iov_start, meta->iov_end,
				       meta->file_offset, PRIORITY_PATTERN) == 0)
			queued++;
	}

	pthread_mutex_lock(&stats_lock);
	stats.pattern_count += queued;
	pthread_mutex_unlock(&stats_lock);

	return queued;
}

/* Ahead-of-fault prefetch strategy */
static int prefetch_ahead_of_fault(void *lpi, int current_iov_index)
{
	int queued;
	int ahead_count;
	int i;

	queued = 0;

	pthread_mutex_lock(&config_lock);
	ahead_count = config.ahead_iovs;
	pthread_mutex_unlock(&config_lock);

	for (i = 1; i <= ahead_count; i++) {
		int target_index;
		struct iov_meta *meta;

		target_index = current_iov_index + i;

		if (target_index >= total_iovs)
			break;

		meta = iov_meta_get_by_index(target_index);
		if (!meta || meta->restored || meta->prefetching)
			continue;

		/* Queue for prefetch */
		if (prefetch_queue_iov(lpi, meta->iov_start, meta->iov_end,
				       meta->file_offset, PRIORITY_AHEAD) == 0)
			queued++;
	}

	pthread_mutex_lock(&stats_lock);
	stats.ahead_count += queued;
	pthread_mutex_unlock(&stats_lock);

	pr_debug("Ahead-of-fault: queued %d IOVs\n", queued);

	return queued;
}

/* Background unrestored prefetch strategy */
static int prefetch_background_unrestored(void *lpi)
{
	int queued;
	int background_count;
	int i;

	queued = 0;

	pthread_mutex_lock(&config_lock);
	background_count = config.background_iovs;
	pthread_mutex_unlock(&config_lock);

	if (background_count == 0)
		return 0;

	/* Find unrestored IOVs */
	pthread_mutex_lock(&iov_meta_lock);

	for (i = 0; i < total_iovs && queued < background_count; i++) {
		struct iov_meta *meta = iov_index_map[i];

		if (!meta || meta->restored || meta->prefetching || meta->has_fault)
			continue;

		/* Queue for background prefetch */
		pthread_mutex_unlock(&iov_meta_lock);

		if (prefetch_queue_iov(lpi, meta->iov_start, meta->iov_end,
				       meta->file_offset, PRIORITY_BACKGROUND) == 0)
			queued++;

		pthread_mutex_lock(&iov_meta_lock);
	}

	pthread_mutex_unlock(&iov_meta_lock);

	pthread_mutex_lock(&stats_lock);
	stats.background_count += queued;
	pthread_mutex_unlock(&stats_lock);

	pr_debug("Background prefetch: queued %d IOVs\n", queued);

	return queued;
}

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
		void *cached_data;
		int ret;
		struct timespec ts;

		/* Wait for work or timeout */
		pthread_mutex_lock(&queue_lock);

		while (workers_running &&
		       list_empty(&queue_high) &&
		       list_empty(&queue_medium) &&
		       list_empty(&queue_low)) {
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += 1;  /* 1 second timeout */

			pthread_mutex_lock(&config_lock);
			config.idle_workers++;
			pthread_mutex_unlock(&config_lock);

			pthread_cond_timedwait(&queue_cond, &queue_lock, &ts);

			pthread_mutex_lock(&config_lock);
			config.idle_workers--;
			pthread_mutex_unlock(&config_lock);
		}

		pthread_mutex_unlock(&queue_lock);

		if (!workers_running)
			break;

		/* Dequeue request */
		req = dequeue_request();
		if (!req)
			continue;

		/* Check if already cached after dequeue (another worker may have cached it) */
		cached_data = NULL;
		if (cache_lookup_iov(req->iov_start, req->iov_end, &cached_data) == CACHE_HIT) {
			pr_debug("PREFETCH: Worker %d: IOV [0x%lx-0x%lx] already cached by another worker, skipping\n",
				 worker_id, req->iov_start, req->iov_end);
			xfree(cached_data);
			xfree(req);
			continue;
		}

		/* Check if already being processed by another worker */
		pthread_mutex_lock(&iov_meta_lock);
		meta = iov_meta_search(req->iov_start);
		if (meta && (meta->in_cache || meta->prefetching)) {
			pthread_mutex_unlock(&iov_meta_lock);
			pr_debug("PREFETCH: Worker %d: IOV [0x%lx-0x%lx] already being processed, skipping\n",
				 worker_id, req->iov_start, req->iov_end);
			xfree(req);
			continue;
		}
		if (meta)
			meta->prefetching = true;
		pthread_mutex_unlock(&iov_meta_lock);

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
				pr_err("PREFETCH: Worker %d: Failed to fetch from S3: %s (ret=%d)\n",
				       worker_id, object_key, ret);
			}
		}

		if (ret == 0) {
			/* Store in cache */
			ret = cache_store_iov(req->iov_start, req->iov_end, req->file_offset,
					      data, size, true);
			if (ret == 0) {
				/* Update metadata */
				iov_meta_mark_cached(req->iov_start);

				pthread_mutex_lock(&stats_lock);
				stats.cache_stored++;
				stats.bytes_prefetched += size;
				stats.completed++;
				pthread_mutex_unlock(&stats_lock);

				pr_debug("PREFETCH: Worker %d: Successfully cached IOV\n", worker_id);
			} else {
				pr_err("PREFETCH: Worker %d: Failed to cache IOV\n", worker_id);

				pthread_mutex_lock(&stats_lock);
				stats.failed++;
				pthread_mutex_unlock(&stats_lock);
			}
		} else {
			pr_err("PREFETCH: Worker %d: Failed to fetch IOV from storage\n", worker_id);

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
			meta->prefetching = false;
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

	pr_info("Prefetch system cleaned up\n");
}

/* Queue IOV for prefetch */
int prefetch_queue_iov(void *lpi, unsigned long iov_start, unsigned long iov_end,
		       unsigned long file_offset, enum prefetch_priority priority)
{
	struct prefetch_request *req;
	struct list_head *target_queue;

	/* Check if already in cache */
	void *cached_data;
	if (cache_lookup_iov(iov_start, iov_end, &cached_data) == CACHE_HIT) {
		pr_debug("PREFETCH: IOV [0x%lx-0x%lx] already in cache, skipping queue\n", iov_start, iov_end);
		xfree(cached_data);
		return 0;
	}

	/* Create request */
	req = xzalloc(sizeof(*req));
	if (!req) {
		pr_err("Failed to allocate prefetch request\n");
		return -ENOMEM;
	}

	req->lpi = lpi;
	req->iov_start = iov_start;
	req->iov_end = iov_end;
	req->file_offset = file_offset;
	req->pages_img_id = global_pages_img_id;
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

	pr_debug("PREFETCH: Queued IOV [0x%lx-0x%lx] with priority %d\n",
		 iov_start, iov_end, priority);

	return 0;
}

/* Trigger prefetch strategies on page fault */
void prefetch_on_fault(void *lpi, int iov_index)
{
	struct iov_meta *meta;
	int queued;

	pr_debug("Page fault triggered for IOV index %d\n", iov_index);

	/* Register/update IOV metadata if needed */
	/* Note: In real implementation, we'd extract IOV details from lpi */

	/* Update access history */
	update_access_history(iov_index);

	/* Mark as faulted */
	meta = iov_meta_get_by_index(iov_index);
	if (meta) {
		pthread_mutex_lock(&iov_meta_lock);
		meta->has_fault = true;
		pthread_mutex_unlock(&iov_meta_lock);
	}

	/* Update fault count */
	pthread_mutex_lock(&config_lock);
	config.fault_count++;
	pthread_mutex_unlock(&config_lock);

	/* Trigger all three strategies */
	queued = 0;

	/* 1. Pattern-based (highest priority) */
	queued += prefetch_pattern_based(lpi, iov_index);

	/* 2. Ahead-of-fault (medium priority) */
	queued += prefetch_ahead_of_fault(lpi, iov_index);

	/* 3. Background unrestored (low priority) */
	queued += prefetch_background_unrestored(lpi);

	pr_debug("Prefetch triggered: queued %d IOVs total\n", queued);

	/* Adapt configuration periodically */
	adapt_config();
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
int prefetch_get_idle_workers(void)
{
	int idle;

	pthread_mutex_lock(&config_lock);
	idle = config.idle_workers;
	pthread_mutex_unlock(&config_lock);

	return idle;
}
