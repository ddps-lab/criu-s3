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
#define DEFAULT_AHEAD_IOVS 32  /* Coverage-first: ahead determines hit potential */
#define DEFAULT_BACKGROUND_IOVS 0  /* Sequential workload: focus on ahead, disable background */
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
	bool queued;         /* Currently in prefetch queue */

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

static int proximity_window = PROXIMITY_WINDOW_DEFAULT;

/* ========== IOV Metadata Functions (Phase 2) ========== */

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
		meta->has_fault = false;
		meta->in_cache = false;
		meta->prefetching = false;
		meta->restored = false;
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
	int consecutive_seq;
	int max_consecutive;
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

	/* Analyze for sequential pattern with enhanced detection */
	sequential_count = 0;
	consecutive_seq = 0;  /* Count consecutive sequential accesses */
	max_consecutive = 0;

	for (i = 1; i < window_size; i++) {
		if (indices[i] == indices[i-1] + 1) {
			sequential_count++;
			consecutive_seq++;
			if (consecutive_seq > max_consecutive)
				max_consecutive = consecutive_seq;
		} else {
			consecutive_seq = 0;
		}
	}

	seq_ratio = (float)sequential_count / (window_size - 1);

	/* Enhanced confidence: boost if we have long consecutive runs */
	if (max_consecutive >= 3) {
		/* Strong sequential pattern: 3+ consecutive accesses */
		info.type = PATTERN_SEQUENTIAL;
		info.confidence = 0.95;  /* High confidence for consecutive pattern */
		return info;
	} else if (seq_ratio > 0.7) {
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
static void __attribute__((unused)) adapt_config(void)
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
static int __attribute__((unused)) prefetch_pattern_based(void *lpi, int current_iov_index)
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
static int __attribute__((unused)) prefetch_ahead_of_fault(void *lpi, int current_iov_index)
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
		unsigned long iov_size;

		target_index = current_iov_index + i;

		if (target_index >= total_iovs)
			break;

		meta = iov_meta_get_by_index(target_index);
		if (!meta || meta->restored || meta->prefetching)
			continue;

		/* Skip small IOVs (< 256KB) - not worth prefetching */
		iov_size = meta->iov_end - meta->iov_start;
		if (iov_size < (256 * 1024))
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
static int __attribute__((unused)) prefetch_background_unrestored(void *lpi)
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
		unsigned long iov_size;

		if (!meta || meta->restored || meta->prefetching || meta->has_fault)
			continue;

		/* Skip small IOVs (< 256KB) - not worth prefetching */
		iov_size = meta->iov_end - meta->iov_start;
		if (iov_size < (256 * 1024))
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

		/* Remove from hash table (controller uses hash for O(1) lookup) */
		pthread_mutex_lock(&queue_lock);
		hash_table_remove(&request_hash_table, req->iov_index);
		pthread_mutex_unlock(&queue_lock);

		/* Check metadata */
		pthread_mutex_lock(&iov_meta_lock);
		meta = iov_meta_search(req->iov_start);

		if (meta) {
			/* Skip if already in cache */
			if (meta->in_cache) {
				pthread_mutex_unlock(&iov_meta_lock);
				pr_debug("PREFETCH: Worker %d: IOV[%d] already in cache, skipping\n",
					 worker_id, req->iov_index);
				xfree(req);
				continue;
			}

			/* Set prefetching flag */
			meta->prefetching = true;
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

				/* Calculate worker duration and log completion */
				clock_gettime(CLOCK_MONOTONIC, &worker_end);
				worker_duration_ms = (worker_end.tv_sec - worker_start.tv_sec) * 1000.0 +
						     (worker_end.tv_nsec - worker_start.tv_nsec) / 1000000.0;
				PREFETCH_WORKER_DONE_LOG(worker_id, req->iov_index, worker_duration_ms);

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

	/* Cleanup hash table */
	hash_table_cleanup(&request_hash_table);

	/* Print controller stats */
	pthread_mutex_lock(&controller_stats_lock);
	pr_info("CONTROLLER Stats: faults=%lu removes=%lu promotes=%lu obsolete_prevented=%lu proximity_removed=%lu\n",
		controller_stats.faults_processed,
		controller_stats.queue_removes,
		controller_stats.priority_promotions,
		controller_stats.obsolete_prevented,
		controller_stats.proximity_removed);
	pthread_mutex_unlock(&controller_stats_lock);

	pr_info("Prefetch system cleaned up\n");
}

/* Pre-queue all IOVs for controller-based prefetch */
int prefetch_prequeue_all_iovs(void *lpi, unsigned int pages_img_id)
{
	int i, queued = 0;

	if (!global_lpi || !iov_index_map) {
		pr_err("CONTROLLER: Cannot pre-queue - IOV metadata not initialized\n");
		return -EINVAL;
	}

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

		/* Initial priority: First 32 = MEDIUM (50), rest = LOW (20) */
		if (i < 32) {
			initial_priority = 50;  /* PRIORITY_MEDIUM */
			list_add_tail(&req->list, &queue_medium);
		} else {
			initial_priority = 20;  /* PRIORITY_LOW */
			list_add_tail(&req->list, &queue_low);
		}

		req->priority = initial_priority;

		/* Add to hash table for O(1) lookup */
		if (hash_table_insert(&request_hash_table, i, req) < 0) {
			pr_warn("CONTROLLER: Failed to insert IOV[%d] into hash table\n", i);
			list_del(&req->list);
			xfree(req);
			continue;
		}

		queued++;
	}

	pthread_mutex_unlock(&queue_lock);

	pr_info("CONTROLLER: Pre-queued %d IOVs (filtered %d small IOVs)\n",
		queued, total_iovs - queued);

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
		if (meta->in_cache || meta->restored) {
			pthread_mutex_unlock(&iov_meta_lock);
			return 0;
		}

		/* Skip if already being prefetched - no need to re-queue */
		if (meta->prefetching) {
			pthread_mutex_unlock(&iov_meta_lock);
			return 0;
		}

		/* Mark as prefetching immediately at queue time to prevent duplicates */
		/* This is the key: set flag BEFORE queueing to prevent race condition */
		meta->prefetching = true;

		pthread_mutex_unlock(&iov_meta_lock);
	}

	/* Create request */
	req = xzalloc(sizeof(*req));
	if (!req) {
		pr_err("Failed to allocate prefetch request\n");
		/* Rollback prefetching flag on allocation failure */
		if (meta) {
			pthread_mutex_lock(&iov_meta_lock);
			meta->prefetching = false;
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
	struct pattern_info pattern;
	int promote_count = 0;
	int promote_distance = 0;
	int current_queue_size;
	int base_forward_window;

	pr_debug("CONTROLLER: Page fault at IOV index %d\n", iov_index);

	/* Update access history */
	update_access_history(iov_index);

	/* Detect pattern first for logging */
	{
		struct pattern_info early_pattern = detect_pattern();
		PREFETCH_CONTROLLER_FAULT_LOG(iov_index, early_pattern.type, early_pattern.confidence);
	}

	/* Mark as faulted */
	meta = iov_meta_get_by_index(iov_index);
	if (meta) {
		pthread_mutex_lock(&iov_meta_lock);
		meta->has_fault = true;
		pthread_mutex_unlock(&iov_meta_lock);
	}

	/* === CONTROLLER LOGIC === */
	pthread_mutex_lock(&queue_lock);

	/* 1. Remove faulted IOV from queue (already on-demand fetched) */
	{
		struct prefetch_request *faulted_req = hash_table_lookup(&request_hash_table, iov_index);
		if (faulted_req) {
			PREFETCH_CONTROLLER_REMOVE_LOG(iov_index, "on-demand");
			list_del(&faulted_req->list);
			hash_table_remove(&request_hash_table, iov_index);
			xfree(faulted_req);

			pthread_mutex_lock(&controller_stats_lock);
			controller_stats.queue_removes++;
			controller_stats.obsolete_prevented++;
			pthread_mutex_unlock(&controller_stats_lock);

			pr_debug("CONTROLLER: Removed IOV[%d] from queue (on-demand fetched)\n", iov_index);
		}
	}

	/* 2. Detect pattern */
	pattern = detect_pattern();

	/* 2.1. Calculate current queue size for adaptive calculations */
	current_queue_size = request_hash_table.count;

	/* 2.2. Formula-based adaptive proximity window calculation */
	if (pattern.type == PATTERN_SEQUENTIAL) {
		/* Sequential pattern: Use formula-based continuous scaling */
		float queue_health;

		/* Base window on confidence */
		if (pattern.confidence > 0.8) {
			base_forward_window = PROXIMITY_WINDOW_SEQUENTIAL;  /* 8 for strong sequential */
		} else if (pattern.confidence > 0.5) {
			base_forward_window = PROXIMITY_WINDOW_DEFAULT;  /* 8 for moderate sequential */
		} else {
			base_forward_window = 4;  /* 4 for weak sequential */
		}

		/* Formula: forward_window = base × queue_health_factor
		 * queue_health = current_queue_size / TARGET_QUEUE_SIZE
		 * Clamp to [0.25, 1.0] to keep window in [base/4, base] range
		 */
		queue_health = (float)current_queue_size / TARGET_QUEUE_SIZE;
		if (queue_health < 0.25f)
			queue_health = 0.25f;
		if (queue_health > 1.0f)
			queue_health = 1.0f;

		/* Continuous scaling: 1 unit precision */
		proximity_window = (int)(base_forward_window * queue_health);

		/* Ensure minimum window */
		if (proximity_window < 2)
			proximity_window = 2;

		/* Critical queue: disable removal */
		if (current_queue_size < 16) {
			proximity_window = 0;
			pr_info("CONTROLLER: Queue critically low (%d IOVs), disabling proximity removal\n",
				current_queue_size);
		}
	} else if (pattern.type == PATTERN_RANDOM) {
		/* Random pattern: application may NOT access nearby IOVs */
		proximity_window = 0;  /* No proximity removal for random access */
	} else if (pattern.type == PATTERN_STRIDE) {
		/* Stride pattern: only remove strided IOVs, not sequential */
		proximity_window = 0;  /* Handle separately in stride promotion logic */
	} else {
		/* Unknown pattern: conservative removal */
		proximity_window = PROXIMITY_WINDOW_RANDOM;  /* 4 as default conservative */
	}

	/* 2.3. Remove proximity IOVs from queue (only for sequential patterns) */
	{
		int proximity_removed_count = 0;
		int backward_jump_detected = 0;
		int backward_window = 0;

		/* Detect backward jump: check if we jumped back significantly */
		if (history_count >= 2) {
			int prev_iov = access_history[(history_head - 1 + PATTERN_HISTORY_SIZE) % PATTERN_HISTORY_SIZE];
			int delta = iov_index - prev_iov;

			/* If we jumped backward by more than 8 IOVs, don't remove backward IOVs */
			if (delta < -8) {
				backward_jump_detected = 1;
				pr_info("CONTROLLER: Backward jump detected: %d -> %d (delta=%d)\n",
					 prev_iov, iov_index, delta);
			}
		}

		/* Formula: backward_window = forward_window / 4
		 * Backward jumps are rare (~0.5%), so conservative removal
		 * Minimum: 1 IOV if forward >= 4
		 */
		if (proximity_window >= 4) {
			backward_window = proximity_window / 4;
			if (backward_window < 1)
				backward_window = 1;  /* Ensure minimum 1 */
		} else {
			backward_window = 0;  /* No backward removal if forward < 4 */
		}

		/* Only remove if we have a predictable pattern */
		if (proximity_window > 0) {
			/* Forward removal */
			for (int i = 1; i <= proximity_window; i++) {
				int proximity_idx = iov_index + i;
				struct prefetch_request *prox_req = hash_table_lookup(&request_hash_table, proximity_idx);
				if (prox_req) {
					PREFETCH_CONTROLLER_REMOVE_LOG(proximity_idx, "proximity_fwd");
					list_del(&prox_req->list);
					hash_table_remove(&request_hash_table, proximity_idx);
					xfree(prox_req);
					proximity_removed_count++;

					pr_debug("CONTROLLER: Removed forward proximity IOV[%d] (window=%d)\n",
						 proximity_idx, proximity_window);
				}
			}

			/* Backward removal: smaller window, only if no backward jump detected */
			if (!backward_jump_detected && backward_window > 0) {
				for (int i = 1; i <= backward_window; i++) {
					int proximity_idx = iov_index - i;
					struct prefetch_request *prox_req = hash_table_lookup(&request_hash_table, proximity_idx);
					if (prox_req) {
						PREFETCH_CONTROLLER_REMOVE_LOG(proximity_idx, "proximity_bwd");
						list_del(&prox_req->list);
						hash_table_remove(&request_hash_table, proximity_idx);
						xfree(prox_req);
						proximity_removed_count++;

						pr_debug("CONTROLLER: Removed backward proximity IOV[%d] (window=%d)\n",
							 proximity_idx, backward_window);
					}
				}
			} else if (backward_jump_detected) {
				pr_info("CONTROLLER: Skipped backward removal due to backward jump (preserving IOVs for potential re-access)\n");
			}
		}

		pthread_mutex_lock(&controller_stats_lock);
		controller_stats.proximity_removed += proximity_removed_count;
		pthread_mutex_unlock(&controller_stats_lock);

		if (proximity_removed_count > 0) {
			pr_debug("CONTROLLER: Removed %d proximity IOVs (fwd_win=%d, bwd_win=%d, queue=%d, pattern=%d, conf=%.2f, bwd_jump=%d)\n",
				 proximity_removed_count, proximity_window, backward_window, current_queue_size,
				 pattern.type, pattern.confidence, backward_jump_detected);
		}
	}

	/* 3. Formula-based adaptive promotion distance */
	switch (pattern.type) {
	case PATTERN_SEQUENTIAL:
		{
			int queue_deficit;
			int base_promote_distance;

			/* Base distance on confidence */
			if (pattern.confidence > 0.8) {
				base_promote_distance = 64;  /* Strong sequential */
			} else if (pattern.confidence > 0.6) {
				base_promote_distance = 32;  /* Moderate sequential */
			} else {
				base_promote_distance = 16;   /* Weak sequential */
			}

			/* Formula: promote_distance = BASE + (queue_deficit / 2)
			 * queue_deficit = max(0, TARGET - current)
			 * Damping factor (/ 2) prevents over-promotion when queue is healthy
			 * This provides gradual refill rather than aggressive promotion
			 */
			queue_deficit = TARGET_QUEUE_SIZE - current_queue_size;
			if (queue_deficit < 0)
				queue_deficit = 0;

			/* Apply damping: half of deficit for gradual adjustment */
			promote_distance = base_promote_distance + (queue_deficit / 2);

			/* Cap maximum to avoid excessive promotion */
			if (promote_distance > 128)
				promote_distance = 128;

			pr_debug("ADAPTIVE: queue=%d deficit=%d base_promote=%d final_promote=%d\n",
				 current_queue_size, queue_deficit, base_promote_distance, promote_distance);

			/* Promote IOVs AFTER proximity window to HIGH priority */
			/* Workers should focus on IOVs that application won't access immediately */
			for (int i = proximity_window + 1; i <= proximity_window + promote_distance; i++) {
				if (promote_iov_priority(iov_index + i, 70) == 0) {
					promote_count++;
				}
			}
		}
		break;

	case PATTERN_STRIDE:
		/* Promote stride-based IOVs */
		for (int i = 1; i <= 16; i++) {
			if (promote_iov_priority(iov_index + i * pattern.stride, 70) == 0) {
				promote_count++;
			}
		}
		break;

	case PATTERN_RANDOM:
		/* Minimal prefetch */
		promote_iov_priority(iov_index + 1, 60);
		promote_iov_priority(iov_index + 2, 60);
		promote_count = 2;
		break;

	default:
		/* Default: ahead 8 */
		for (int i = 1; i <= 8; i++) {
			if (promote_iov_priority(iov_index + i, 65) == 0) {
				promote_count++;
			}
		}
		break;
	}

	pthread_mutex_unlock(&queue_lock);

	/* 4. Wake worker if promoted any IOVs */
	if (promote_count > 0) {
		pthread_cond_signal(&queue_cond);
	}

	/* Update controller stats */
	pthread_mutex_lock(&controller_stats_lock);
	controller_stats.faults_processed++;
	controller_stats.priority_promotions += promote_count;
	pthread_mutex_unlock(&controller_stats_lock);

	pr_debug("CONTROLLER: Pattern=%d conf=%.2f, promoted %d IOVs\n",
		 pattern.type, pattern.confidence, promote_count);
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
