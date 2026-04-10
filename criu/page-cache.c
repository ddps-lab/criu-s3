#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "page-cache.h"
#include "log.h"
#include "xmalloc.h"
#include "rbtree.h"
#include "object-storage.h"

/* Cache entry - one per IOV */
struct cache_entry {
	/* IOV identity */
	unsigned long iov_start;
	unsigned long iov_end;
	unsigned long file_offset;

	/* Data */
	void *data;
	size_t data_size;

	/* RB-tree node (key: iov_start) */
	struct rb_node node;

	/* Metadata */
	bool is_restored;
	bool is_prefetched;
	struct timespec enqueue_time; /* For FIFO eviction */
};

/* Global cache state */
static struct {
	struct rb_root tree;
	pthread_mutex_t lock;
	pthread_cond_t drain_cond;      /* signaled when bytes drop below low watermark */

	/* Memory tracking */
	unsigned long total_bytes;
	unsigned long inflight_bytes;   /* worker fetch buffers not yet in cache */
	unsigned long max_bytes;
	unsigned long high_watermark;   /* 85% of max_bytes — workers pause */
	unsigned long low_watermark;    /* 60% of max_bytes — workers resume */

	/* /proc/meminfo cache */
	size_t cached_avail_memory;
	unsigned long last_meminfo_store_count;

	/* Statistics */
	struct cache_stats stats;

	bool initialized;
	bool shutdown;
} cache_state = {
	.tree = RB_ROOT,
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.drain_cond = PTHREAD_COND_INITIALIZER,
	.total_bytes = 0,
	.inflight_bytes = 0,
	.max_bytes = 0,
	.initialized = false,
	.shutdown = false,
};

/* Internal: lookup cache entry by iov_start */
static struct cache_entry *cache_lookup_internal(unsigned long iov_start)
{
	struct rb_node *node = cache_state.tree.rb_node;

	while (node) {
		struct cache_entry *entry = rb_entry(node, struct cache_entry, node);

		if (iov_start < entry->iov_start)
			node = node->rb_left;
		else if (iov_start > entry->iov_start)
			node = node->rb_right;
		else
			return entry;
	}

	return NULL;
}

/* Internal: insert cache entry into RB-tree */
static int cache_insert_internal(struct cache_entry *new_entry)
{
	struct rb_node **link = &cache_state.tree.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		struct cache_entry *entry;
		parent = *link;
		entry = rb_entry(parent, struct cache_entry, node);

		if (new_entry->iov_start < entry->iov_start)
			link = &parent->rb_left;
		else if (new_entry->iov_start > entry->iov_start)
			link = &parent->rb_right;
		else
			return -1; /* Duplicate */
	}

	rb_link_node(&new_entry->node, parent, link);
	rb_insert_color(&new_entry->node, &cache_state.tree);

	return 0;
}

/* Internal: find oldest entry for FIFO eviction */
static struct cache_entry *cache_find_oldest(void)
{
	struct rb_node *node;
	struct cache_entry *entry, *oldest = NULL;

	for (node = rb_first(&cache_state.tree); node; node = rb_next(node)) {
		entry = rb_entry(node, struct cache_entry, node);

		if (!oldest || entry->enqueue_time.tv_sec < oldest->enqueue_time.tv_sec ||
		    (entry->enqueue_time.tv_sec == oldest->enqueue_time.tv_sec &&
		     entry->enqueue_time.tv_nsec < oldest->enqueue_time.tv_nsec)) {
			oldest = entry;
		}
	}

	return oldest;
}

/* Internal: evict entries to make room for incoming_size */
/*
 * Get available system memory in bytes from /proc/meminfo.
 * Returns 0 on failure.
 */
static size_t get_available_memory(void)
{
	FILE *f;
	char line[256];
	size_t avail = 0;

	f = fopen("/proc/meminfo", "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "MemAvailable: %zu kB", &avail) == 1) {
			avail *= 1024; /* kB to bytes */
			break;
		}
	}
	fclose(f);
	return avail;
}

/* Minimum available memory to maintain (1GB) */
#define CACHE_MEM_RESERVE (1024UL * 1024 * 1024)

#define MEMINFO_CHECK_INTERVAL_STORES 16

static void cache_evict_to_limit(size_t incoming_size)
{
	size_t limit;

	/* Primary: hard cap (always set, either explicit or auto-computed) */
	limit = cache_state.max_bytes;

	/*
	 * Secondary safety net: check /proc/meminfo periodically.
	 * Only if we're within 90% of hard cap AND enough stores have passed.
	 */
	if (cache_state.total_bytes + incoming_size > limit * 90 / 100) {
		unsigned long stores_since;

		stores_since = cache_state.stats.stores - cache_state.last_meminfo_store_count;
		if (stores_since >= MEMINFO_CHECK_INTERVAL_STORES) {
			size_t avail = get_available_memory();

			cache_state.stats.meminfo_checks++;
			cache_state.cached_avail_memory = avail;
			cache_state.last_meminfo_store_count = cache_state.stats.stores;

			if (avail > 0 && avail <= CACHE_MEM_RESERVE) {
				/* Memory critical: tighten limit */
				size_t tighter = cache_state.total_bytes > incoming_size ?
					cache_state.total_bytes - incoming_size : 0;
				if (tighter < limit)
					limit = tighter;
			}
		}
	}

	while (cache_state.total_bytes + incoming_size > limit) {
		struct cache_entry *oldest = cache_find_oldest();
		if (!oldest)
			break;

		pr_debug("Cache: Evicting oldest entry [0x%lx-0x%lx] (%zu bytes)\n", oldest->iov_start,
			 oldest->iov_end, oldest->data_size);

		rb_erase(&oldest->node, &cache_state.tree);
		cache_state.total_bytes -= oldest->data_size;
		cache_state.stats.evictions++;

		xfree(oldest->data);
		xfree(oldest);
	}

	/* Signal workers if eviction brought us below low watermark */
	if (cache_state.total_bytes < cache_state.low_watermark)
		pthread_cond_broadcast(&cache_state.drain_cond);
}

int cache_init(unsigned long max_memory_mb, unsigned long total_lazy_bytes)
{
	if (cache_state.initialized)
		return 0;

	cache_state.tree = RB_ROOT;
	cache_state.total_bytes = 0;
	cache_state.inflight_bytes = 0;
	cache_state.shutdown = false;
	memset(&cache_state.stats, 0, sizeof(cache_state.stats));

	if (max_memory_mb > 0) {
		cache_state.max_bytes = max_memory_mb * 1024 * 1024;
	} else {
		/*
		 * Auto-compute cache limit:
		 *   min(total_lazy_bytes / 3, max(256MB, available / 4))
		 *
		 * - total_lazy/3: cache more than 1/3 of restore data is wasteful
		 * - available/4: conservative — init snapshot may be optimistic
		 *   as process RSS grows during restore
		 * - Runtime watermark + meminfo secondary check provide additional control
		 */
		size_t avail = get_available_memory();
		size_t from_lazy = total_lazy_bytes / 3;
		size_t from_avail = avail / 4;
		size_t floor = 256UL * 1024 * 1024;

		if (from_avail < floor)
			from_avail = floor;
		cache_state.max_bytes = (from_lazy < from_avail) ? from_lazy : from_avail;
		if (cache_state.max_bytes < floor)
			cache_state.max_bytes = floor;
	}

	cache_state.high_watermark = cache_state.max_bytes * 85 / 100;
	cache_state.low_watermark = cache_state.max_bytes * 60 / 100;

	cache_state.initialized = true;

	pr_info("IOV-based page cache initialized (max: %lu MB, high: %lu MB, low: %lu MB, lazy total: %lu MB)\n",
		cache_state.max_bytes / (1024 * 1024),
		cache_state.high_watermark / (1024 * 1024),
		cache_state.low_watermark / (1024 * 1024),
		total_lazy_bytes / (1024 * 1024));

	return 0;
}

void cache_update_limit(unsigned long total_lazy_bytes)
{
	size_t new_max;
	size_t from_lazy;
	size_t avail;
	size_t floor;

	if (!cache_state.initialized)
		return;

	/* If user set explicit --cache-limit, don't override */
	if (cache_state.max_bytes != 256UL * 1024 * 1024 &&
	    cache_state.max_bytes != 0)
		return;

	floor = 256UL * 1024 * 1024;
	avail = get_available_memory();
	from_lazy = total_lazy_bytes / 3;

	if (avail / 4 > floor)
		new_max = avail / 4;
	else
		new_max = floor;

	if (from_lazy > 0 && from_lazy < new_max)
		new_max = from_lazy;

	if (new_max < floor)
		new_max = floor;

	pthread_mutex_lock(&cache_state.lock);
	cache_state.max_bytes = new_max;
	cache_state.high_watermark = new_max * 85 / 100;
	cache_state.low_watermark = new_max * 60 / 100;
	pthread_mutex_unlock(&cache_state.lock);

	pr_info("Cache limit updated: max=%lu MB, high=%lu MB, low=%lu MB (lazy total=%lu MB)\n",
		new_max / (1024 * 1024),
		cache_state.high_watermark / (1024 * 1024),
		cache_state.low_watermark / (1024 * 1024),
		total_lazy_bytes / (1024 * 1024));
}

void cache_cleanup(void)
{
	struct rb_node *node;
	struct cache_entry *entry;

	if (!cache_state.initialized)
		return;

	pthread_mutex_lock(&cache_state.lock);

	/* Free all entries */
	while ((node = rb_first(&cache_state.tree)) != NULL) {
		entry = rb_entry(node, struct cache_entry, node);
		rb_erase(node, &cache_state.tree);
		xfree(entry->data);
		xfree(entry);
	}

	cache_state.initialized = false;
	cache_state.total_bytes = 0;

	pthread_mutex_unlock(&cache_state.lock);

	pr_info("Page cache cleanup complete. Final stats: lookups=%lu, hits=%lu (%.1f%%), stores=%lu, "
		"evictions=%lu, backpressure=%lu, meminfo_checks=%lu\n",
		cache_state.stats.lookups, cache_state.stats.hits,
		cache_state.stats.lookups ? (100.0 * cache_state.stats.hits / cache_state.stats.lookups) : 0.0,
		cache_state.stats.stores, cache_state.stats.evictions,
		cache_state.stats.backpressure_waits, cache_state.stats.meminfo_checks);
}

/*
 * Wait until cache + inflight bytes are below high watermark.
 * Called by prefetch workers BEFORE allocating fetch buffer.
 *
 * Lock discipline: must NOT hold iov_meta_lock or queue_lock.
 * This function acquires cache_state.lock internally.
 */
int cache_wait_for_room(size_t incoming_size)
{
	struct timespec ts;

	if (!cache_state.initialized || cache_state.max_bytes == 0)
		return 0;

	pthread_mutex_lock(&cache_state.lock);
	while (cache_state.total_bytes + cache_state.inflight_bytes + incoming_size
	       >= cache_state.high_watermark) {
		if (cache_state.shutdown) {
			pthread_mutex_unlock(&cache_state.lock);
			return -1;
		}
		cache_state.stats.backpressure_waits++;
		/* Timed wait: 100ms to check shutdown flag */
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_nsec += 100 * 1000000;
		if (ts.tv_nsec >= 1000000000) {
			ts.tv_sec += 1;
			ts.tv_nsec -= 1000000000;
		}
		pthread_cond_timedwait(&cache_state.drain_cond,
				       &cache_state.lock, &ts);
	}
	pthread_mutex_unlock(&cache_state.lock);
	return 0;
}

void cache_set_shutdown(void)
{
	pthread_mutex_lock(&cache_state.lock);
	cache_state.shutdown = true;
	pthread_cond_broadcast(&cache_state.drain_cond);
	pthread_mutex_unlock(&cache_state.lock);
}

void cache_add_inflight(size_t bytes)
{
	pthread_mutex_lock(&cache_state.lock);
	cache_state.inflight_bytes += bytes;
	pthread_mutex_unlock(&cache_state.lock);
}

void cache_remove_inflight(size_t bytes)
{
	pthread_mutex_lock(&cache_state.lock);
	if (cache_state.inflight_bytes >= bytes)
		cache_state.inflight_bytes -= bytes;
	else
		cache_state.inflight_bytes = 0;
	pthread_mutex_unlock(&cache_state.lock);
}

/* Internal lookup with statistics - for page fault handlers */
enum cache_result cache_lookup_iov_for_fault(unsigned long iov_start, unsigned long iov_end, void **data_out)
{
	struct cache_entry *entry;
	enum cache_result result = CACHE_MISS;

	if (!cache_state.initialized)
		return CACHE_MISS;

	pthread_mutex_lock(&cache_state.lock);

	cache_state.stats.lookups++;

	entry = cache_lookup_internal(iov_start);

	if (entry && entry->iov_start == iov_start && entry->iov_end == iov_end) {
		/*
		 * Exact match - copy data and remove entry from cache.
		 * Deep copy is needed because prefetch workers may still
		 * reference the cache tree concurrently.
		 */
		void *data_copy = xmalloc(entry->data_size);
		if (!data_copy) {
			pr_err("Failed to allocate memory for cache data copy\n");
			pthread_mutex_unlock(&cache_state.lock);
			return CACHE_MISS;
		}

		memcpy(data_copy, entry->data, entry->data_size);
		*data_out = data_copy;
		cache_state.stats.hits++;
		result = CACHE_HIT;

		/* Remove entry from cache to free memory immediately */
		{
			size_t freed_size = entry->data_size;
			rb_erase(&entry->node, &cache_state.tree);
			cache_state.total_bytes -= freed_size;
			xfree(entry->data);
			xfree(entry);

			/* Signal workers if below low watermark */
			if (cache_state.total_bytes < cache_state.low_watermark)
				pthread_cond_broadcast(&cache_state.drain_cond);

			PREFETCH_CACHE_HIT_LOG(-1);
			pr_debug("Cache HIT: IOV [0x%lx-0x%lx] (%zu bytes, removed)\n",
				 iov_start, iov_end, freed_size);
		}
	} else {
		cache_state.stats.misses++;
		result = CACHE_MISS;

		/* Log cache miss for simulation */
		PREFETCH_CACHE_MISS_LOG(-1);
		pr_debug("Cache MISS: IOV [0x%lx-0x%lx]\n", iov_start, iov_end);
	}

	pthread_mutex_unlock(&cache_state.lock);

	return result;
}

/* Internal lookup without statistics - for prefetch workers */
enum cache_result cache_lookup_iov(unsigned long iov_start, unsigned long iov_end, void **data_out)
{
	struct cache_entry *entry;
	enum cache_result result = CACHE_MISS;

	if (!cache_state.initialized)
		return CACHE_MISS;

	pthread_mutex_lock(&cache_state.lock);

	/* No statistics update for prefetch worker lookups */

	entry = cache_lookup_internal(iov_start);

	if (entry && entry->iov_start == iov_start && entry->iov_end == iov_end) {
		/* Exact match - allocate and copy data to avoid use-after-free */
		void *data_copy = xmalloc(entry->data_size);
		if (!data_copy) {
			pr_err("Failed to allocate memory for cache data copy\n");
			pthread_mutex_unlock(&cache_state.lock);
			return CACHE_MISS;
		}

		memcpy(data_copy, entry->data, entry->data_size);
		*data_out = data_copy;
		result = CACHE_HIT;

		pr_debug("Cache HIT (no stats): IOV [0x%lx-0x%lx] (%zu bytes)\n", iov_start, iov_end, entry->data_size);
	} else {
		result = CACHE_MISS;

		pr_debug("Cache MISS (no stats): IOV [0x%lx-0x%lx]\n", iov_start, iov_end);
	}

	pthread_mutex_unlock(&cache_state.lock);

	return result;
}

int cache_store_iov(unsigned long iov_start, unsigned long iov_end, unsigned long file_offset, void *data,
		    size_t size, bool is_prefetched)
{
	struct cache_entry *entry;

	if (!cache_state.initialized)
		return -1;

	pthread_mutex_lock(&cache_state.lock);

	/* Check if already exists */
	entry = cache_lookup_internal(iov_start);
	if (entry) {
		pr_debug("Cache SKIP: IOV [0x%lx-0x%lx] already exists\n", iov_start, iov_end);
		pthread_mutex_unlock(&cache_state.lock);
		return 0;
	}

	/* Evict if needed */
	cache_evict_to_limit(size);

	/* Create new entry */
	entry = xzalloc(sizeof(*entry));
	if (!entry) {
		pthread_mutex_unlock(&cache_state.lock);
		return -1;
	}

	entry->iov_start = iov_start;
	entry->iov_end = iov_end;
	entry->file_offset = file_offset;
	entry->data_size = size;
	entry->is_restored = false;
	entry->is_prefetched = is_prefetched;
	clock_gettime(CLOCK_MONOTONIC, &entry->enqueue_time);

	/* Deep copy data into cache entry */
	entry->data = xmalloc(size);
	if (!entry->data) {
		xfree(entry);
		pthread_mutex_unlock(&cache_state.lock);
		return -1;
	}
	memcpy(entry->data, data, size);

	/* Insert into tree */
	if (cache_insert_internal(entry) < 0) {
		xfree(entry->data);
		xfree(entry);
		pthread_mutex_unlock(&cache_state.lock);
		return -1;
	}

	cache_state.total_bytes += size;
	cache_state.stats.stores++;

	if (cache_state.total_bytes > cache_state.stats.peak_bytes)
		cache_state.stats.peak_bytes = cache_state.total_bytes;

	/* Log cache store for simulation */
	PREFETCH_CACHE_STORE_LOG(-1, size);
	pr_debug("Cache STORE: IOV [0x%lx-0x%lx] (%zu bytes, prefetched=%d)\n", iov_start, iov_end, size,
		 is_prefetched);

	pthread_mutex_unlock(&cache_state.lock);

	return 0;
}

void cache_mark_restored(unsigned long iov_start, unsigned long iov_end)
{
	struct cache_entry *entry;

	if (!cache_state.initialized)
		return;

	pthread_mutex_lock(&cache_state.lock);

	entry = cache_lookup_internal(iov_start);
	if (entry && entry->iov_start == iov_start && entry->iov_end == iov_end) {
		pr_debug("Cache: Removing restored IOV [0x%lx-0x%lx] (%zu bytes)\n", iov_start, iov_end,
			 entry->data_size);

		rb_erase(&entry->node, &cache_state.tree);
		cache_state.total_bytes -= entry->data_size;
		cache_state.stats.restores++;

		xfree(entry->data);
		xfree(entry);
	}

	pthread_mutex_unlock(&cache_state.lock);
}

void cache_get_stats(struct cache_stats *stats)
{
	if (!cache_state.initialized || !stats)
		return;

	pthread_mutex_lock(&cache_state.lock);
	*stats = cache_state.stats;
	stats->total_bytes = cache_state.total_bytes;
	pthread_mutex_unlock(&cache_state.lock);
}

void cache_reset_stats(void)
{
	if (!cache_state.initialized)
		return;

	pthread_mutex_lock(&cache_state.lock);
	memset(&cache_state.stats, 0, sizeof(cache_state.stats));
	pthread_mutex_unlock(&cache_state.lock);
}
