#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "page-cache.h"
#include "log.h"
#include "xmalloc.h"
#include "rbtree.h"

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

	/* Memory tracking */
	unsigned long total_bytes;
	unsigned long max_bytes;

	/* Statistics */
	struct cache_stats stats;

	bool initialized;
} cache_state = {
	.tree = RB_ROOT,
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.total_bytes = 0,
	.max_bytes = 0,
	.initialized = false,
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
static void cache_evict_to_limit(size_t incoming_size)
{
	if (cache_state.max_bytes == 0)
		return; /* Unlimited */

	while (cache_state.total_bytes + incoming_size > cache_state.max_bytes) {
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
}

int cache_init(unsigned long max_memory_mb)
{
	if (cache_state.initialized)
		return 0;

	cache_state.tree = RB_ROOT;
	cache_state.total_bytes = 0;
	cache_state.max_bytes = max_memory_mb * 1024 * 1024; /* Convert MB to bytes */

	memset(&cache_state.stats, 0, sizeof(cache_state.stats));
	cache_state.initialized = true;

	if (max_memory_mb == 0) {
		pr_info("IOV-based page cache initialized (unlimited memory)\n");
	} else {
		pr_info("IOV-based page cache initialized (max memory: %lu MB)\n", max_memory_mb);
	}

	return 0;
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

	pr_info("Page cache cleanup complete. Final stats: lookups=%lu, hits=%lu (%.1f%%), stores=%lu\n",
		cache_state.stats.lookups, cache_state.stats.hits,
		cache_state.stats.lookups ? (100.0 * cache_state.stats.hits / cache_state.stats.lookups) : 0.0,
		cache_state.stats.stores);
}

enum cache_result cache_lookup_iov(unsigned long iov_start, unsigned long iov_end, void **data_out)
{
	struct cache_entry *entry;
	enum cache_result result = CACHE_MISS;

	if (!cache_state.initialized)
		return CACHE_MISS;

	pthread_mutex_lock(&cache_state.lock);

	cache_state.stats.lookups++;

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
		cache_state.stats.hits++;
		result = CACHE_HIT;

		pr_debug("Cache HIT: IOV [0x%lx-0x%lx] (%zu bytes)\n", iov_start, iov_end, entry->data_size);
	} else {
		cache_state.stats.misses++;
		result = CACHE_MISS;

		pr_debug("Cache MISS: IOV [0x%lx-0x%lx]\n", iov_start, iov_end);
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

	/* Allocate and copy data */
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
