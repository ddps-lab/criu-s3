#ifndef __CR_PAGE_CACHE_H__
#define __CR_PAGE_CACHE_H__

#include <stdbool.h>

/* IOV-based page cache for async prefetch */

/* Cache lookup result */
enum cache_result {
	CACHE_MISS = 0,
	CACHE_HIT = 1,
};

/* Cache statistics */
struct cache_stats {
	unsigned long lookups;
	unsigned long hits;
	unsigned long misses;
	unsigned long stores;
	unsigned long restores;
	unsigned long evictions;
	unsigned long total_bytes;
	unsigned long peak_bytes;
	unsigned long backpressure_waits;
	unsigned long meminfo_checks;
	unsigned long prefetch_dropped_race;
};

/*
 * Initialize cache.
 * max_memory_mb: explicit limit in MB (0 = auto-compute from total_lazy_bytes)
 * total_lazy_bytes: total size of all lazy pages (used for auto-cap formula)
 */
int cache_init(unsigned long max_memory_mb, unsigned long total_lazy_bytes);

/* Cleanup cache and free all resources */
void cache_cleanup(void);

/*
 * Wait until cache has room for incoming_size bytes.
 * Called by prefetch workers BEFORE allocating fetch buffer.
 * Must NOT hold iov_meta_lock or queue_lock when calling.
 * Returns 0 to proceed, -1 if shutdown.
 */
int cache_wait_for_room(size_t incoming_size);

/* Refine cache limit after total lazy bytes are known */
void cache_update_limit(unsigned long total_lazy_bytes);

/* Signal that prefetch system is shutting down (unblocks waiting workers) */
void cache_set_shutdown(void);

/* Track in-flight fetch bytes (worker buffer not yet in cache) */
void cache_add_inflight(size_t bytes);
void cache_remove_inflight(size_t bytes);

/* Lookup IOV in cache - returns CACHE_HIT if exact match found
 * On CACHE_HIT: allocates memory and copies data to *data_out. Caller must free.
 * On CACHE_MISS: *data_out is not modified
 *
 * This is for page fault handlers - updates statistics (lookups, hits, misses)
 */
enum cache_result cache_lookup_iov_for_fault(unsigned long iov_start, unsigned long iov_end, void **data_out);

/* Internal cache lookup without statistics update
 * Used by prefetch workers to avoid polluting page fault cache hit rate statistics
 */
enum cache_result cache_lookup_iov(unsigned long iov_start, unsigned long iov_end, void **data_out);

/* Store IOV data in cache */
int cache_store_iov(unsigned long iov_start, unsigned long iov_end, unsigned long file_offset, void *data,
		    size_t size, bool is_prefetched);

/* Mark IOV as restored - removes from cache immediately */
void cache_mark_restored(unsigned long iov_start, unsigned long iov_end);

/* Get cache statistics */
void cache_get_stats(struct cache_stats *stats);

/* Reset statistics */
void cache_reset_stats(void);

#endif /* __CR_PAGE_CACHE_H__ */
