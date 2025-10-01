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
};

/* Initialize cache with memory limit (0 = unlimited) */
int cache_init(unsigned long max_memory_mb);

/* Cleanup cache and free all resources */
void cache_cleanup(void);

/* Lookup IOV in cache - returns CACHE_HIT if exact match found
 * On CACHE_HIT: allocates memory and copies data to *data_out. Caller must free.
 * On CACHE_MISS: *data_out is not modified
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
