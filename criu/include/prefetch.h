#ifndef __CR_PREFETCH_H__
#define __CR_PREFETCH_H__

#include <stdbool.h>

/* Async prefetch for IOV-based lazy pages */

/* Prefetch priority levels */
enum prefetch_priority {
	PRIORITY_PATTERN = 90,	 /* Pattern-based prediction */
	PRIORITY_AHEAD = 70,	 /* Ahead-of-fault */
	PRIORITY_BACKGROUND = 30 /* Background unrestored IOVs */
};

/* Prefetch statistics */
struct prefetch_stats {
	unsigned long total_requests;
	unsigned long completed;
	unsigned long failed;
	unsigned long cache_stored;
	unsigned long pattern_count;
	unsigned long ahead_count;
	unsigned long background_count;
	unsigned long bytes_prefetched;
};

/* IOV info for metadata initialization */
struct iov_info {
	unsigned long iov_start;
	unsigned long iov_end;
	unsigned long file_offset;
};

/* Initialize prefetch system with N workers */
int prefetch_init(int num_workers);

/* Cleanup prefetch system */
void prefetch_cleanup(void);

/* Initialize IOV metadata from IOV array */
int prefetch_init_iovs(void *lpi, unsigned int pages_img_id, struct iov_info *iovs, int num_iovs);

/* Pre-queue all IOVs for controller-based prefetch */
int prefetch_prequeue_all_iovs(void *lpi, unsigned int pages_img_id);

/* Get IOV index by address (correct mapping using RB-tree) */
int iov_meta_get_index_by_addr(unsigned long addr);

/* Queue IOV for prefetch */
int prefetch_queue_iov(void *lpi, unsigned long iov_start, unsigned long iov_end, unsigned long file_offset,
		       enum prefetch_priority priority);

/* Trigger prefetch strategies on page fault */
void prefetch_on_fault(void *lpi, int iov_index);

/* Get prefetch statistics */
void prefetch_get_stats(struct prefetch_stats *stats);

/* Reset statistics */
void prefetch_reset_stats(void);

/* Get idle worker count */
int prefetch_get_idle_workers(void);

#endif /* __CR_PREFETCH_H__ */
