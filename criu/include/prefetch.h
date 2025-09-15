#ifndef __CR_PREFETCH_H__
#define __CR_PREFETCH_H__

#include <stdbool.h>
#include <pthread.h>
#include "common/list.h"

enum prefetch_type {
    PREFETCH_AHEAD_OF_FAULT,
    PREFETCH_SEQUENTIAL,
    PREFETCH_PATTERN_BASED
};

struct prefetch_request {
    unsigned long semi_sync_start;
    unsigned long semi_sync_end;
    unsigned long file_offset;
    enum prefetch_type type;
    struct list_head list;
    void *lpi;
    int priority;
};

struct prefetch_stats {
    unsigned long total_requests;
    unsigned long completed;
    unsigned long failed;
    unsigned long cache_stored;
    unsigned long ahead_of_fault_count;
    unsigned long sequential_count;
    unsigned long pattern_based_count;
    unsigned long pattern_sparse_skips;  /* Track sparse region skips */
    unsigned long bytes_prefetched;
};

int prefetch_init(void);
void prefetch_cleanup(void);

int prefetch_queue_semi_sync_unit(unsigned long vaddr_start, unsigned long file_offset,
                                  void *lpi, enum prefetch_type type);

int prefetch_ahead_of_fault(unsigned long current_fault_addr, void *lpi);

void prefetch_start_sequential(void *lpi);
void prefetch_stop_sequential(void);

void prefetch_get_stats(struct prefetch_stats *stats);
void prefetch_reset_stats(void);

bool prefetch_is_active(void);
int prefetch_get_queue_size(void);

#endif