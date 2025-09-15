#ifndef __CR_PAGE_CACHE_H__
#define __CR_PAGE_CACHE_H__

#include <stdbool.h>
#include <pthread.h>
#include "rbtree.h"
#include "common/list.h"

#define SEMI_SYNC_UNIT_PAGES    1024
#define SEMI_SYNC_UNIT_SIZE     (SEMI_SYNC_UNIT_PAGES * PAGE_SIZE)
#define MAX_CACHE_UNITS         0  /* 0 = unlimited cache */
#define MAX_CACHE_MEMORY        0  /* 0 = unlimited cache */

struct semi_sync_cache_entry {
    unsigned long vaddr_start;
    unsigned long vaddr_end;
    unsigned long file_offset;
    void *data;
    size_t data_size;
    struct rb_node vaddr_node;
    struct list_head lru_list;
    bool is_complete;
    unsigned long access_count;
    struct timespec last_access;
};

struct semi_sync_cache_stats {
    unsigned long total_lookups;
    unsigned long full_hits;
    unsigned long misses;
    unsigned long prefetch_triggered;
    unsigned long prefetch_hits;
    unsigned long evictions;
    size_t current_memory;
    size_t peak_memory;
    unsigned long s3_fetches_saved;
};

enum cache_lookup_result {
    CACHE_MISS = 0,
    CACHE_FULL_HIT = 1,
};

int page_cache_init(void);
void page_cache_cleanup(void);

enum cache_lookup_result page_cache_lookup_semi_sync(unsigned long vaddr_start,
                                                     unsigned long vaddr_end,
                                                     void **data_out);

int page_cache_store_semi_sync(unsigned long vaddr_start, unsigned long vaddr_end,
                               unsigned long file_offset, void *data, size_t data_size);

void page_cache_get_stats(struct semi_sync_cache_stats *stats);
void page_cache_reset_stats(void);

unsigned long page_cache_align_to_semi_sync(unsigned long addr);
bool page_cache_should_prefetch_next(unsigned long vaddr_start);

void page_cache_mark_access_pattern(unsigned long addr);
unsigned long page_cache_get_next_prefetch_target(unsigned long current_addr);

#endif