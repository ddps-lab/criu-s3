#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "page-cache.h"
#include "log.h"
#include "xmalloc.h"
#include "page.h"
#include "common/list.h"

static struct rb_root cache_vaddr_root = RB_ROOT;
static LIST_HEAD(cache_lru_list);
static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
static struct semi_sync_cache_stats cache_stats = {0};

static bool cache_initialized = false;

#define PATTERN_HISTORY_SIZE 8
static unsigned long access_pattern[PATTERN_HISTORY_SIZE];
static int pattern_index = 0;

static void update_access_pattern(unsigned long addr)
{
    unsigned long aligned = page_cache_align_to_semi_sync(addr);
    access_pattern[pattern_index] = aligned;
    pattern_index = (pattern_index + 1) % PATTERN_HISTORY_SIZE;
}

static unsigned long detect_stride_pattern(void)
{
    int prev, prev2;

    if (pattern_index < 2)
        return 0;

    prev = (pattern_index - 1 + PATTERN_HISTORY_SIZE) % PATTERN_HISTORY_SIZE;
    prev2 = (pattern_index - 2 + PATTERN_HISTORY_SIZE) % PATTERN_HISTORY_SIZE;

    if (access_pattern[prev] > access_pattern[prev2]) {
        return access_pattern[prev] - access_pattern[prev2];
    }
    return 0;
}

unsigned long page_cache_align_to_semi_sync(unsigned long addr)
{
    return addr & ~(SEMI_SYNC_UNIT_SIZE - 1);
}

static void cache_entry_free(struct semi_sync_cache_entry *entry)
{
    if (entry->data) {
        free(entry->data);
        cache_stats.current_memory -= entry->data_size;
    }
    xfree(entry);
}

static struct semi_sync_cache_entry *cache_lookup_internal(unsigned long vaddr_start)
{
    struct rb_node *node = cache_vaddr_root.rb_node;

    while (node) {
        struct semi_sync_cache_entry *entry = rb_entry(node, struct semi_sync_cache_entry, vaddr_node);

        if (vaddr_start < entry->vaddr_start)
            node = node->rb_left;
        else if (vaddr_start >= entry->vaddr_end)
            node = node->rb_right;
        else
            return entry;
    }

    return NULL;
}

static void cache_lru_update(struct semi_sync_cache_entry *entry)
{
    list_del(&entry->lru_list);
    list_add(&entry->lru_list, &cache_lru_list);
    entry->access_count++;
    clock_gettime(CLOCK_MONOTONIC, &entry->last_access);
}

static void cache_evict_lru(void)
{
    struct semi_sync_cache_entry *entry, *n;

    /* If MAX_CACHE_MEMORY is 0 (unlimited), never evict */
    if (MAX_CACHE_MEMORY == 0)
        return;

    list_for_each_entry_safe_reverse(entry, n, &cache_lru_list, lru_list) {
        if (cache_stats.current_memory <= MAX_CACHE_MEMORY * 0.9)
            break;

        pr_debug("Cache: Evicting LRU entry [0x%lx-0x%lx], accessed %lu times\n",
                entry->vaddr_start, entry->vaddr_end, entry->access_count);

        rb_erase(&entry->vaddr_node, &cache_vaddr_root);
        list_del(&entry->lru_list);
        cache_stats.evictions++;
        cache_entry_free(entry);
    }
}

static int cache_insert(struct semi_sync_cache_entry *new_entry)
{
    struct rb_node **link = &cache_vaddr_root.rb_node;
    struct rb_node *parent = NULL;

    while (*link) {
        struct semi_sync_cache_entry *entry;
        parent = *link;
        entry = rb_entry(parent, struct semi_sync_cache_entry, vaddr_node);

        if (new_entry->vaddr_start < entry->vaddr_start)
            link = &parent->rb_left;
        else if (new_entry->vaddr_start >= entry->vaddr_end)
            link = &parent->rb_right;
        else {
            pr_warn("Cache: Overlapping entry [0x%lx-0x%lx] already exists\n",
                   entry->vaddr_start, entry->vaddr_end);
            return -EEXIST;
        }
    }

    rb_link_node(&new_entry->vaddr_node, parent, link);
    rb_insert_color(&new_entry->vaddr_node, &cache_vaddr_root);
    list_add(&new_entry->lru_list, &cache_lru_list);

    return 0;
}

int page_cache_init(void)
{
    if (cache_initialized)
        return 0;

    cache_vaddr_root = RB_ROOT;
    INIT_LIST_HEAD(&cache_lru_list);
    memset(&cache_stats, 0, sizeof(cache_stats));
    memset(access_pattern, 0, sizeof(access_pattern));
    pattern_index = 0;

    cache_initialized = true;
    if (MAX_CACHE_UNITS == 0) {
        pr_info("Semi-sync aware page cache initialized (unit size: %d pages, unlimited cache)\n",
                SEMI_SYNC_UNIT_PAGES);
    } else {
        pr_info("Semi-sync aware page cache initialized (unit size: %d pages, max units: %d)\n",
                SEMI_SYNC_UNIT_PAGES, MAX_CACHE_UNITS);
    }

    return 0;
}

void page_cache_cleanup(void)
{
    struct rb_node *node;
    struct semi_sync_cache_entry *entry;

    pthread_mutex_lock(&cache_lock);

    while ((node = rb_first(&cache_vaddr_root)) != NULL) {
        entry = rb_entry(node, struct semi_sync_cache_entry, vaddr_node);
        rb_erase(node, &cache_vaddr_root);
        list_del(&entry->lru_list);
        cache_entry_free(entry);
    }

    cache_initialized = false;
    pthread_mutex_unlock(&cache_lock);

    pr_info("Page cache cleaned up. Final stats: lookups=%lu, hits=%lu (%.2f%%), S3 saves=%lu\n",
            cache_stats.total_lookups, cache_stats.full_hits,
            cache_stats.total_lookups ? (100.0 * cache_stats.full_hits / cache_stats.total_lookups) : 0,
            cache_stats.s3_fetches_saved);
}

enum cache_lookup_result page_cache_lookup_semi_sync(unsigned long vaddr_start,
                                                     unsigned long vaddr_end,
                                                     void **data_out)
{
    struct semi_sync_cache_entry *entry;
    enum cache_lookup_result result = CACHE_MISS;
    unsigned long aligned_start;

    if (!cache_initialized)
        return CACHE_MISS;

    aligned_start = page_cache_align_to_semi_sync(vaddr_start);

    pthread_mutex_lock(&cache_lock);

    cache_stats.total_lookups++;
    update_access_pattern(vaddr_start);

    entry = cache_lookup_internal(aligned_start);

    if (entry && entry->vaddr_start <= vaddr_start &&
        entry->vaddr_end >= vaddr_end && entry->is_complete) {

        /* Calculate offset within cached data for partial reads */
        unsigned long offset = vaddr_start - entry->vaddr_start;
        unsigned long requested_size = vaddr_end - vaddr_start;

        /* Safety checks to prevent memory access violations */
        if (!entry->data) {
            pr_err("Cache entry has NULL data pointer\n");
            result = CACHE_MISS;
        } else if (offset >= entry->data_size) {
            pr_err("Cache offset %lu exceeds data size %zu\n", offset, entry->data_size);
            result = CACHE_MISS;
        } else if (offset + requested_size > entry->data_size) {
            pr_err("Cache request exceeds data bounds: offset=%lu, req_size=%lu, data_size=%zu\n",
                   offset, requested_size, entry->data_size);
            result = CACHE_MISS;
        } else {
            *data_out = (char *)entry->data + offset;
            cache_lru_update(entry);
            cache_stats.full_hits++;
            cache_stats.s3_fetches_saved++;
            result = CACHE_FULL_HIT;

            pr_debug("Cache FULL HIT: Semi-sync unit [0x%lx-0x%lx] contains requested [0x%lx-0x%lx], saves S3 fetch\n",
                    entry->vaddr_start, entry->vaddr_end, vaddr_start, vaddr_end);
        }
    } else {
        cache_stats.misses++;
        pr_debug("Cache MISS: Semi-sync unit [0x%lx-0x%lx] not cached\n",
                aligned_start, vaddr_end);
    }

    pthread_mutex_unlock(&cache_lock);
    return result;
}

int page_cache_store_semi_sync(unsigned long vaddr_start, unsigned long vaddr_end,
                               unsigned long file_offset, void *data, size_t data_size)
{
    struct semi_sync_cache_entry *entry;
    int ret = 0;
    unsigned long aligned_start;

    if (!cache_initialized)
        return -EINVAL;

    aligned_start = page_cache_align_to_semi_sync(vaddr_start);

    pthread_mutex_lock(&cache_lock);

    entry = cache_lookup_internal(aligned_start);
    if (entry) {
        pr_debug("Cache: Semi-sync unit [0x%lx-0x%lx] already cached\n",
                aligned_start, vaddr_end);
        pthread_mutex_unlock(&cache_lock);
        return 0;
    }

    /* Only evict if we have a memory limit (MAX_CACHE_MEMORY > 0) */
    if (MAX_CACHE_MEMORY > 0 && cache_stats.current_memory + data_size > MAX_CACHE_MEMORY) {
        cache_evict_lru();
    }

    entry = xzalloc(sizeof(*entry));
    if (!entry) {
        ret = -ENOMEM;
        goto out;
    }

    entry->data = xmalloc(data_size);
    if (!entry->data) {
        xfree(entry);
        ret = -ENOMEM;
        goto out;
    }

    memcpy(entry->data, data, data_size);
    entry->vaddr_start = aligned_start;
    entry->vaddr_end = vaddr_end;
    entry->file_offset = file_offset;
    entry->data_size = data_size;
    entry->is_complete = true;
    entry->access_count = 0;
    clock_gettime(CLOCK_MONOTONIC, &entry->last_access);
    INIT_LIST_HEAD(&entry->lru_list);

    ret = cache_insert(entry);
    if (ret < 0) {
        cache_entry_free(entry);
        goto out;
    }

    cache_stats.current_memory += data_size;
    if (cache_stats.current_memory > cache_stats.peak_memory)
        cache_stats.peak_memory = cache_stats.current_memory;

    pr_debug("Cache: Stored semi-sync unit [0x%lx-0x%lx], %zu bytes, offset 0x%lx\n",
            aligned_start, vaddr_end, data_size, file_offset);

out:
    pthread_mutex_unlock(&cache_lock);
    return ret;
}

bool page_cache_should_prefetch_next(unsigned long vaddr_start)
{
    struct semi_sync_cache_entry *entry;
    unsigned long next_aligned;
    bool should_prefetch = true;  /* Default to true for aggressive prefetch */
    int i;
    int cached_count = 0;
    int max_lookahead = 5;

    if (!cache_initialized)
        return false;

    pthread_mutex_lock(&cache_lock);

    /* Check if we have enough units cached ahead */
    for (i = 1; i <= max_lookahead; i++) {
        next_aligned = page_cache_align_to_semi_sync(vaddr_start) + (i * SEMI_SYNC_UNIT_SIZE);
        entry = cache_lookup_internal(next_aligned);
        if (entry) {
            cached_count++;
        }
    }

    /* If we have less than 3 units cached ahead, trigger prefetch */
    if (cached_count < 3) {
        should_prefetch = true;
        cache_stats.prefetch_triggered++;
    } else {
        /* We have enough cached ahead */
        should_prefetch = false;
    }

    pthread_mutex_unlock(&cache_lock);

    return should_prefetch;
}

void page_cache_mark_access_pattern(unsigned long addr)
{
    pthread_mutex_lock(&cache_lock);
    update_access_pattern(addr);
    pthread_mutex_unlock(&cache_lock);
}

unsigned long page_cache_get_next_prefetch_target(unsigned long current_addr)
{
    unsigned long aligned = page_cache_align_to_semi_sync(current_addr);
    unsigned long next = aligned + SEMI_SYNC_UNIT_SIZE;
    unsigned long stride;

    /* Validate current address is reasonable */
    if (current_addr == 0 || current_addr > 0x800000000000UL) {
        pr_debug("Cache: Invalid address for prefetch target: 0x%lx\n", current_addr);
        return 0;
    }

    pthread_mutex_lock(&cache_lock);

    stride = detect_stride_pattern();
    if (stride >= SEMI_SYNC_UNIT_SIZE) {
        unsigned long pattern_next = aligned + stride;
        /* Validate pattern-detected address is reasonable */
        if (pattern_next > 0x800000000000UL) {
            pr_debug("Cache: Pattern detection produced invalid address: 0x%lx, using sequential\n", pattern_next);
        } else {
            next = pattern_next;
            pr_debug("Cache: Detected stride pattern, prefetch target: 0x%lx\n", next);
        }
    }

    pthread_mutex_unlock(&cache_lock);

    return next;
}

void page_cache_get_stats(struct semi_sync_cache_stats *stats)
{
    pthread_mutex_lock(&cache_lock);
    memcpy(stats, &cache_stats, sizeof(*stats));
    pthread_mutex_unlock(&cache_lock);
}

void page_cache_reset_stats(void)
{
    pthread_mutex_lock(&cache_lock);

    cache_stats.total_lookups = 0;
    cache_stats.full_hits = 0;
    cache_stats.misses = 0;
    cache_stats.prefetch_triggered = 0;
    cache_stats.prefetch_hits = 0;
    cache_stats.evictions = 0;
    cache_stats.s3_fetches_saved = 0;

    pthread_mutex_unlock(&cache_lock);
}