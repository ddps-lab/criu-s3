#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/uio.h>

#include "int.h"
#include "prefetch.h"
#include "page-cache.h"
#include "log.h"
#include "xmalloc.h"
#include "page.h"
#include "page-xfer.h"
#include "pagemap.h"
#include "protobuf.h"
#include "object-storage.h"
#include "cr_options.h"
#include "uffd.h"

#define MAX_PREFETCH_QUEUE 64

static struct {
    struct list_head queue;
    struct list_head processing; /* Requests currently being processed */
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_cond;
    pthread_t *workers;
    int num_workers;
    bool initialized;
    bool shutdown;
    struct prefetch_stats stats;
    unsigned long sequential_frontier;
    bool sequential_active;
    void *current_lpi;
} prefetch_state = {
    .queue = LIST_HEAD_INIT(prefetch_state.queue),
    .processing = LIST_HEAD_INIT(prefetch_state.processing),
    .queue_lock = PTHREAD_MUTEX_INITIALIZER,
    .queue_cond = PTHREAD_COND_INITIALIZER,
    .initialized = false,
    .shutdown = false,
    .sequential_frontier = 0,
    .sequential_active = false,
    .current_lpi = NULL
};

extern struct page_read *lpi_get_page_read(void *lpi);
extern void lpi_lock_pr(void *lpi);
extern void lpi_unlock_pr(void *lpi);
extern bool lpi_unit_has_iov(void *lpi_ptr, unsigned long unit_start, unsigned long unit_end);
extern int lpi_get_first_iov_in_unit(void *lpi_ptr, unsigned long unit_start,
                                     unsigned long unit_end, unsigned long *offset_out);

/* resolve_file_offset no longer needed - using optimized unit checks instead */

static bool request_exists_or_processing(unsigned long vaddr_start)
{
    struct prefetch_request *req;

    /* Check if already in queue */
    list_for_each_entry(req, &prefetch_state.queue, list) {
        if (req->semi_sync_start == vaddr_start)
            return true;
    }

    /* Check if currently being processed */
    list_for_each_entry(req, &prefetch_state.processing, list) {
        if (req->semi_sync_start == vaddr_start)
            return true;
    }

    return false;
}

static int perform_prefetch(struct prefetch_request *req)
{
    void *data;
    size_t data_size;
    int ret;
    unsigned long nr_pages;
    char object_key[256];

    nr_pages = (req->semi_sync_end - req->semi_sync_start) / PAGE_SIZE;
    data_size = nr_pages * PAGE_SIZE;

    data = xmalloc(data_size);
    if (!data) {
        pr_err("Prefetch: Failed to allocate %zu bytes for data\n", data_size);
        return -ENOMEM;
    }

    /* Construct object key - typically "pages-1.img" or similar */
    snprintf(object_key, sizeof(object_key), "pages-1.img");

    /* Use direct object storage fetch to avoid page_read conflicts */
    ret = object_storage_fetch_range(object_key, req->file_offset, data_size, data);
    if (ret < 0) {
        pr_err("Prefetch: Failed to fetch from S3 for [0x%lx-0x%lx], offset 0x%lx\n",
               req->semi_sync_start, req->semi_sync_end, req->file_offset);
        xfree(data);
        return ret;
    }

    pr_debug("Prefetch: Fetched %lu pages (%zu bytes) from S3 for [0x%lx-0x%lx]\n",
            nr_pages, data_size, req->semi_sync_start, req->semi_sync_end);

    /* Store in cache for future page faults */
    ret = page_cache_store_semi_sync(req->semi_sync_start, req->semi_sync_end,
                                     req->file_offset, data, data_size);

    xfree(data);

    if (ret == 0) {
        prefetch_state.stats.cache_stored++;
        prefetch_state.stats.bytes_prefetched += data_size;
        pr_info("Prefetch: Cached semi-sync unit [0x%lx-0x%lx], type=%d\n",
               req->semi_sync_start, req->semi_sync_end, req->type);
    }

    return ret;
}

static void *prefetch_worker(void *arg)
{
    struct prefetch_request *req;
    int worker_id = (int)(long)arg;

    pr_info("Prefetch worker %d started\n", worker_id);

    while (1) {
        pthread_mutex_lock(&prefetch_state.queue_lock);

        while (list_empty(&prefetch_state.queue) && !prefetch_state.shutdown) {
            pthread_cond_wait(&prefetch_state.queue_cond, &prefetch_state.queue_lock);
        }

        if (prefetch_state.shutdown) {
            pthread_mutex_unlock(&prefetch_state.queue_lock);
            break;
        }

        req = list_first_entry(&prefetch_state.queue, struct prefetch_request, list);
        list_del(&req->list);
        /* Move to processing list */
        list_add(&req->list, &prefetch_state.processing);

        pthread_mutex_unlock(&prefetch_state.queue_lock);

        pr_debug("Worker %d: Processing prefetch for [0x%lx-0x%lx]\n",
                worker_id, req->semi_sync_start, req->semi_sync_end);

        if (perform_prefetch(req) == 0) {
            prefetch_state.stats.completed++;

            switch (req->type) {
            case PREFETCH_AHEAD_OF_FAULT:
                prefetch_state.stats.ahead_of_fault_count++;
                break;
            case PREFETCH_SEQUENTIAL:
                prefetch_state.stats.sequential_count++;
                prefetch_state.sequential_frontier = req->semi_sync_end;
                break;
            case PREFETCH_PATTERN_BASED:
                prefetch_state.stats.pattern_based_count++;
                break;
            }
        } else {
            prefetch_state.stats.failed++;
        }

        /* Remove from processing list */
        pthread_mutex_lock(&prefetch_state.queue_lock);
        list_del(&req->list);
        pthread_mutex_unlock(&prefetch_state.queue_lock);

        xfree(req);
    }

    pr_info("Prefetch worker %d exiting\n", worker_id);
    return NULL;
}

int prefetch_init(void)
{
    int i;

    if (prefetch_state.initialized)
        return 0;

    prefetch_state.num_workers = opts.prefetch_workers;
    if (prefetch_state.num_workers <= 0)
        prefetch_state.num_workers = 4;  /* Default if not set */

    prefetch_state.workers = xmalloc(sizeof(pthread_t) * prefetch_state.num_workers);
    if (!prefetch_state.workers) {
        pr_err("Failed to allocate worker threads array\n");
        return -1;
    }

    INIT_LIST_HEAD(&prefetch_state.queue);
    INIT_LIST_HEAD(&prefetch_state.processing);
    memset(&prefetch_state.stats, 0, sizeof(prefetch_state.stats));
    prefetch_state.shutdown = false;
    prefetch_state.sequential_frontier = 0;

    for (i = 0; i < prefetch_state.num_workers; i++) {
        if (pthread_create(&prefetch_state.workers[i], NULL, prefetch_worker, (void *)(long)i) != 0) {
            pr_err("Failed to create prefetch worker %d\n", i);
            prefetch_state.shutdown = true;
            pthread_cond_broadcast(&prefetch_state.queue_cond);
            for (int j = 0; j < i; j++) {
                pthread_join(prefetch_state.workers[j], NULL);
            }
            xfree(prefetch_state.workers);
            return -1;
        }
    }

    prefetch_state.initialized = true;
    pr_info("Semi-sync aware prefetch initialized with %d workers\n", prefetch_state.num_workers);

    return 0;
}

void prefetch_cleanup(void)
{
    struct prefetch_request *req, *tmp;
    int i;

    if (!prefetch_state.initialized)
        return;

    pthread_mutex_lock(&prefetch_state.queue_lock);
    prefetch_state.shutdown = true;
    pthread_cond_broadcast(&prefetch_state.queue_cond);
    pthread_mutex_unlock(&prefetch_state.queue_lock);

    for (i = 0; i < prefetch_state.num_workers; i++) {
        pthread_join(prefetch_state.workers[i], NULL);
    }

    list_for_each_entry_safe(req, tmp, &prefetch_state.queue, list) {
        list_del(&req->list);
        xfree(req);
    }

    /* Clean up any requests still being processed */
    list_for_each_entry_safe(req, tmp, &prefetch_state.processing, list) {
        list_del(&req->list);
        xfree(req);
    }

    xfree(prefetch_state.workers);
    prefetch_state.workers = NULL;
    prefetch_state.initialized = false;

    pr_info("Prefetch cleaned up. Stats: total=%lu, completed=%lu, failed=%lu, cached=%lu MB\n",
            prefetch_state.stats.total_requests, prefetch_state.stats.completed,
            prefetch_state.stats.failed, prefetch_state.stats.bytes_prefetched / (1024 * 1024));
}

int prefetch_queue_semi_sync_unit(unsigned long vaddr_start, unsigned long file_offset,
                                  void *lpi, enum prefetch_type type)
{
    struct prefetch_request *req;
    unsigned long aligned_start;
    int queue_size = 0;

    if (!prefetch_state.initialized)
        return -EINVAL;

    aligned_start = page_cache_align_to_semi_sync(vaddr_start);

    pthread_mutex_lock(&prefetch_state.queue_lock);

    if (request_exists_or_processing(aligned_start)) {
        pthread_mutex_unlock(&prefetch_state.queue_lock);
        pr_debug("Prefetch: Semi-sync unit at 0x%lx already queued or processing\n", aligned_start);
        return -EEXIST;
    }

    list_for_each_entry(req, &prefetch_state.queue, list) {
        queue_size++;
    }

    if (queue_size >= MAX_PREFETCH_QUEUE) {
        pthread_mutex_unlock(&prefetch_state.queue_lock);
        pr_debug("Prefetch queue full (%d items)\n", queue_size);
        return -EBUSY;
    }

    req = xzalloc(sizeof(*req));
    if (!req) {
        pthread_mutex_unlock(&prefetch_state.queue_lock);
        return -ENOMEM;
    }

    req->semi_sync_start = aligned_start;
    req->semi_sync_end = aligned_start + SEMI_SYNC_UNIT_SIZE;
    req->file_offset = file_offset;
    req->type = type;
    req->lpi = lpi;
    req->priority = (type == PREFETCH_AHEAD_OF_FAULT) ? 1 : 0;
    INIT_LIST_HEAD(&req->list);

    if (req->priority > 0) {
        list_add(&req->list, &prefetch_state.queue);
    } else {
        list_add_tail(&req->list, &prefetch_state.queue);
    }

    prefetch_state.stats.total_requests++;
    pthread_cond_signal(&prefetch_state.queue_cond);
    pthread_mutex_unlock(&prefetch_state.queue_lock);

    pr_debug("Prefetch: Queued semi-sync unit [0x%lx-0x%lx], type=%d, priority=%d\n",
            aligned_start, req->semi_sync_end, type, req->priority);

    return 0;
}

int prefetch_ahead_of_fault(unsigned long current_fault_addr, void *lpi)
{
    unsigned long next_unit_start;
    unsigned long file_offset;
    int ret;
    int units_queued = 0;
    int max_units = 8;  /* Prefetch up to 8 units ahead (32MB) */
    int i;
    void *dummy;
    /* search_addr and search_step no longer needed with optimized unit check */ /* Check every 16 pages for efficiency */

    if (!page_cache_should_prefetch_next(current_fault_addr))
        return 0;

    /* Try to prefetch multiple units ahead */
    for (i = 0; i < max_units; i++) {
        if (i == 0) {
            next_unit_start = page_cache_get_next_prefetch_target(current_fault_addr);
        } else {
            /* Sequential units after the first */
            next_unit_start = page_cache_align_to_semi_sync(current_fault_addr) +
                           ((i + 1) * SEMI_SYNC_UNIT_SIZE);
        }

        if (next_unit_start == 0) {
            pr_debug("Prefetch: Invalid target address for unit %d, stopping\n", i);
            break;
        }

        /* Check if already cached or queued */
        if (page_cache_lookup_semi_sync(next_unit_start,
                                        next_unit_start + SEMI_SYNC_UNIT_SIZE,
                                        &dummy) == CACHE_FULL_HIT) {
            pr_debug("Prefetch: Unit %d at 0x%lx already cached, skipping\n", i, next_unit_start);
            continue;
        }

        /* Optimized: Check if unit has any IOV first (single pass) */
        if (!lpi_unit_has_iov(lpi, next_unit_start, next_unit_start + SEMI_SYNC_UNIT_SIZE)) {
            /* Entire unit is sparse/non-lazy, skip silently */
            prefetch_state.stats.pattern_sparse_skips++;
            pr_debug("Prefetch: Entire unit at 0x%lx is sparse/non-lazy (optimized check), skipping\n",
                    next_unit_start);
            /* Only stop if this is the first unit and it's entirely sparse */
            if (i == 0) return 0;
            continue; /* Try next unit */
        }

        /* Unit has IOV, get the first IOV's file offset */
        ret = lpi_get_first_iov_in_unit(lpi, next_unit_start,
                                        next_unit_start + SEMI_SYNC_UNIT_SIZE,
                                        &file_offset);
        if (ret < 0) {
            pr_debug("Prefetch: Failed to get IOV offset for unit %d at 0x%lx (error %d)\n",
                    i, next_unit_start, ret);
            break;
        }

        ret = prefetch_queue_semi_sync_unit(next_unit_start, file_offset, lpi,
                                           PREFETCH_AHEAD_OF_FAULT);
        if (ret == 0) {
            units_queued++;
            pr_debug("Prefetch: Queued unit %d at 0x%lx (offset 0x%lx)\n",
                    i, next_unit_start, file_offset);
        } else if (ret == -EEXIST) {
            /* Already queued, that's fine */
            pr_debug("Prefetch: Unit %d at 0x%lx already queued\n", i, next_unit_start);
        } else if (ret == -EBUSY) {
            /* Queue full, stop trying */
            pr_debug("Prefetch: Queue full after %d units\n", units_queued);
            break;
        }
    }

    if (units_queued > 0) {
        pr_info("Prefetch: Queued %d units ahead of fault at 0x%lx\n",
                units_queued, current_fault_addr);
    }

    return units_queued > 0 ? 0 : -1;
}

void prefetch_start_sequential(void *lpi)
{
    unsigned long start_addr;
    unsigned long file_offset;
    int ret;
    /* search_addr and search_step no longer needed with optimized unit check */
    int i;

    pthread_mutex_lock(&prefetch_state.queue_lock);
    prefetch_state.sequential_active = true;
    prefetch_state.current_lpi = lpi;

    if (prefetch_state.sequential_frontier == 0) {
        /* Get the first IOV's address from lazy-pages info */
        /* We need to use extern functions to access lpi internals */
        prefetch_state.sequential_frontier = 0x22000000; /* Start from process heap area */
    }

    start_addr = prefetch_state.sequential_frontier;
    pthread_mutex_unlock(&prefetch_state.queue_lock);

    pr_info("Sequential prefetch started from 0x%lx\n", start_addr);

    /* Queue initial sequential prefetch requests - more aggressive */
    for (i = 0; i < 16; i++) {
        unsigned long unit_start = start_addr + (i * SEMI_SYNC_UNIT_SIZE);

        /* Optimized: Check if unit has any IOV first (single pass) */
        if (!lpi_unit_has_iov(lpi, unit_start, unit_start + SEMI_SYNC_UNIT_SIZE)) {
            /* Entire unit is sparse, skip silently */
            pr_debug("Sequential: Unit at 0x%lx is entirely sparse (optimized check), skipping\n", unit_start);
            continue;
        }

        /* Unit has IOV, get the first IOV's file offset */
        ret = lpi_get_first_iov_in_unit(lpi, unit_start,
                                        unit_start + SEMI_SYNC_UNIT_SIZE,
                                        &file_offset);
        if (ret == 0) {
            prefetch_queue_semi_sync_unit(unit_start, file_offset, lpi, PREFETCH_SEQUENTIAL);
        } else {
            /* Log actual errors */
            pr_debug("Sequential prefetch: Failed to get IOV offset for 0x%lx (error %d)\n",
                    unit_start, ret);
        }
    }
}

void prefetch_stop_sequential(void)
{
    pthread_mutex_lock(&prefetch_state.queue_lock);
    prefetch_state.sequential_active = false;
    prefetch_state.current_lpi = NULL;
    pthread_mutex_unlock(&prefetch_state.queue_lock);

    pr_info("Sequential prefetch stopped\n");
}

bool prefetch_is_active(void)
{
    bool active;
    pthread_mutex_lock(&prefetch_state.queue_lock);
    active = !list_empty(&prefetch_state.queue);
    pthread_mutex_unlock(&prefetch_state.queue_lock);
    return active;
}

int prefetch_get_queue_size(void)
{
    struct prefetch_request *req;
    int size = 0;

    pthread_mutex_lock(&prefetch_state.queue_lock);
    list_for_each_entry(req, &prefetch_state.queue, list) {
        size++;
    }
    pthread_mutex_unlock(&prefetch_state.queue_lock);

    return size;
}

void prefetch_get_stats(struct prefetch_stats *stats)
{
    pthread_mutex_lock(&prefetch_state.queue_lock);
    memcpy(stats, &prefetch_state.stats, sizeof(*stats));
    pthread_mutex_unlock(&prefetch_state.queue_lock);
}

void prefetch_reset_stats(void)
{
    pthread_mutex_lock(&prefetch_state.queue_lock);
    memset(&prefetch_state.stats, 0, sizeof(prefetch_state.stats));
    pthread_mutex_unlock(&prefetch_state.queue_lock);
}