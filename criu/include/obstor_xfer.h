#ifndef __CR_OBSTOR_XFER_H__
#define __CR_OBSTOR_XFER_H__

#include <stdbool.h>

/*
 * Object-storage parallel xfer path.
 *
 * Sister to uffd.c's xfer_pages() — when the checkpoint lives on S3-style
 * object storage, the main-loop sequential xfer_pages() would be too slow
 * (blocking libcurl fetches at ~80ms/chunk). This module spawns a pool of
 * worker threads that fetch IOVs in parallel and install them directly via
 * UFFDIO_COPY (criu/uffd.c:uffd_copy_from_buf). The main-loop xfer_pages()
 * then merely reaps IOVs the workers have marked IOV_RESTORED.
 *
 * Function names still carry the legacy "prefetch_" prefix from when this
 * was a cache-warmer sidecar; a follow-up cleanup PR will rename them.
 */

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
	unsigned long ahead_count;
	unsigned long bytes_prefetched;

	/* Phase 6 batch coalescing stats */
	unsigned long batches_issued;        /* number of multi-IOV S3 GETs */
	unsigned long batched_iovs;          /* IOVs covered by batched GETs */
	unsigned long batched_bytes;         /* total bytes pulled by batched GETs */
	unsigned long batch_partial_failures;/* IOVs in a batch that failed install */

	/* Phase 6.1a fault-path bounded wait stats */
	unsigned long fault_wait_attempted;   /* fault saw IOV_FETCHING, entered wait */
	unsigned long fault_wait_absorbed;    /* worker completed inside wait (win) */
	unsigned long fault_wait_timed_out;   /* fell through to sync fetch */
	unsigned long fault_wait_not_fetching;/* meta wasn't IOV_FETCHING (EAGAIN) */
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

/*
 * Install pages directly into the target process address space via
 * UFFDIO_COPY. Called by object-storage workers after fetching an IOV.
 * Defined in uffd.c where struct lazy_pages_info is visible.
 *
 * lpi_ptr: opaque struct lazy_pages_info * cast from req->lpi
 * addr:    destination virtual address in the restored process
 * nr:      IN: number of pages to install, OUT: number actually installed
 * buf:     source buffer (worker-owned)
 *
 * Returns 0 on success (possibly partial — check *nr == input), negative on error.
 */
int obstor_xfer_install_pages(void *lpi_ptr, unsigned long addr, int *nr, void *buf);

/*
 * IOV state queries for the main lazy-pages loop. Thread-safe.
 * Used by xfer_pages() to reap RESTORED IOVs and skip PENDING ones, and by
 * handle_page_fault() to detect worker races (fault on already-restored).
 */
bool obstor_xfer_iov_is_restored(unsigned long iov_start);
bool obstor_xfer_iov_is_pending(unsigned long iov_start);  /* QUEUED or FETCHING */

/*
 * Bounded wait for a worker to finish installing the IOV.
 * Only waits while meta state is IOV_FETCHING. Returns:
 *   0          — installed; caller should drop the iov from the list
 *   -EAGAIN    — meta not in IOV_FETCHING (caller takes its own path)
 *   -ENOENT    — no meta for iov_start
 *   -ETIMEDOUT — timeout elapsed while still IOV_FETCHING
 */
int obstor_xfer_iov_wait_restored(unsigned long iov_start, unsigned long timeout_ms);

/* Record the outcome of a bounded wait into prefetch_stats. */
void obstor_xfer_account_fault_wait(int wait_rc);

/*
 * Timeout for the fault-path bounded wait. Sized to roughly one typical
 * S3 range GET (~70ms for a 4MB IOV on us-west-2 standard S3); a stuck
 * worker can never block a fault longer than this. Can be promoted to
 * a CLI flag if measurement ever shows per-workload tuning matters.
 */
#define OBSTOR_FAULT_WAIT_MS 100UL

/* Get idle worker count */

#endif /* __CR_OBSTOR_XFER_H__ */
