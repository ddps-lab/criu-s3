#ifndef __CR_OBJECT_STORAGE_H__
#define __CR_OBJECT_STORAGE_H__

#include "log.h"

/*
 * =============================================================================
 * Simulation-friendly structured logging macros
 *
 * These macros produce consistent log output that can be parsed by
 * criu_workload/tools/parse_criu_logs.py for simulation analysis.
 *
 * Log format follows CRIU standard: (timestamp) pid message
 * Extended format for simulation:
 *   objstor: <EVENT> key=<key> offset=<offset> len=<len> [dur_ms=<duration>]
 *   prefetch: <EVENT> iov_idx=<idx> [priority=<priority>] [status=<status>]
 * =============================================================================
 */

/* Object Storage fetch events */
#define OBJSTOR_FETCH_START_LOG(key, offset, len) \
	pr_info("objstor: FETCH_START key=%s offset=%lu len=%lu\n", \
		(key), (unsigned long)(offset), (unsigned long)(len))

#define OBJSTOR_FETCH_DONE_LOG(key, offset, len, dur_ms) \
	pr_info("objstor: FETCH_DONE key=%s offset=%lu len=%lu dur_ms=%.2f\n", \
		(key), (unsigned long)(offset), (unsigned long)(len), (double)(dur_ms))

#define OBJSTOR_FETCH_ERROR_LOG(key, offset, len, error_code) \
	pr_err("objstor: FETCH_ERROR key=%s offset=%lu len=%lu error=%d\n", \
	       (key), (unsigned long)(offset), (unsigned long)(len), (int)(error_code))

/* Object Storage session events (for Express One Zone) */
#define OBJSTOR_SESSION_CREATE_LOG() \
	pr_info("objstor: SESSION_CREATE\n")

#define OBJSTOR_SESSION_CREATED_LOG(expiration) \
	pr_info("objstor: SESSION_CREATED expires=%ld\n", (long)(expiration))

#define OBJSTOR_SESSION_ERROR_LOG(http_code) \
	pr_err("objstor: SESSION_ERROR http_code=%ld\n", (long)(http_code))

/* Prefetch queue events */
#define PREFETCH_QUEUE_LOG(iov_idx, iov_start, iov_end, priority) \
	pr_info("prefetch: QUEUE iov_idx=%d iov_start=0x%lx iov_end=0x%lx priority=%d\n", \
		(int)(iov_idx), (unsigned long)(iov_start), (unsigned long)(iov_end), (int)(priority))

#define PREFETCH_DEQUEUE_LOG(iov_idx, worker_id) \
	pr_info("prefetch: DEQUEUE iov_idx=%d worker=%d\n", \
		(int)(iov_idx), (int)(worker_id))

/* Prefetch worker events */
#define PREFETCH_WORKER_START_LOG(worker_id, iov_idx) \
	pr_info("prefetch: WORKER_START worker=%d iov_idx=%d\n", \
		(int)(worker_id), (int)(iov_idx))

#define PREFETCH_WORKER_DONE_LOG(worker_id, iov_idx, dur_ms) \
	pr_info("prefetch: WORKER_DONE worker=%d iov_idx=%d dur_ms=%.2f\n", \
		(int)(worker_id), (int)(iov_idx), (double)(dur_ms))

#define PREFETCH_WORKER_ERROR_LOG(worker_id, iov_idx, error_code) \
	pr_err("prefetch: WORKER_ERROR worker=%d iov_idx=%d error=%d\n", \
	       (int)(worker_id), (int)(iov_idx), (int)(error_code))

/* Cache events */
#define PREFETCH_CACHE_HIT_LOG(iov_idx) \
	pr_info("prefetch: CACHE_HIT iov_idx=%d\n", (int)(iov_idx))

#define PREFETCH_CACHE_MISS_LOG(iov_idx) \
	pr_info("prefetch: CACHE_MISS iov_idx=%d\n", (int)(iov_idx))

#define PREFETCH_CACHE_STORE_LOG(iov_idx, size_bytes) \
	pr_info("prefetch: CACHE_STORE iov_idx=%d size=%lu\n", \
		(int)(iov_idx), (unsigned long)(size_bytes))

/* Controller events */
#define PREFETCH_CONTROLLER_FAULT_LOG(iov_idx, pattern_type, confidence) \
	pr_info("prefetch: CONTROLLER_FAULT iov_idx=%d pattern=%d confidence=%.2f\n", \
		(int)(iov_idx), (int)(pattern_type), (double)(confidence))

#define PREFETCH_CONTROLLER_PROMOTE_LOG(iov_idx, old_priority, new_priority) \
	pr_info("prefetch: CONTROLLER_PROMOTE iov_idx=%d old_prio=%d new_prio=%d\n", \
		(int)(iov_idx), (int)(old_priority), (int)(new_priority))

#define PREFETCH_CONTROLLER_REMOVE_LOG(iov_idx, reason) \
	pr_info("prefetch: CONTROLLER_REMOVE iov_idx=%d reason=%s\n", \
		(int)(iov_idx), (reason))

/* Statistics events (emitted periodically or at cleanup) */
#define PREFETCH_STATS_LOG(total_requests, completed, failed, cache_hits, cache_misses) \
	pr_info("prefetch: STATS requests=%lu completed=%lu failed=%lu hits=%lu misses=%lu\n", \
		(unsigned long)(total_requests), (unsigned long)(completed), \
		(unsigned long)(failed), (unsigned long)(cache_hits), (unsigned long)(cache_misses))

/*
 * =============================================================================
 * Public API
 * =============================================================================
 */

/*
 * Initialize the object storage client
 * Returns 0 on success, -1 on failure
 */
int object_storage_init(void);

/*
 * Fetch a range of bytes from an object in object storage
 *
 * @param object_key: The key/path of the object in the bucket
 * @param offset: The starting byte offset to fetch
 * @param length: The number of bytes to fetch
 * @param buffer: Buffer to store the fetched data (must be at least 'length' bytes)
 *
 * Returns 0 on success, -1 on failure
 */
int object_storage_fetch_range(const char *object_key, unsigned long offset, unsigned long length, void *buffer);

/*
 * Upload an object to object storage (simple PUT, for files < 5GB)
 *
 * @param object_key: The key/path for the object in the bucket
 * @param data: Pointer to data to upload
 * @param length: Size of data in bytes
 *
 * Returns 0 on success, -1 on failure
 */
int object_storage_put_object(const char *object_key, const void *data, unsigned long length);

/*
 * Fetch an entire object from object storage (for metadata files with unknown size)
 *
 * @param object_key: The key/path of the object
 * @param out_data: Output pointer to allocated buffer (caller must free)
 * @param out_length: Output size of fetched data
 *
 * Returns 0 on success, -ENOENT if not found, -1 on other failure
 */
int object_storage_get_object(const char *object_key, void **out_data, unsigned long *out_length);

/*
 * Multipart upload API — for large files (pages-*.img, > 5MB)
 *
 * Usage:
 *   1. multipart_init()        → get upload_id
 *   2. multipart_upload_part() → repeat for each part (min 5MB except last)
 *   3. multipart_complete()    → finalize with etags
 *   On error: multipart_abort() to clean up
 */
int object_storage_multipart_init(const char *object_key, char *upload_id, size_t id_len);
int object_storage_multipart_upload_part(const char *object_key, const char *upload_id,
					 int part_num, const void *data, unsigned long length,
					 char *etag, size_t etag_len);
int object_storage_multipart_complete(const char *object_key, const char *upload_id,
				      int n_parts, const char **etags);
int object_storage_multipart_abort(const char *object_key, const char *upload_id);

/*
 * Clean up the object storage client and release resources
 */
void object_storage_cleanup(void);

/*
 * Special function to clean up curl resources after prepare_mappings
 * and prepare for lazy-pages mode
 *
 * Returns 0 on success, -1 on failure
 */
int object_storage_cleanup_and_prepare_for_lazy_pages(void);

#endif /* __CR_OBJECT_STORAGE_H__ */