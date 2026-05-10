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
#define OBJSTOR_FETCH_START_LOG(key, offset, len, source) \
	pr_info("objstor: FETCH_START key=%s offset=%lu len=%lu src=%s\n", \
		(key), (unsigned long)(offset), (unsigned long)(len), (source))

/*
 * NOTE: x_cache and x_amz_cf_pop may be empty strings when the response did
 * not include the corresponding headers (e.g., direct S3 origin). Always
 * NUL-terminated by header_callback so it's safe to %s them here. `source`
 * is one of OBJSTOR_SRC_FAULT / OBJSTOR_SRC_PREFETCH so analysis tooling
 * can attribute hits to fault-path vs prefetch-path call sites.
 */
#define OBJSTOR_FETCH_DONE_LOG(key, offset, len, dur_ms, x_cache, x_pop, source) \
	pr_info("objstor: FETCH_DONE key=%s offset=%lu len=%lu dur_ms=%.2f x_cache=\"%s\" x_pop=\"%s\" src=%s\n", \
		(key), (unsigned long)(offset), (unsigned long)(len), (double)(dur_ms), \
		(x_cache), (x_pop), (source))

#define OBJSTOR_FETCH_ERROR_LOG(key, offset, len, error_code, source) \
	pr_err("objstor: FETCH_ERROR key=%s offset=%lu len=%lu error=%d src=%s\n", \
	       (key), (unsigned long)(offset), (unsigned long)(len), (int)(error_code), (source))

/* Object Storage session events (for Express One Zone) */
#define OBJSTOR_SESSION_CREATE_LOG() \
	pr_info("objstor: SESSION_CREATE\n")

#define OBJSTOR_SESSION_CREATED_LOG(expiration) \
	pr_info("objstor: SESSION_CREATED expires=%ld\n", (long)(expiration))

#define OBJSTOR_SESSION_ERROR_LOG(http_code) \
	pr_err("objstor: SESSION_ERROR http_code=%ld\n", (long)(http_code))

/* Prefetch queue events */
#define PREFETCH_QUEUE_LOG(iov_idx, iov_start, iov_end, priority) \
	pr_info(" QUEUE iov_idx=%d iov_start=0x%lx iov_end=0x%lx priority=%d\n", \
		(int)(iov_idx), (unsigned long)(iov_start), (unsigned long)(iov_end), (int)(priority))

#define PREFETCH_DEQUEUE_LOG(iov_idx, worker_id) \
	pr_info(" DEQUEUE iov_idx=%d worker=%d\n", \
		(int)(iov_idx), (int)(worker_id))

/* Prefetch worker events */
#define PREFETCH_WORKER_START_LOG(worker_id, iov_idx) \
	pr_info(" WORKER_START worker=%d iov_idx=%d\n", \
		(int)(worker_id), (int)(iov_idx))

#define PREFETCH_WORKER_DONE_LOG(worker_id, iov_idx, dur_ms) \
	pr_info(" WORKER_DONE worker=%d iov_idx=%d dur_ms=%.2f\n", \
		(int)(worker_id), (int)(iov_idx), (double)(dur_ms))

#define PREFETCH_WORKER_ERROR_LOG(worker_id, iov_idx, error_code) \
	pr_err(" WORKER_ERROR worker=%d iov_idx=%d error=%d\n", \
	       (int)(worker_id), (int)(iov_idx), (int)(error_code))

/* Cache events */
#define PREFETCH_CACHE_HIT_LOG(iov_idx) \
	pr_info(" CACHE_HIT iov_idx=%d\n", (int)(iov_idx))

#define PREFETCH_CACHE_MISS_LOG(iov_idx) \
	pr_info(" CACHE_MISS iov_idx=%d\n", (int)(iov_idx))

#define PREFETCH_CACHE_STORE_LOG(iov_idx, size_bytes) \
	pr_info(" CACHE_STORE iov_idx=%d size=%lu\n", \
		(int)(iov_idx), (unsigned long)(size_bytes))

/* Controller events */
#define PREFETCH_CONTROLLER_FAULT_LOG(iov_idx) \
	pr_info(" FAULT iov_idx=%d\n", (int)(iov_idx))

#define PREFETCH_CONTROLLER_PROMOTE_LOG(iov_idx, old_priority, new_priority) \
	pr_info(" PROMOTE iov_idx=%d old_prio=%d new_prio=%d\n", \
		(int)(iov_idx), (int)(old_priority), (int)(new_priority))

#define PREFETCH_CONTROLLER_REMOVE_LOG(iov_idx, reason) \
	pr_info(" REMOVE iov_idx=%d reason=%s\n", \
		(int)(iov_idx), (reason))


/* Lazy restore page fault events (uffd.c) */
#define LAZY_FAULT_LOG(pid, addr, iov_start, iov_end, nr_pages) \
	pr_info(" FAULT pid=%d addr=0x%lx iov=[0x%lx-0x%lx] pages=%d\n", \
		(int)(pid), (unsigned long)(addr), (unsigned long)(iov_start), \
		(unsigned long)(iov_end), (int)(nr_pages))

#define LAZY_SERVED_CACHE_LOG(pid, addr, nr_pages) \
	pr_info(" SERVED_CACHE pid=%d addr=0x%lx pages=%d\n", \
		(int)(pid), (unsigned long)(addr), (int)(nr_pages))

#define LAZY_SERVED_S3_LOG(pid, addr, nr_pages, dur_ms) \
	pr_info(" SERVED_S3 pid=%d addr=0x%lx pages=%d dur_ms=%.2f\n", \
		(int)(pid), (unsigned long)(addr), (int)(nr_pages), (double)(dur_ms))

#define LAZY_SERVED_ZERO_LOG(pid, addr) \
	pr_info(" SERVED_ZERO pid=%d addr=0x%lx\n", \
		(int)(pid), (unsigned long)(addr))

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
 * Source of a fetch_range call.  Used to tag the FETCH_START / FETCH_DONE
 * log lines so post-restore analysis can separate fault-driven fetches from
 * prefetch worker fetches when computing per-source CDN cache hit ratios.
 */
#define OBJSTOR_SRC_FAULT    "fault"
#define OBJSTOR_SRC_PREFETCH "prefetch"

/*
 * Fetch a range of bytes from an object in object storage
 *
 * @param object_key: The key/path of the object in the bucket
 * @param offset: The starting byte offset to fetch
 * @param length: The number of bytes to fetch
 * @param buffer: Buffer to store the fetched data (must be at least 'length' bytes)
 * @param source: One of OBJSTOR_SRC_FAULT or OBJSTOR_SRC_PREFETCH (only
 *                used by the FETCH_* log macros, not stored anywhere)
 *
 * Returns 0 on success, -1 on failure
 */
int object_storage_fetch_range(const char *object_key, unsigned long offset, unsigned long length, void *buffer,
			       const char *source);
/*
 * Tolerant variant: returns 0 on success (any byte count, including 0
 * and short reads past EOF) and stores the number of bytes actually
 * read in *out_got. Used by the compression probe path and by the
 * seekable decoder's lazy read callback.
 */
int object_storage_fetch_range_short(const char *object_key, unsigned long offset,
				     unsigned long length, void *buffer,
				     unsigned long *out_got, const char *source);

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
 * Async variant of put_object. Enqueues the upload to a small worker
 * pool and returns immediately. Takes ownership of `data` (worker frees
 * after the PUT completes), and copies the key.
 *
 * Saves cumulative dump-time round trips when many small image files
 * are written back-to-back: ~30 × ~150 ms cross-region (sequential)
 * collapses to (30 / N_workers) × 150 ms.
 *
 * Callers MUST invoke object_storage_drain_uploads() before relying on
 * any uploaded bytes being visible on S3 (e.g., before write_manifest).
 *
 * Returns 0 on success (item enqueued), -1 on enqueue failure (caller
 * must free `data`).
 */
int object_storage_put_object_async(const char *object_key, void *data,
				    unsigned long length);

/*
 * Block until every queued async PUT has returned (or failed). Idempotent.
 * Cheap when nothing is in flight.
 */
void object_storage_drain_uploads(void);

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
 * HEAD an object: one round-trip to get Content-Length without the body.
 *
 * Used by restore-side compression detection to discover the compressed
 * pages-*.img size in a single request instead of an O(log N) geometric
 * Range-GET probe.
 *
 * Returns 0 on success, -ENOENT if not found, -1 on other failure.
 */
int object_storage_head_object(const char *object_key, unsigned long *out_length);

/*
 * Fetch the trailing tail of an object using HTTP "Range: bytes=-N"
 * (negative range). One round trip returns both:
 *   - up to max_tail bytes from the end of the object (in `buffer`),
 *   - the object's total length parsed from Content-Range,
 * which together replace the historical HEAD + multiple Range GET probe
 * sequence used by compressed-image init. Saves 3 RTTs per pages-*.img
 * on cross-region restores.
 *
 * On success: stores the actual byte count in *out_got (<= max_tail) and
 * the object's full size in *out_total_size. If the object is smaller
 * than max_tail, the entire object is returned and *out_got equals
 * *out_total_size.
 *
 * Returns 0 on success, -ENOENT if not found, -1 on other failure.
 */
int object_storage_fetch_tail(const char *object_key, unsigned long max_tail,
			      void *buffer, unsigned long *out_got,
			      unsigned long *out_total_size, const char *source);

/*
 * Enumerate object keys under a prefix using S3 ListObjectsV2.
 * Handles pagination; returned keys are all under the given prefix.
 *
 * On success: *out_keys is an xmalloc'd array of xstrdup'd key strings,
 * *out_sizes (if non-NULL) is a parallel realloc'd array of byte sizes from
 * the LIST <Size> field, *out_n is the count. Caller must xfree each key
 * and free() both arrays. Pass out_sizes=NULL if sizes are not needed.
 *
 * Returns 0 on success, -1 on failure.
 */
int object_storage_list_objects(const char *key_prefix, char ***out_keys,
				unsigned long **out_sizes, size_t *out_n);

/*
 * Manifest helpers — replace the post-dump LIST round-trip on restore.
 *
 * Format (manifest_v1, plain text, "\n" line endings):
 *   manifest_v1
 *   <key_relative_to_prefix>\t<size_bytes>
 *   ...
 *
 * Written by the dumper at the end of a successful object-storage dump
 * to <prefix>/manifest.txt, then read by the restore-side prefetch
 * before issuing any LIST. If the GET 404s the restore falls back to
 * the legacy LIST path, so old dumps remain restorable.
 */
int object_storage_write_manifest(void);

/*
 * On success: *out_keys is xmalloc'd array of xstrdup'd full keys (with
 * caller's prefix prepended, matching object_storage_list_objects), and
 * *out_sizes is realloc'd parallel array of byte sizes; *out_n is the
 * count. Returns 0 on success, -ENOENT if no manifest at <prefix>/manifest.txt,
 * -1 on parse / network failure.
 */
int object_storage_read_manifest(const char *key_prefix, char ***out_keys,
				 unsigned long **out_sizes, size_t *out_n);

/*
 * Metadata bundle — collapse 30-ish small metadata file GETs at restore
 * into one. Format (bundle_v1, plain text header + raw bodies):
 *   "OBSTOR_BUNDLE_v1\n"
 *   per entry:  "<key>\t<size>\n" then <size> bytes of body
 *   ...
 *
 * Bundle accumulation happens in object_storage_put_object: every small
 * (<1 MB) PUT is mirrored into an in-memory list in addition to its
 * normal upload. object_storage_write_metadata_bundle() then PUTs the
 * concatenated bundle as <prefix>/metadata.tar at end of dump.
 *
 * Restore side: object_storage_read_metadata_bundle() fetches the bundle
 * and yields the parallel (key, data) view. -ENOENT when no bundle
 * exists; restore falls back to per-key fetch.
 */
int object_storage_write_metadata_bundle(void);

struct objstor_bundle_entry {
	char *key;
	void *data;
	unsigned long length;
};

/*
 * On success: *out_entries is malloc'd array of objstor_bundle_entry
 * (caller frees each .key, .data, then the array itself); *out_n is the
 * count. Keys are stored relative to the prefix (no prefix prepended).
 */
int object_storage_read_metadata_bundle(struct objstor_bundle_entry **out_entries,
					size_t *out_n);

/*
 * Re-initialize the object-storage client after a fork (e.g. the lazy-pages
 * daemon child inheriting its parent's curl state). Single-threaded; must
 * be called before any worker thread starts issuing GETs. Fixes a
 * serialization pathology where N worker threads racing into libcurl /
 * OpenSSL lazy-init post-fork each take hundreds of ms for a small GET.
 */
int object_storage_reinit_after_fork(void);

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