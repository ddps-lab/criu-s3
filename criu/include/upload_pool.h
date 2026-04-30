/*
 * upload_pool.h — async S3 multipart upload via libcurl multi-handle.
 *
 * Design: avoid the pthread + libcurl + parasite-RPC interaction that broke
 * the parallel upload_worker path before. We keep all curl activity on a
 * single thread (the dump thread), using CURLM to drive up to N concurrent
 * PUT uploads via non-blocking I/O.
 *
 * Memory footprint: at most max_in_flight × 8 MB part buffers simultaneously
 * alive. Dump thread blocks on submit() only when that ceiling is hit,
 * giving natural back-pressure.
 *
 * Lifecycle:
 *   pool = upload_pool_create(key, upload_id, N)
 *   for each part: upload_pool_submit(pool, part_num, data, len)  // takes ownership of data
 *   etag_array = upload_pool_wait(pool)   // waits for all in-flight, returns ordered etags
 *   upload_pool_destroy(pool)
 *
 * Errors:
 *   submit() returns 0 on success, -1 on hard failure. Individual transfer
 *   failures bubble up through wait() which reports which part_num failed.
 */
#ifndef __CR_UPLOAD_POOL_H__
#define __CR_UPLOAD_POOL_H__

#include <stddef.h>

struct upload_pool;

/*
 * A single chunk in a scatter-gather upload body. See upload_pool_submit_sg.
 * Both the array of chunks and each chunk's `data` pointer must be heap-
 * allocated; the pool xfree()s them when the transfer completes.
 */
struct upload_sg_chunk {
	void *data;
	size_t len;
};

/*
 * Create an upload pool bound to a single multipart upload.
 * max_in_flight: number of concurrent PUT requests (recommend 4-8).
 * Returns NULL on failure.
 */
struct upload_pool *upload_pool_create(const char *object_key,
				       const char *upload_id,
				       int max_in_flight);

/*
 * Submit one part for upload. Transfers ownership of `data` to the pool
 * (pool frees data once transfer completes). If max_in_flight is reached,
 * blocks until at least one slot is free (pumping CURLM meanwhile).
 * part_num is the 1-based multipart part number.
 *
 * Returns 0 on success, -1 on failure (e.g., prior transfer failed).
 */
int upload_pool_submit(struct upload_pool *pool, int part_num,
		       void *data, size_t len);

/*
 * Scatter-gather variant of upload_pool_submit. Accepts a vector of
 * heap-owned chunks that the pool streams through libcurl's read callback
 * without ever assembling into a contiguous buffer. This avoids the per-
 * byte memcpy that writer_drain was doing when concatenating compressed
 * frames into an 8 MB part_buf.
 *
 * Ownership: `chunks` (the array itself) AND each `chunks[i].data` must
 * be heap-allocated. Pool frees everything on completion (success or
 * failure). Caller must NOT touch chunks or their data after this call.
 *
 * total_len must equal sum(chunks[i].len) and matches Content-Length.
 *
 * Back-pressure: same as upload_pool_submit — blocks when all slots busy.
 * Requires opts.sign_payload == false (UNSIGNED-PAYLOAD); sign_payload on
 * degrades to UNSIGNED for this request with a warning (signing a scatter
 * list would require a full body scan defeating the zero-memcpy purpose).
 */
int upload_pool_submit_sg(struct upload_pool *pool, int part_num,
			  struct upload_sg_chunk *chunks, int n_chunks,
			  size_t total_len);

/*
 * Block until all submitted parts complete. On success returns 0 and the
 * caller can read the ordered etag array via upload_pool_get_etags().
 * Returns -1 if any transfer failed; sets *failed_part_num if non-NULL.
 */
int upload_pool_wait(struct upload_pool *pool, int *failed_part_num);

/*
 * Return the etag array indexed by part_num-1 and its logical length
 * (= max part_num submitted). The array is owned by the pool.
 */
int upload_pool_get_etags(struct upload_pool *pool,
			  const char ***etags_out, int *n_parts_out);

/* Release all resources. */
void upload_pool_destroy(struct upload_pool *pool);

#endif
