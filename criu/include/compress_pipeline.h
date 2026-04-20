/*
 * compress_pipeline.h — 3-stage parallel compress/upload pipeline for S3 dump.
 *
 * Main dump thread submits raw IOVs via compress_pipeline_submit(); the call
 * returns immediately after queueing. Internally:
 *
 *   Compress pool (N workers, own ZSTD_CCtx each):
 *     dequeue raw IOV → ZSTD_compress2 → push compressed frame to writer
 *
 *   Writer thread (1):
 *     assemble frames in submit order, append to current 8 MB part_buf,
 *     log frame (size, raw_size) into seekable frame log,
 *     when part_buf fills up → enqueue part to upload pool
 *
 *   Upload pool (M workers, reusing existing multipart API):
 *     dequeue part → object_storage_multipart_upload_part() → record etag
 *
 * On finalize, writer appends the seek table (via ZSTD_seekable_writeSeekTable)
 * as the final bytes of the stream, flushes the remaining part, and the
 * pipeline waits for all uploads before calling multipart_complete().
 */

#ifndef __CR_COMPRESS_PIPELINE_H__
#define __CR_COMPRESS_PIPELINE_H__

#include <stdbool.h>
#include <stddef.h>

struct compress_pipeline;

/*
 * Create a pipeline. `object_key` and `upload_id` are the S3 multipart
 * session identifiers (already obtained via multipart_init). `level` is the
 * zstd compression level (default 1). Worker counts follow opts.compress_*.
 *
 * Returns NULL on failure.
 */
struct compress_pipeline *compress_pipeline_create(const char *object_key,
						   const char *upload_id,
						   int level,
						   int n_compress_workers,
						   int m_upload_workers);

/*
 * Submit one IOV (= one pagemap entry = one zstd frame). Copies `data` into
 * pipeline-owned storage; caller may free/reuse the buffer immediately.
 *
 * Blocks if the compress queue is full (back-pressure). Returns 0 on success
 * or -1 if a worker has reported an error (use compress_pipeline_error() to
 * check state mid-stream).
 */
int compress_pipeline_submit(struct compress_pipeline *p,
			     const void *data, size_t len);

/*
 * Finalize: drain compress queue, append the zstd seekable seek table,
 * flush the last part, wait for all uploads to land. After a successful
 * return, etag_list[0..n_parts-1] contains the etags (caller-supplied
 * array, or a pointer pair filled in by the callee).
 *
 * On success: *out_etags is a newly-allocated NULL-terminated array of
 * etag strings (caller must xfree each entry and the array itself);
 * *out_n_parts is the count. Returns -1 on any worker error.
 */
int compress_pipeline_finalize(struct compress_pipeline *p,
			       char ***out_etags, int *out_n_parts);

/* Current error state (non-zero means a worker has aborted). */
int compress_pipeline_error(struct compress_pipeline *p);

void compress_pipeline_destroy(struct compress_pipeline *p);

#endif /* __CR_COMPRESS_PIPELINE_H__ */
