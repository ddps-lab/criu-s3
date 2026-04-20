/*
 * compression.h — zstd seekable compression for CRIU checkpoint images.
 *
 * The pages-*.img files are compressed with zstd's seekable format:
 * each IOV (pagemap entry) becomes one independently compressed frame,
 * and a seek table appended at end-of-file lets restore map uncompressed
 * offsets to compressed byte ranges for Range GETs on S3.
 *
 * Enabled by --compress. Restore auto-detects via the seekable magic
 * (0x8F92EAB1) in the trailing skippable frame, so a compressed dump
 * can be restored without passing --compress.
 */

#ifndef __CR_COMPRESSION_H__
#define __CR_COMPRESSION_H__

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * Dump-side streaming compressor. One frame per call to compress_frame().
 * Produces a seekable-format zstd stream with a trailing seek table.
 */
struct compress_stream;

/* Initialize a new compressor. level=1..22. Returns NULL on failure. */
struct compress_stream *compress_stream_create(int level);

/* Feed one IOV of raw bytes, emit one independently compressed frame.
 * Callbacks `write_cb(cookie, buf, len)` are invoked with compressed
 * bytes; implementations can buffer or stream them to S3/local disk.
 *
 * Returns 0 on success, -1 on failure. */
typedef int (*compress_write_cb)(void *cookie, const void *buf, size_t len);

int compress_stream_add_frame(struct compress_stream *cs,
			      const void *in, size_t in_len,
			      compress_write_cb write_cb, void *cookie);

/* Finalize: emit the trailing seek table frame. Must be called before free. */
int compress_stream_finalize(struct compress_stream *cs,
			     compress_write_cb write_cb, void *cookie);

void compress_stream_free(struct compress_stream *cs);


/*
 * Restore-side random-access decompressor. Initialized with the seek table
 * region (last N bytes of the file) and the total compressed file size.
 * Subsequent decompress_range() calls map uncompressed (offset, length)
 * to a compressed byte range, fetch via a caller-supplied read callback,
 * and decompress into the output buffer.
 */
struct decompress_ctx;

/* Probe whether the trailing buffer is a zstd seekable seek table.
 * `tail_buf` is the last `tail_len` bytes of the compressed file.
 * Returns 1 if compressed, 0 if not, -1 on error. */
int decompress_probe(const void *tail_buf, size_t tail_len);

/*
 * Initialize a decompressor from the full compressed file contents in memory.
 * The input buffer must remain valid until decompress_free().
 * Use this for small compressed files (e.g. metadata) where fetching the
 * whole blob is cheap.
 */
struct decompress_ctx *decompress_create_from_buffer(const void *compressed,
						     size_t comp_len);

/*
 * Initialize a decompressor from just the seek table bytes.
 * `seek_table_buf` is the last ~12 KB of the compressed file (seek table
 * region). `total_comp_size` is the full compressed file size.
 * Compressed frame data is fetched lazily via `read_cb` when needed.
 */
typedef int (*decompress_read_cb)(void *cookie, off_t offset, size_t length,
				  void *out);

struct decompress_ctx *decompress_create_lazy(const void *seek_table_buf,
					      size_t seek_table_len,
					      off_t total_comp_size,
					      decompress_read_cb read_cb,
					      void *cookie);

/* Decompress an uncompressed byte range [off, off+len) into out. */
int decompress_range(struct decompress_ctx *d, off_t off, size_t len,
		     void *out);

/*
 * Map an uncompressed range to the compressed byte range it overlaps.
 * Useful when the caller wants to issue the Range GET itself and feed
 * bytes back via decompress_feed_range().
 */
int decompress_map_range(struct decompress_ctx *d, off_t uoff, size_t ulen,
			 off_t *comp_off, size_t *comp_len);

void decompress_free(struct decompress_ctx *d);

/*
 * zstd seekable format constants. Exported so callers can size the seek
 * table fetch (the trailing region they hand to decompress_create_lazy).
 *
 * Seek table layout (little-endian, at end of file):
 *   Skippable frame magic (4B) | frame size (4B) | entries | footer
 *   footer = numFrames (4B) | seekTableDescriptor (1B) | magic (4B = 0x8F92EAB1)
 *
 * Each entry is 8 or 12 bytes depending on checksum flag.
 * A conservative 64 KB trailing fetch covers ~5000 frames; pages-*.img
 * with 4 MB IOVs has ~1000 frames for mc-4gb.
 */
#define COMPRESS_SEEK_TABLE_FETCH_BYTES	(64UL * 1024)
#define COMPRESS_SEEKABLE_MAGIC		0x8F92EAB1U

#endif /* __CR_COMPRESSION_H__ */
