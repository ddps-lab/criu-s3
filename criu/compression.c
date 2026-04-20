/*
 * compression.c — zstd seekable compression wrappers for CRIU.
 *
 * See compression.h for the overall scheme (IOV-aligned frames, auto-detect
 * via seekable magic in the seek table footer).
 *
 * On the dump side, compress_stream_add_frame() feeds one IOV worth of raw
 * page bytes to a ZSTD_seekable_CStream, ends the frame, and drives the
 * compressed bytes out through a caller-supplied write callback. Frames
 * therefore map 1:1 to pagemap entries; the restore-side seek table index
 * is identical to the pagemap entry index.
 *
 * On the restore side, decompress_create_lazy() wires up a ZSTD_seekable
 * with a caller-supplied Range-GET callback so we can defer fetching of
 * any frame body until the workload actually touches the pages in it.
 */

#define pr_fmt(fmt) "compression: " fmt

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <zstd.h>

#include "zstd_seekable.h"

#include "compression.h"
#include "common/compiler.h"
#include "log.h"
#include "xmalloc.h"

/*
 * Frame size selection:
 * IOV sizes in practice range from 4 KB (scattered dirty pages during
 * pre-dump) up to 4 MB (VMA-sized regions in full dump). Cap the
 * seekable max frame size at 16 MB to allow a safety margin above the
 * typical MAX_XFER_LEN (4 MB) without pushing into gigabyte territory.
 */
#define CS_DEFAULT_MAX_FRAME	(16UL * 1024 * 1024)

/*
 * Scratch buffer the compressor streams into. Large enough to hold one
 * worst-case frame plus zstd's small per-frame overhead; emitted to the
 * write callback as it fills up.
 */
#define CS_OUT_BUF_SIZE		(1UL * 1024 * 1024)

/* ======================================================================
 * Compression (dump side)
 * ====================================================================== */

struct compress_stream {
	ZSTD_seekable_CStream *zcs;
	void *out_buf;
	size_t out_cap;
};

static int cs_drain(ZSTD_outBuffer *out, compress_write_cb cb, void *cookie,
		    void *out_buf, size_t out_cap)
{
	if (out->pos == 0)
		return 0;
	if (cb(cookie, out_buf, out->pos) != 0)
		return -1;
	out->pos = 0;
	(void)out_cap;
	return 0;
}

struct compress_stream *compress_stream_create(int level)
{
	struct compress_stream *cs;
	size_t rc;

	cs = xzalloc(sizeof(*cs));
	if (!cs)
		return NULL;

	cs->zcs = ZSTD_seekable_createCStream();
	if (!cs->zcs) {
		pr_err("ZSTD_seekable_createCStream failed\n");
		goto err;
	}

	/*
	 * checksumFlag=0: we rely on zstd's per-frame content checksum when
	 * enabled by the compression context; skipping the separate XXH64
	 * keeps the seek table 8B/entry instead of 12B, roughly -33% table
	 * size for large dumps.
	 */
	rc = ZSTD_seekable_initCStream(cs->zcs, level, 0, CS_DEFAULT_MAX_FRAME);
	if (ZSTD_isError(rc)) {
		pr_err("ZSTD_seekable_initCStream: %s\n", ZSTD_getErrorName(rc));
		goto err;
	}

	cs->out_cap = CS_OUT_BUF_SIZE;
	cs->out_buf = xmalloc(cs->out_cap);
	if (!cs->out_buf)
		goto err;

	return cs;
err:
	compress_stream_free(cs);
	return NULL;
}

int compress_stream_add_frame(struct compress_stream *cs,
			      const void *in, size_t in_len,
			      compress_write_cb write_cb, void *cookie)
{
	ZSTD_inBuffer in_buf = { in, in_len, 0 };
	ZSTD_outBuffer out_buf = { cs->out_buf, cs->out_cap, 0 };
	size_t rc;

	/* Push the whole IOV through the streaming compressor. */
	while (in_buf.pos < in_buf.size) {
		rc = ZSTD_seekable_compressStream(cs->zcs, &out_buf, &in_buf);
		if (ZSTD_isError(rc)) {
			pr_err("ZSTD_seekable_compressStream: %s\n",
			       ZSTD_getErrorName(rc));
			return -1;
		}
		if (cs_drain(&out_buf, write_cb, cookie,
			     cs->out_buf, cs->out_cap) < 0)
			return -1;
	}

	/*
	 * End this frame so subsequent compress_stream_add_frame calls start
	 * a fresh, independently-decompressible frame. The seekable API
	 * internally bumps its frame log; at finalize time the seek table
	 * will have one entry per add_frame call.
	 */
	do {
		out_buf.pos = 0;
		rc = ZSTD_seekable_endFrame(cs->zcs, &out_buf);
		if (ZSTD_isError(rc)) {
			pr_err("ZSTD_seekable_endFrame: %s\n",
			       ZSTD_getErrorName(rc));
			return -1;
		}
		if (cs_drain(&out_buf, write_cb, cookie,
			     cs->out_buf, cs->out_cap) < 0)
			return -1;
	} while (rc > 0);

	return 0;
}

int compress_stream_finalize(struct compress_stream *cs,
			     compress_write_cb write_cb, void *cookie)
{
	ZSTD_outBuffer out_buf = { cs->out_buf, cs->out_cap, 0 };
	size_t rc;

	/*
	 * endStream flushes any buffered frame data plus the trailing
	 * skippable frame that holds the seek table. It may take several
	 * calls when the seek table itself is larger than out_buf.
	 */
	do {
		out_buf.pos = 0;
		rc = ZSTD_seekable_endStream(cs->zcs, &out_buf);
		if (ZSTD_isError(rc)) {
			pr_err("ZSTD_seekable_endStream: %s\n",
			       ZSTD_getErrorName(rc));
			return -1;
		}
		if (cs_drain(&out_buf, write_cb, cookie,
			     cs->out_buf, cs->out_cap) < 0)
			return -1;
	} while (rc > 0);

	return 0;
}

void compress_stream_free(struct compress_stream *cs)
{
	if (!cs)
		return;
	if (cs->zcs)
		ZSTD_seekable_freeCStream(cs->zcs);
	xfree(cs->out_buf);
	xfree(cs);
}

/* ======================================================================
 * Decompression (restore side)
 * ====================================================================== */

struct decompress_ctx {
	ZSTD_seekable *zs;

	/* Lazy-read mode: callback into the caller's S3 fetcher. */
	decompress_read_cb read_cb;
	void *read_cookie;
	off_t total_size;
	off_t cursor;

	/* Buffer mode: keep caller-owned buffer alive via a stable pointer. */
	const void *buffer;
	size_t buffer_len;
};

int decompress_probe(const void *tail_buf, size_t tail_len)
{
	const uint8_t *p;
	uint32_t magic;

	if (!tail_buf || tail_len < 4)
		return -1;

	p = (const uint8_t *)tail_buf + tail_len - 4;
	magic = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
		((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	return magic == COMPRESS_SEEKABLE_MAGIC ? 1 : 0;
}

struct decompress_ctx *decompress_create_from_buffer(const void *compressed,
						     size_t comp_len)
{
	struct decompress_ctx *d;
	size_t rc;

	d = xzalloc(sizeof(*d));
	if (!d)
		return NULL;

	d->zs = ZSTD_seekable_create();
	if (!d->zs) {
		pr_err("ZSTD_seekable_create failed\n");
		goto err;
	}

	d->buffer = compressed;
	d->buffer_len = comp_len;
	d->total_size = comp_len;

	rc = ZSTD_seekable_initBuff(d->zs, compressed, comp_len);
	if (ZSTD_isError(rc)) {
		pr_err("ZSTD_seekable_initBuff: %s\n", ZSTD_getErrorName(rc));
		goto err;
	}

	return d;
err:
	decompress_free(d);
	return NULL;
}

/*
 * Advanced-I/O callbacks bridging ZSTD_seekable into our range-GET callback.
 * The seekable decoder only needs seek + sequential read; we translate each
 * read(offset, length) into a call into the caller's read_cb().
 */
static int adv_read(void *opaque, void *buffer, size_t n)
{
	struct decompress_ctx *d = opaque;

	if (d->cursor < 0 || (off_t)(d->cursor + n) > d->total_size) {
		pr_err("seekable adv_read past EOF (cursor=%lld, n=%zu, total=%lld)\n",
		       (long long)d->cursor, n, (long long)d->total_size);
		return -1;
	}
	if (d->read_cb(d->read_cookie, d->cursor, n, buffer) != 0)
		return -1;
	d->cursor += n;
	return 0;
}

static int adv_seek(void *opaque, long long offset, int origin)
{
	struct decompress_ctx *d = opaque;
	off_t new_pos;

	switch (origin) {
	case 0: /* SEEK_SET */
		new_pos = offset;
		break;
	case 2: /* SEEK_END */
		new_pos = d->total_size + offset;
		break;
	default:
		pr_err("seekable adv_seek: unsupported origin %d\n", origin);
		return -1;
	}
	if (new_pos < 0 || new_pos > d->total_size) {
		pr_err("seekable adv_seek out of range: %lld (size=%lld)\n",
		       (long long)new_pos, (long long)d->total_size);
		return -1;
	}
	d->cursor = new_pos;
	return 0;
}

struct decompress_ctx *decompress_create_lazy(const void *seek_table_buf,
					      size_t seek_table_len,
					      off_t total_comp_size,
					      decompress_read_cb read_cb,
					      void *cookie)
{
	struct decompress_ctx *d;
	ZSTD_seekable_customFile cf;
	size_t rc;

	(void)seek_table_buf;
	(void)seek_table_len;

	d = xzalloc(sizeof(*d));
	if (!d)
		return NULL;

	d->zs = ZSTD_seekable_create();
	if (!d->zs) {
		pr_err("ZSTD_seekable_create failed\n");
		goto err;
	}

	d->read_cb = read_cb;
	d->read_cookie = cookie;
	d->total_size = total_comp_size;
	d->cursor = 0;

	cf.opaque = d;
	cf.read = adv_read;
	cf.seek = adv_seek;

	rc = ZSTD_seekable_initAdvanced(d->zs, cf);
	if (ZSTD_isError(rc)) {
		pr_err("ZSTD_seekable_initAdvanced: %s\n",
		       ZSTD_getErrorName(rc));
		goto err;
	}

	return d;
err:
	decompress_free(d);
	return NULL;
}

int decompress_range(struct decompress_ctx *d, off_t off, size_t len,
		     void *out)
{
	size_t got = 0;
	size_t rc;

	/* The seekable API returns the count decompressed on each call; for
	 * large reads it may satisfy the request in multiple steps. */
	while (got < len) {
		rc = ZSTD_seekable_decompress(d->zs,
					      (char *)out + got, len - got,
					      (unsigned long long)(off + got));
		if (ZSTD_isError(rc)) {
			pr_err("ZSTD_seekable_decompress: %s\n",
			       ZSTD_getErrorName(rc));
			return -1;
		}
		if (rc == 0) {
			pr_err("ZSTD_seekable_decompress returned 0 at offset %lld\n",
			       (long long)(off + got));
			return -1;
		}
		got += rc;
	}
	return 0;
}

unsigned long long decompress_total_raw_size(struct decompress_ctx *d)
{
	unsigned long long total = 0;
	unsigned nf = ZSTD_seekable_getNumFrames(d->zs);
	unsigned i;

	for (i = 0; i < nf; i++)
		total += ZSTD_seekable_getFrameDecompressedSize(d->zs, i);
	return total;
}

unsigned decompress_num_frames(struct decompress_ctx *d)
{
	return ZSTD_seekable_getNumFrames(d->zs);
}

int decompress_map_range(struct decompress_ctx *d, off_t uoff, size_t ulen,
			 off_t *comp_off, size_t *comp_len)
{
	unsigned first, last, f;
	unsigned long long start_off, end_off;

	if (ulen == 0) {
		*comp_off = 0;
		*comp_len = 0;
		return 0;
	}

	first = ZSTD_seekable_offsetToFrameIndex(d->zs,
						 (unsigned long long)uoff);
	/*
	 * offsetToFrameIndex() on an offset one past a frame boundary can
	 * return the *next* frame, which is fine for the "last" bound —
	 * probe (uoff+ulen-1) to pick the frame containing the final byte.
	 */
	last = ZSTD_seekable_offsetToFrameIndex(d->zs,
						(unsigned long long)(uoff + ulen - 1));
	if (last < first)
		last = first;

	start_off = ZSTD_seekable_getFrameCompressedOffset(d->zs, first);
	end_off = ZSTD_seekable_getFrameCompressedOffset(d->zs, last);
	if (start_off == ZSTD_SEEKABLE_FRAMEINDEX_TOOLARGE ||
	    end_off == ZSTD_SEEKABLE_FRAMEINDEX_TOOLARGE) {
		pr_err("seekable map_range: frame index out of range (first=%u last=%u)\n",
		       first, last);
		return -1;
	}
	f = last;
	end_off += ZSTD_seekable_getFrameCompressedSize(d->zs, f);

	*comp_off = (off_t)start_off;
	*comp_len = (size_t)(end_off - start_off);
	return 0;
}

void decompress_free(struct decompress_ctx *d)
{
	if (!d)
		return;
	if (d->zs)
		ZSTD_seekable_free(d->zs);
	xfree(d);
}
