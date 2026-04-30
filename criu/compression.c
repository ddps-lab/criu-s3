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

/*
 * Per-frame directory extracted from the seek table at probe time. Lets
 * us do exactly one Range GET per frame touched during decompress,
 * bypassing ZSTD_seekable_decompress's chunked customFile reads.
 */
struct zstd_frame_entry {
	unsigned long long comp_off;
	unsigned long long comp_size;
	unsigned long long decomp_off;
	unsigned long long decomp_size;
};

struct decompress_ctx {
	/* Buffer-mode (small files slurped in full): ZSTD_seekable over
	 * the full compressed buffer, decompress_range delegates directly
	 * to ZSTD_seekable_decompress (zero network). */
	ZSTD_seekable *zs;
	const void *buffer;
	size_t buffer_len;

	/*
	 * Lazy-mode (large files): frame directory extracted at init,
	 * plus a ZSTD_DCtx and a range-fetch callback. decompress_range
	 * issues one callback per frame → 1 Range GET per frame, same
	 * shape as the raw-page path.
	 */
	struct zstd_frame_entry *frames;
	unsigned int num_frames;
	ZSTD_DCtx *dctx;
	decompress_read_cb read_cb;
	void *read_cookie;

	/* Scratch buffers, resized as needed. */
	void *comp_scratch;
	size_t comp_scratch_cap;
	void *decomp_scratch;
	size_t decomp_scratch_cap;

	off_t total_size;

	/* Only used by the ZSTD_seekable customFile during the one-shot
	 * init pass that parses the seek table. Not touched afterwards. */
	off_t cursor;

	/*
	 * Per-ctx decompress instrumentation. Accumulated in decompress_range
	 * and logged once in decompress_free so we can see for each worker
	 * (and the main-thread pr->decompress) how much time was spent in
	 * read_cb (S3 Range GET) vs ZSTD_decompressDCtx (CPU), plus the
	 * observed compression ratio. Intended output shape:
	 *
	 *   decompress[frametable]: calls=N frames=M comp=XMB→raw=YMB
	 *       (ratio=Z) fetch=FMs decomp=DMs ...
	 */
	unsigned long stat_calls;
	unsigned long stat_frames;
	unsigned long long stat_bytes_comp;
	unsigned long long stat_bytes_decomp;
	unsigned long long stat_fetch_ns;
	unsigned long long stat_decomp_ns;
};

#ifdef __linux__
#include <time.h>
static inline unsigned long long _mono_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
#else
static inline unsigned long long _mono_ns(void) { return 0; }
#endif

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

/*
 * Init path: use ZSTD_seekable once to parse the seek table via the
 * caller's read_cb (which should serve those reads from a pre-fetched
 * tail buffer), snapshot every frame's {comp_off, comp_size, decomp_off,
 * decomp_size} into our own array, then free ZSTD_seekable. Decompress
 * from this point on is driven by frames[] and ZSTD_DCtx — ZSTD_seekable
 * no longer touches the read_cb, so there is no per-frame customFile
 * read amplification.
 */
struct decompress_ctx *decompress_create_lazy(const void *seek_table_buf,
					      size_t seek_table_len,
					      off_t total_comp_size,
					      decompress_read_cb read_cb,
					      void *cookie)
{
	struct decompress_ctx *d;
	ZSTD_seekable *parse_zs = NULL;
	ZSTD_seekable_customFile cf;
	size_t rc;
	unsigned i, nf;

	(void)seek_table_buf;
	(void)seek_table_len;

	d = xzalloc(sizeof(*d));
	if (!d)
		return NULL;

	d->read_cb = read_cb;
	d->read_cookie = cookie;
	d->total_size = total_comp_size;
	d->cursor = 0;

	parse_zs = ZSTD_seekable_create();
	if (!parse_zs) {
		pr_err("ZSTD_seekable_create failed\n");
		goto err;
	}

	cf.opaque = d;
	cf.read = adv_read;
	cf.seek = adv_seek;

	rc = ZSTD_seekable_initAdvanced(parse_zs, cf);
	if (ZSTD_isError(rc)) {
		pr_err("ZSTD_seekable_initAdvanced: %s\n",
		       ZSTD_getErrorName(rc));
		goto err;
	}

	nf = ZSTD_seekable_getNumFrames(parse_zs);
	if (nf == 0) {
		pr_err("decompress_create_lazy: seek table reports 0 frames\n");
		goto err;
	}

	d->frames = xzalloc(nf * sizeof(*d->frames));
	if (!d->frames)
		goto err;
	for (i = 0; i < nf; i++) {
		d->frames[i].comp_off   = ZSTD_seekable_getFrameCompressedOffset(parse_zs, i);
		d->frames[i].comp_size  = ZSTD_seekable_getFrameCompressedSize(parse_zs, i);
		d->frames[i].decomp_off = ZSTD_seekable_getFrameDecompressedOffset(parse_zs, i);
		d->frames[i].decomp_size = ZSTD_seekable_getFrameDecompressedSize(parse_zs, i);
	}
	d->num_frames = nf;

	ZSTD_seekable_free(parse_zs);
	parse_zs = NULL;

	d->dctx = ZSTD_createDCtx();
	if (!d->dctx) {
		pr_err("ZSTD_createDCtx failed\n");
		goto err;
	}

	return d;
err:
	if (parse_zs)
		ZSTD_seekable_free(parse_zs);
	decompress_free(d);
	return NULL;
}

/*
 * Find the frame containing the given uncompressed byte offset via
 * binary search on frames[].decomp_off. Returns num_frames if the
 * offset sits past the last frame.
 */
static unsigned find_frame(const struct zstd_frame_entry *frames,
			   unsigned num_frames, unsigned long long uoff)
{
	unsigned lo = 0, hi = num_frames;
	while (lo < hi) {
		unsigned mid = lo + (hi - lo) / 2;
		unsigned long long fo = frames[mid].decomp_off;
		unsigned long long fe = fo + frames[mid].decomp_size;
		if (uoff < fo)
			hi = mid;
		else if (uoff >= fe)
			lo = mid + 1;
		else
			return mid;
	}
	return num_frames;
}

/*
 * Grow a scratch buffer in place if cap is too small. Returns 0 on ok.
 */
static int ensure_scratch(void **buf, size_t *cap, size_t need)
{
	void *nb;
	if (need <= *cap)
		return 0;
	nb = xrealloc(*buf, need);
	if (!nb)
		return -1;
	*buf = nb;
	*cap = need;
	return 0;
}

int decompress_range(struct decompress_ctx *d, off_t off, size_t len,
		     void *out)
{
	/* Buffer-mode: delegate to ZSTD_seekable which has full bytes in
	 * memory already. No Range GETs, so amplification doesn't matter. */
	if (d->zs) {
		size_t got = 0;
		size_t rc;
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

	/* Lazy/frame-table mode. */
	if (!d->frames || !d->dctx || !d->read_cb) {
		pr_err("decompress_range: ctx not initialized for frame-table mode\n");
		return -1;
	}

	{
		unsigned long long uoff = (unsigned long long)off;
		unsigned long long uend = uoff + len;
		unsigned first = find_frame(d->frames, d->num_frames, uoff);
		unsigned last;
		unsigned long long span_comp_off, span_comp_end;
		size_t span_comp_size;
		char *dst = (char *)out;
		size_t done = 0;
		unsigned i;

		if (first >= d->num_frames) {
			pr_err("decompress_range: uoff=%llu past frame table\n", uoff);
			return -1;
		}

		/*
		 * Find the last frame the requested uncompressed range touches.
		 * Frames[] is ordered by both uncompressed and compressed offset,
		 * so the compressed bytes for frames[first..last] form a single
		 * contiguous byte range we can pull in one Range GET instead of
		 * the one-RTT-per-frame loop we used to run. For an 8-worker
		 * MinIO/S3 fault path this cut 4500+ tiny Range GETs down to
		 * a few hundred batch GETs, roughly matching the raw-page path.
		 */
		last = first;
		while (last + 1 < d->num_frames &&
		       d->frames[last].decomp_off + d->frames[last].decomp_size < uend)
			last++;

		span_comp_off = d->frames[first].comp_off;
		span_comp_end = d->frames[last].comp_off + d->frames[last].comp_size;
		span_comp_size = (size_t)(span_comp_end - span_comp_off);

		if (ensure_scratch(&d->comp_scratch, &d->comp_scratch_cap,
				   span_comp_size) < 0)
			return -1;
		{
			unsigned long long _t0 = _mono_ns();
			int _rc = d->read_cb(d->read_cookie, (off_t)span_comp_off,
					     span_comp_size, d->comp_scratch);
			d->stat_fetch_ns += _mono_ns() - _t0;
			if (_rc != 0) {
				pr_err("decompress_range: batched read_cb failed (frames %u..%u, comp_off=%llu, size=%zu)\n",
				       first, last, span_comp_off, span_comp_size);
				return -1;
			}
		}
		d->stat_bytes_comp += span_comp_size;

		for (i = first; i <= last; i++) {
			struct zstd_frame_entry *f = &d->frames[i];
			const char *cbytes =
				(const char *)d->comp_scratch +
				(f->comp_off - span_comp_off);
			size_t dec;
			unsigned long long _t0;

			if (uoff >= f->decomp_off + f->decomp_size)
				continue; /* caller's range starts after this frame */

			if (uoff == f->decomp_off && (uend - uoff) >= f->decomp_size) {
				/* Whole frame fits in the caller's buffer. */
				_t0 = _mono_ns();
				dec = ZSTD_decompressDCtx(d->dctx,
							  dst + done,
							  (size_t)f->decomp_size,
							  cbytes,
							  (size_t)f->comp_size);
				d->stat_decomp_ns += _mono_ns() - _t0;
				if (ZSTD_isError(dec)) {
					pr_err("ZSTD_decompressDCtx frame %u: %s\n",
					       i, ZSTD_getErrorName(dec));
					return -1;
				}
				d->stat_frames++;
				d->stat_bytes_decomp += dec;
				done += dec;
				uoff += dec;
			} else {
				/* Partial overlap — decompress into scratch, copy subset. */
				size_t frame_off_in = (size_t)(uoff - f->decomp_off);
				size_t want = (size_t)(uend - uoff);
				size_t avail = (size_t)(f->decomp_size - frame_off_in);
				size_t take = want < avail ? want : avail;

				if (ensure_scratch(&d->decomp_scratch, &d->decomp_scratch_cap,
						   (size_t)f->decomp_size) < 0)
					return -1;
				_t0 = _mono_ns();
				dec = ZSTD_decompressDCtx(d->dctx,
							  d->decomp_scratch,
							  (size_t)f->decomp_size,
							  cbytes,
							  (size_t)f->comp_size);
				d->stat_decomp_ns += _mono_ns() - _t0;
				if (ZSTD_isError(dec)) {
					pr_err("ZSTD_decompressDCtx frame %u: %s\n",
					       i, ZSTD_getErrorName(dec));
					return -1;
				}
				d->stat_frames++;
				d->stat_bytes_decomp += dec;
				memcpy(dst + done,
				       (char *)d->decomp_scratch + frame_off_in, take);
				done += take;
				uoff += take;
			}
			if (uoff >= uend)
				break;
		}
		d->stat_calls++;
		return 0;
	}
}

unsigned long long decompress_total_raw_size(struct decompress_ctx *d)
{
	unsigned long long total = 0;
	unsigned i;

	if (d->zs) {
		unsigned nf = ZSTD_seekable_getNumFrames(d->zs);
		for (i = 0; i < nf; i++)
			total += ZSTD_seekable_getFrameDecompressedSize(d->zs, i);
	} else if (d->frames) {
		for (i = 0; i < d->num_frames; i++)
			total += d->frames[i].decomp_size;
	}
	return total;
}

unsigned decompress_num_frames(struct decompress_ctx *d)
{
	if (d->zs)
		return ZSTD_seekable_getNumFrames(d->zs);
	return d->num_frames;
}

int decompress_map_range(struct decompress_ctx *d, off_t uoff, size_t ulen,
			 off_t *comp_off, size_t *comp_len)
{
	unsigned first, last;

	if (ulen == 0) {
		*comp_off = 0;
		*comp_len = 0;
		return 0;
	}

	if (d->zs) {
		unsigned long long start_off, end_off;
		unsigned f;

		first = ZSTD_seekable_offsetToFrameIndex(d->zs, (unsigned long long)uoff);
		last = ZSTD_seekable_offsetToFrameIndex(d->zs,
							(unsigned long long)(uoff + ulen - 1));
		if (last < first)
			last = first;
		start_off = ZSTD_seekable_getFrameCompressedOffset(d->zs, first);
		end_off = ZSTD_seekable_getFrameCompressedOffset(d->zs, last);
		if (start_off == ZSTD_SEEKABLE_FRAMEINDEX_TOOLARGE ||
		    end_off == ZSTD_SEEKABLE_FRAMEINDEX_TOOLARGE)
			return -1;
		f = last;
		end_off += ZSTD_seekable_getFrameCompressedSize(d->zs, f);
		*comp_off = (off_t)start_off;
		*comp_len = (size_t)(end_off - start_off);
		return 0;
	}

	/* Frame-table mode. */
	first = find_frame(d->frames, d->num_frames, (unsigned long long)uoff);
	last = find_frame(d->frames, d->num_frames,
			  (unsigned long long)(uoff + ulen - 1));
	if (first >= d->num_frames || last >= d->num_frames)
		return -1;
	*comp_off = (off_t)d->frames[first].comp_off;
	*comp_len = (size_t)((d->frames[last].comp_off + d->frames[last].comp_size) -
			     d->frames[first].comp_off);
	return 0;
}

void decompress_free(struct decompress_ctx *d)
{
	if (!d)
		return;
	/*
	 * Per-ctx usage summary. Emitted only when the ctx actually did work
	 * (stat_calls > 0), so short-lived init contexts don't spam the log.
	 * Shape is stable and keyed by "decompress_stats:" for `parse_ablation.py`.
	 * bytes_comp is bytes pulled by read_cb (what the network actually
	 * moved). bytes_decomp is uncompressed bytes produced. ratio is
	 * comp/decomp so smaller = better compression.
	 */
	if (d->stat_calls > 0) {
		double fetch_ms = d->stat_fetch_ns / 1e6;
		double decomp_ms = d->stat_decomp_ns / 1e6;
		double ratio = d->stat_bytes_decomp
			? (double)d->stat_bytes_comp / (double)d->stat_bytes_decomp
			: 0.0;
		double comp_mbps = fetch_ms > 0
			? (d->stat_bytes_comp / 1048576.0) / (fetch_ms / 1000.0)
			: 0.0;
		double decomp_mbps = decomp_ms > 0
			? (d->stat_bytes_decomp / 1048576.0) / (decomp_ms / 1000.0)
			: 0.0;
		pr_info("decompress_stats: mode=%s calls=%lu frames=%lu "
			"bytes_comp=%llu bytes_decomp=%llu ratio=%.3f "
			"fetch_ms=%.1f decomp_ms=%.1f fetch_mbps=%.0f decomp_mbps=%.0f\n",
			d->zs ? "buffer" : "lazy",
			d->stat_calls, d->stat_frames,
			d->stat_bytes_comp, d->stat_bytes_decomp, ratio,
			fetch_ms, decomp_ms, comp_mbps, decomp_mbps);
	}
	if (d->zs)
		ZSTD_seekable_free(d->zs);
	if (d->dctx)
		ZSTD_freeDCtx(d->dctx);
	if (d->frames)
		xfree(d->frames);
	if (d->comp_scratch)
		xfree(d->comp_scratch);
	if (d->decomp_scratch)
		xfree(d->decomp_scratch);
	xfree(d);
}
