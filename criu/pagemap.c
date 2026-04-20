#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/falloc.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <limits.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "types.h"
#include "image.h"
#include "cr_options.h"
#include "servicefd.h"
#include "pagemap.h"
#include "restorer.h"
#include "rst-malloc.h"
#include "page-xfer.h"

#include "fault-injection.h"
#include "xmalloc.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"
#include "object-storage.h"
#include "compression.h"

#ifndef SEEK_DATA
#define SEEK_DATA 3
#define SEEK_HOLE 4
#endif

#define MAX_BUNCH_SIZE 256

/*
 * One "job" for the preadv() syscall in pagemap.c
 */
struct page_read_iov {
	off_t from;	  /* offset in pi file where to start reading from */
	off_t end;	  /* the end of the read == sum to.iov_len -s */
	struct iovec *to; /* destination iovs */
	unsigned int nr;  /* their number */

	struct list_head l;
};

static inline bool can_extend_bunch(struct iovec *bunch, unsigned long off, unsigned long len)
{
	return /* The next region is the continuation of the existing */
		((unsigned long)bunch->iov_base + bunch->iov_len == off) &&
		/* The resulting region is non empty and is small enough */
		(bunch->iov_len == 0 || bunch->iov_len + len < MAX_BUNCH_SIZE * PAGE_SIZE);
}

static int punch_hole(struct page_read *pr, unsigned long off, unsigned long len, bool cleanup)
{
	int ret;
	struct iovec *bunch = &pr->bunch;

	if (!cleanup && can_extend_bunch(bunch, off, len)) {
		pr_debug("pr%lu-%u:Extend bunch len from %zu to %lu\n", pr->img_id, pr->id, bunch->iov_len,
			 bunch->iov_len + len);
		bunch->iov_len += len;
	} else {
		if (bunch->iov_len > 0) {
			pr_debug("Punch!/%p/%zu/\n", bunch->iov_base, bunch->iov_len);
			ret = fallocate(img_raw_fd(pr->pi), FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
					(unsigned long)bunch->iov_base, bunch->iov_len);
			if (ret != 0) {
				pr_perror("Error punching hole");
				return -1;
			}
		}
		bunch->iov_base = (void *)off;
		bunch->iov_len = len;
		pr_debug("pr%lu-%u:New bunch/%p/%zu/\n", pr->img_id, pr->id, bunch->iov_base, bunch->iov_len);
	}
	return 0;
}

int dedup_one_iovec(struct page_read *pr, unsigned long off, unsigned long len)
{
	unsigned long iov_end;

	iov_end = off + len;
	while (1) {
		int ret;
		unsigned long piov_end;
		struct page_read *prp;

		ret = pr->seek_pagemap(pr, off);
		if (ret == 0) {
			if (off < pr->cvaddr && pr->cvaddr < iov_end) {
				pr_debug("pr%lu-%u:No range %lx-%lx in pagemap\n", pr->img_id, pr->id, off, pr->cvaddr);
				off = pr->cvaddr;
			} else {
				pr_debug("pr%lu-%u:No range %lx-%lx in pagemap\n", pr->img_id, pr->id, off, iov_end);
				return 0;
			}
		}

		if (!pr->pe)
			return -1;
		piov_end = pr->pe->vaddr + pagemap_len(pr->pe);
		if (!pagemap_in_parent(pr->pe)) {
			ret = punch_hole(pr, pr->pi_off, min(piov_end, iov_end) - off, false);
			if (ret == -1)
				return ret;
		}

		prp = pr->parent;
		if (prp) {
			/* recursively */
			pr_debug("pr%lu-%u:Go to next parent level\n", pr->img_id, pr->id);
			len = min(piov_end, iov_end) - off;
			ret = dedup_one_iovec(prp, off, len);
			if (ret != 0)
				return -1;
		}

		if (piov_end < iov_end) {
			off = piov_end;
			continue;
		} else
			return 0;
	}
	return 0;
}

static int advance(struct page_read *pr)
{
	pr->curr_pme++;
	if (pr->curr_pme >= pr->nr_pmes)
		return 0;

	pr->pe = pr->pmes[pr->curr_pme];
	pr->cvaddr = pr->pe->vaddr;

	return 1;
}

static void skip_pagemap_pages(struct page_read *pr, unsigned long len)
{
	if (!len)
		return;

	if (pagemap_present(pr->pe))
		pr->pi_off += len;
	pr->cvaddr += len;
}

static int seek_pagemap(struct page_read *pr, unsigned long vaddr)
{
	if (!pr->pe)
		goto adv;

	do {
		unsigned long start = pr->pe->vaddr;
		unsigned long end = start + pagemap_len(pr->pe);

		if (vaddr < pr->cvaddr)
			break;

		if (vaddr >= start && vaddr < end) {
			skip_pagemap_pages(pr, vaddr - pr->cvaddr);
			return 1;
		}

		if (end <= vaddr)
			skip_pagemap_pages(pr, end - pr->cvaddr);
	adv:; /* otherwise "label at end of compound stmt" gcc error */
	} while (advance(pr));

	return 0;
}

static inline void pagemap_bound_check(PagemapEntry *pe, unsigned long vaddr, int nr)
{
	if (vaddr < pe->vaddr || (vaddr - pe->vaddr) / PAGE_SIZE + nr > pe->nr_pages) {
		pr_err("Page read err %" PRIx64 ":%u vs %lx:%u\n", pe->vaddr, pe->nr_pages, vaddr, nr);
		BUG();
	}
}

static int read_parent_page(struct page_read *pr, unsigned long vaddr, int nr, void *buf, unsigned flags)
{
	struct page_read *ppr = pr->parent;
	int ret;

	if (!ppr) {
		pr_err("No parent for snapshot pagemap\n");
		return -1;
	}

	/*
	 * Parent pagemap at this point entry may be shorter
	 * than the current vaddr:nr needs, so we have to
	 * carefully 'split' the vaddr:nr into pieces and go
	 * to parent page-read with the longest requests it
	 * can handle.
	 */

	do {
		int p_nr;

		pr_debug("\tpr%lu-%u Read from parent\n", pr->img_id, pr->id);
		ret = ppr->seek_pagemap(ppr, vaddr);
		if (ret <= 0) {
			pr_err("Missing %lx in parent pagemap\n", vaddr);
			return -1;
		}

		/*
		 * This is how many pages we have in the parent
		 * page_read starting from vaddr. Go ahead and
		 * read as much as we can.
		 */
		p_nr = ppr->pe->nr_pages - (vaddr - ppr->pe->vaddr) / PAGE_SIZE;
		pr_info("\tparent has %u pages in\n", p_nr);
		if (p_nr > nr)
			p_nr = nr;

		ret = ppr->read_pages(ppr, vaddr, p_nr, buf, flags);
		if (ret == -1)
			return ret;

		/*
		 * OK, let's see how much data we have left and go
		 * to parent page-read again for the next pagemap
		 * entry.
		 */
		nr -= p_nr;
		vaddr += p_nr * PAGE_SIZE;
		buf += p_nr * PAGE_SIZE;
	} while (nr);

	return 0;
}

/*
 * Callback cookie for decompress_create_lazy() on S3 pages-*.img.
 * Gives the seekable decoder a way to issue Range GETs against
 * the object it lives on without pulling the whole file into RAM.
 */
struct s3_decomp_cookie {
	char object_key[PATH_MAX];
	unsigned long total_size;
};

static int s3_decomp_read_cb(void *cookie, off_t offset, size_t length, void *out)
{
	struct s3_decomp_cookie *c = cookie;
	unsigned long got = 0;
	int rc;

	/*
	 * The seekable decoder requests the last bytes of the file first
	 * to parse the seek table. Use the tolerant short-read variant so
	 * tail probes don't error out just because the range extends a few
	 * bytes past EOF.
	 */
	rc = object_storage_fetch_range_short(c->object_key, (unsigned long)offset,
					      (unsigned long)length, out, &got,
					      OBJSTOR_SRC_FAULT);
	if (rc != 0)
		return -1;
	if (got != length) {
		/* Pad the short tail with zeros; the decoder only indexes
		 * into bytes it actually wrote and will ignore the pad. */
		memset((char *)out + got, 0, length - got);
	}
	return 0;
}

/*
 * Detect zstd seekable format on a pages-*.img stored in object storage
 * and, if present, wire up pr->decompress as the source of truth for
 * every future fetch. The object key must already be constructed; the
 * caller passes in an upper bound for the file size (or 0 to probe for
 * it via a speculative range fetch past a reasonably-sized tail).
 */
static int init_s3_compression(struct page_read *pr, const char *object_key)
{
	uint8_t tail[4096];
	unsigned long tail_got = 0;
	unsigned long probe_len = 4096;
	off_t probe_off;
	struct s3_decomp_cookie *cookie;
	int rc;

	/*
	 * We don't know the file size up front (no HEAD API). Probe by
	 * requesting a generous window near the start of the file — S3
	 * will short-read if the file is smaller. The public fetch_range
	 * treats a short read as failure, so use the tolerant variant.
	 */
	probe_off = 0;
	rc = object_storage_fetch_range_short(object_key, probe_off, probe_len,
					      tail, &tail_got, OBJSTOR_SRC_FAULT);
	if (rc != 0 || tail_got < 4)
		return 0;

	/*
	 * If the whole file fits in our probe buffer its last 4 bytes are
	 * right there; otherwise we need to find out where EOF is and
	 * reread the last 4. The fast path that matters in practice is the
	 * small-file case (metadata, test sleeps) — for a big pages-*.img
	 * we fall back to a binary search.
	 */
	if (tail_got < probe_len) {
		/* Whole file returned; check its tail. */
		if (decompress_probe(tail + tail_got - 4, 4) != 1)
			return 0;

		cookie = xzalloc(sizeof(*cookie));
		if (!cookie)
			return -1;
		snprintf(cookie->object_key, sizeof(cookie->object_key),
			 "%s", object_key);
		cookie->total_size = tail_got;
	} else {
		/*
		 * File is at least probe_len bytes. Walk forward by doubling
		 * ranges until we hit EOF. This is O(log N) range GETs.
		 */
		unsigned long size = probe_len;
		unsigned long step = probe_len;

		/*
		 * Geometric size probe: allocate a sliding scratch buffer
		 * whose size doubles each iteration, issue a Range GET into
		 * it starting at `size`, and stop when the response is short.
		 * O(log N) requests, max buffer = next power of two above
		 * the actual file size.
		 */
		{
			void *probe_scratch = NULL;
			size_t scratch_cap = 0;
			int loop_guard = 0;

			while (loop_guard++ < 48 /* 2^48 > any realistic size */) {
				unsigned long got = 0;

				step *= 2;
				if (scratch_cap < step) {
					void *nb = xrealloc(probe_scratch, step);
					if (!nb) {
						xfree(probe_scratch);
						return -1;
					}
					probe_scratch = nb;
					scratch_cap = step;
				}
				rc = object_storage_fetch_range_short(object_key,
					size, step, probe_scratch, &got,
					OBJSTOR_SRC_FAULT);
				if (rc != 0) {
					xfree(probe_scratch);
					return 0;
				}
				if (got < step) {
					size += got;
					break;
				}
				size += step;
			}
			xfree(probe_scratch);
		}

		/* Fetch last 4 bytes. */
		if (object_storage_fetch_range_short(object_key, size - 4, 4,
					             tail, &tail_got,
					             OBJSTOR_SRC_FAULT) != 0)
			return 0;
		if (tail_got != 4 || decompress_probe(tail, 4) != 1)
			return 0;

		cookie = xzalloc(sizeof(*cookie));
		if (!cookie)
			return -1;
		snprintf(cookie->object_key, sizeof(cookie->object_key),
			 "%s", object_key);
		cookie->total_size = size;
	}

	pr_info("page-read: detected compressed S3 pages-*.img %s (%lu bytes)\n",
		object_key, cookie->total_size);

	pr->decompress = decompress_create_lazy(NULL, 0,
						(off_t)cookie->total_size,
						s3_decomp_read_cb, cookie);
	if (!pr->decompress) {
		xfree(cookie);
		return -1;
	}
	pr->compressed_mode = true;
	pr->decompress_cookie = cookie;
	/* Eager prefetch / ra_buf are bypassed in compressed mode — the
	 * decompressor manages its own read-ahead via the seekable API. */

	return 0;
}

/*
 * Auto-detect zstd seekable format on a local pages-*.img.
 *
 * Detection: the last 4 bytes of a seekable file hold the seek-table magic.
 *
 * On detection we fully decompress the image into a memfd and replace the
 * cr_img fd with the memfd. Every downstream path that reads pages
 * (parasite preadv(), read_local_page(), premap, dedup) sees what looks
 * like a raw pages-*.img and needs no modification. The in-memory raw
 * size matches the original uncompressed dump, but that's memory the
 * restore process is about to consume anyway.
 *
 * If the file is compressed but decoder setup or full-decompress fails,
 * we bail out — falling back to raw reads of compressed bytes would
 * corrupt the restore.
 */
static int init_local_compression(struct page_read *pr)
{
	int src_fd, mfd;
	struct stat st;
	uint8_t tail[4];
	ssize_t n;
	void *src_buf = NULL;
	void *dst_buf = NULL;
	struct decompress_ctx *dctx = NULL;
	off_t off;
	unsigned int n_frames, i;
	unsigned long long total_raw;

	src_fd = img_raw_fd(pr->pi);
	if (src_fd < 0)
		return 0;
	if (fstat(src_fd, &st) < 0) {
		pr_perror("init_local_compression: fstat");
		return -1;
	}
	if (st.st_size < 4)
		return 0;

	n = pread(src_fd, tail, 4, st.st_size - 4);
	if (n != 4) {
		pr_perror("init_local_compression: pread tail");
		return -1;
	}
	if (decompress_probe(tail, sizeof(tail)) != 1)
		return 0;

	pr_info("page-read: detected zstd seekable pages-*.img (%lld bytes compressed)\n",
		(long long)st.st_size);

	/*
	 * Map the compressed file read-only instead of slurping via read().
	 * The seekable decoder only needs random-access bytes; MAP_PRIVATE
	 * lets the kernel demand-page from the backing file and never
	 * counts the bytes against CRIU's RSS (unlike a heap slurp).
	 */
	src_buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, src_fd, 0);
	if (src_buf == MAP_FAILED) {
		pr_perror("init_local_compression: mmap compressed");
		src_buf = NULL;
		return -1;
	}
	(void)off;
	(void)n;

	dctx = decompress_create_from_buffer(src_buf, st.st_size);
	if (!dctx)
		goto err;

	n_frames = decompress_num_frames(dctx);
	total_raw = decompress_total_raw_size(dctx);
	(void)i;
	(void)dst_buf;

	pr_info("page-read: decompressing %u frames -> %llu raw bytes into memfd\n",
		n_frames, total_raw);

	/*
	 * Memory strategy: allocate the uncompressed size as a memfd, mmap
	 * it shared, then decompress directly into the mapping. This
	 * avoids doubling memory vs. the xmalloc-then-write approach —
	 * we pay exactly one raw-sized allocation which the kernel
	 * accounts as tmpfs, not heap.
	 */
	mfd = syscall(SYS_memfd_create, "criu-decompressed-pages", 0);
	if (mfd < 0) {
		pr_perror("init_local_compression: memfd_create");
		goto err;
	}
	if (ftruncate(mfd, total_raw) < 0) {
		pr_perror("init_local_compression: ftruncate memfd");
		close(mfd);
		goto err;
	}
	{
		void *map = mmap(NULL, total_raw, PROT_READ | PROT_WRITE,
				 MAP_SHARED, mfd, 0);
		if (map == MAP_FAILED) {
			pr_perror("init_local_compression: mmap memfd");
			close(mfd);
			goto err;
		}
		if (decompress_range(dctx, 0, total_raw, map) < 0) {
			pr_err("init_local_compression: decompress_range failed\n");
			munmap(map, total_raw);
			close(mfd);
			goto err;
		}
		munmap(map, total_raw);
	}
	if (lseek(mfd, 0, SEEK_SET) < 0) {
		pr_perror("init_local_compression: lseek memfd");
		close(mfd);
		goto err;
	}

	/* Close the original compressed fd and put the memfd in its place. */
	close(pr->pi->_x.fd);
	pr->pi->_x.fd = mfd;

	decompress_free(dctx);
	munmap(src_buf, st.st_size);

	/* Intentionally do NOT set pr->compressed_mode / pr->decompress — from
	 * this point on pr->pi points at a raw pages-*.img (in memfd). Every
	 * downstream path runs unmodified, including parasite preadv(). */
	return 0;

err:
	if (dctx)
		decompress_free(dctx);
	if (src_buf)
		munmap(src_buf, st.st_size);
	if (dst_buf)
		xfree(dst_buf);
	return -1;
}

static int read_local_page(struct page_read *pr, unsigned long vaddr, unsigned long len, void *buf)
{
	int fd;
	ssize_t ret;
	size_t curr = 0;

	/* Compressed pages-*.img: skip fd read, decompress from the
	 * in-memory seekable stream. pi_off is an uncompressed offset. */
	if (pr->compressed_mode) {
		if (decompress_range(pr->decompress, pr->pi_off, len, buf) < 0) {
			pr_err("read_local_page: decompress_range(off=%" PRIx64 ", len=%lu) failed\n",
			       (uint64_t)pr->pi_off, len);
			return -1;
		}
		return 0;
	}

	fd = img_raw_fd(pr->pi);
	if (fd < 0) {
		pr_err("Failed getting raw image fd\n");
		return -1;
	}
	/*
	 * Flush any pending async requests if any not to break the
	 * linear reading from the pages.img file.
	 */
	if (pr->sync(pr))
		return -1;

	pr_debug("\tpr%lu-%u Read page from self %lx/%" PRIx64 "\n", pr->img_id, pr->id, pr->cvaddr, pr->pi_off);
	while (1) {
		ret = pread(fd, buf + curr, len - curr, pr->pi_off + curr);
		if (ret < 1) {
			pr_perror("Can't read mapping page %zd", ret);
			return -1;
		}
		curr += ret;
		if (curr == len)
			break;
	}

	/*
	 * auto-dedup works by punching holes into pages-*.img at the
	 * *raw* byte offset of the read. That doesn't exist on a
	 * compressed pages-*.img — the bytes at pi_off are zstd frame
	 * data, not raw pages. Skip the hole-punch when compressed.
	 */
	if (opts.auto_dedup && !pr->disable_dedup && !pr->compressed_mode) {
		ret = punch_hole(pr, pr->pi_off, len, false);
		if (ret == -1)
			return -1;
	}

	return 0;
}

static int enqueue_async_iov(struct page_read *pr, void *buf, unsigned long len, struct list_head *to)
{
	struct page_read_iov *pr_iov;
	struct iovec *iov;

	pr_iov = xzalloc(sizeof(*pr_iov));
	if (!pr_iov)
		return -1;

	pr_iov->from = pr->pi_off;
	pr_iov->end = pr->pi_off + len;

	iov = xzalloc(sizeof(*iov));
	if (!iov) {
		xfree(pr_iov);
		return -1;
	}

	iov->iov_base = buf;
	iov->iov_len = len;

	pr_iov->to = iov;
	pr_iov->nr = 1;

	list_add_tail(&pr_iov->l, to);

	return 0;
}

int pagemap_render_iovec(struct list_head *from, struct task_restore_args *ta)
{
	struct page_read_iov *piov;

	ta->vma_ios = (struct restore_vma_io *)rst_mem_align_cpos(RM_PRIVATE);
	ta->vma_ios_n = 0;

	list_for_each_entry(piov, from, l) {
		struct restore_vma_io *rio;

		pr_info("`- render %d iovs (%p:%zd...)\n", piov->nr, piov->to[0].iov_base, piov->to[0].iov_len);
		rio = rst_mem_alloc(RIO_SIZE(piov->nr), RM_PRIVATE);
		if (!rio)
			return -1;

		rio->nr_iovs = piov->nr;
		rio->off = piov->from;
		memcpy(rio->iovs, piov->to, piov->nr * sizeof(struct iovec));

		ta->vma_ios_n++;
	}

	return 0;
}

int pagemap_enqueue_iovec(struct page_read *pr, void *buf, unsigned long len, struct list_head *to)
{
	struct page_read_iov *cur_async = NULL;
	struct iovec *iov;

	if (!list_empty(to))
		cur_async = list_entry(to->prev, struct page_read_iov, l);

	/*
	 * We don't have any async requests or we have new read
	 * request that should happen at pos _after_ some hole from
	 * the previous one.
	 * Start the new preadv request here.
	 */
	if (!cur_async || pr->pi_off != cur_async->end)
		return enqueue_async_iov(pr, buf, len, to);

	/*
	 * This read is pure continuation of the previous one. Let's
	 * just add another IOV (or extend one of the existing).
	 */
	iov = &cur_async->to[cur_async->nr - 1];
	if (iov->iov_base + iov->iov_len == buf) {
		/* Extendable */
		iov->iov_len += len;
	} else {
		/* Need one more target iovec */
		unsigned int n_iovs = cur_async->nr + 1;

		if (n_iovs >= IOV_MAX)
			return enqueue_async_iov(pr, buf, len, to);

		iov = xrealloc(cur_async->to, n_iovs * sizeof(*iov));
		if (!iov)
			return -1;

		cur_async->to = iov;

		iov += cur_async->nr;
		iov->iov_base = buf;
		iov->iov_len = len;

		cur_async->nr = n_iovs;
	}

	cur_async->end += len;

	return 0;
}

static int maybe_read_page_local(struct page_read *pr, unsigned long vaddr, int nr, void *buf, unsigned flags)
{
	int ret;
	unsigned long len = nr * PAGE_SIZE;

	/*
	 * There's no API in the kernel to start asynchronous
	 * cached read (or write), so in case someone is asking
	 * for us for urgent async read, just do the regular
	 * cached read.
	 */
	if ((flags & (PR_ASYNC | PR_ASAP)) == PR_ASYNC)
		ret = pagemap_enqueue_iovec(pr, buf, len, &pr->async);
	else {
		ret = read_local_page(pr, vaddr, len, buf);
		if (ret == 0 && pr->io_complete)
			ret = pr->io_complete(pr, vaddr, nr);
	}

	pr->pi_off += len;

	return ret;
}

/*
 * We cannot use maybe_read_page_local() for streaming images as it uses
 * pread(), seeking in the file. Instead, we use this custom page reader.
 */
static int maybe_read_page_img_streamer(struct page_read *pr, unsigned long vaddr, int nr, void *buf, unsigned flags)
{
	unsigned long len = nr * PAGE_SIZE;
	int fd;
	int ret;
	size_t curr = 0;

	fd = img_raw_fd(pr->pi);
	if (fd < 0) {
		pr_err("Getting raw FD failed\n");
		return -1;
	}

	pr_debug("\tpr%lu-%u Read page from self %lx/%" PRIx64 "\n", pr->img_id, pr->id, pr->cvaddr, pr->pi_off);

	/* We can't seek. The requested address better match */
	BUG_ON(pr->cvaddr != vaddr);

	while (1) {
		ret = read(fd, buf + curr, len - curr);
		if (ret == 0) {
			pr_err("Reached EOF unexpectedly while reading page from image\n");
			return -1;
		} else if (ret < 0) {
			pr_perror("Can't read mapping page %d", ret);
			return -1;
		}
		curr += ret;
		if (curr == len)
			break;
	}

	if (opts.auto_dedup)
		pr_warn_once("Can't dedup when streaming images\n");

	if (pr->io_complete)
		ret = pr->io_complete(pr, vaddr, nr);

	pr->pi_off += len;

	return ret;
}

static int read_page_complete(unsigned long img_id, unsigned long vaddr, int nr_pages, void *priv)
{
	int ret = 0;
	struct page_read *pr = priv;

	if (pr->img_id != img_id) {
		pr_err("Out of order read completed (want %lu have %lu)\n", pr->img_id, img_id);
		return -1;
	}

	if (pr->io_complete)
		ret = pr->io_complete(pr, vaddr, nr_pages);
	else
		pr_warn_once("Remote page read w/o io_complete!\n");

	return ret;
}

/* Forward decl — prefetch_eager_ranges below tests pr->maybe_read_page against this. */
static int maybe_read_page_object_storage(struct page_read *pr, unsigned long vaddr, int nr, void *buf, unsigned flags);

/*
 * =================================================================================
 * Phase 6 M10: Eager-prefetch phase for object-storage-backed page_reads.
 *
 * Motivation: cr-restore's pagemap walk issues synchronous S3 range GETs on
 * the main thread for every PE_PRESENT && !PE_LAZY entry. Measurement on
 * mc-4gb showed this adds up to ~3.6 s of pure serial RTT (49 reads, ~25 ms
 * warm / ~80 ms cold each). We can't change the walk itself (it's part of
 * upstream CRIU's restore structure), but we CAN precompute which byte
 * ranges in pages-N.img will be read and pull them in parallel before the
 * walk starts. The main walk then becomes zero-RTT memcpy-from-buffer.
 * =================================================================================
 */

struct eager_worker_arg {
	const char *object_key;
	off_t file_offset;
	size_t len;
	void *dst;
	int rc;
};

struct eager_ss {
	struct eager_worker_arg *args;
	int total;
	int next;
	pthread_mutex_t lock;
};

static void *eager_drain_worker(void *arg)
{
	struct eager_ss *ss = (struct eager_ss *)arg;
	int idx;

	while (1) {
		pthread_mutex_lock(&ss->lock);
		if (ss->next >= ss->total) {
			pthread_mutex_unlock(&ss->lock);
			break;
		}
		idx = ss->next++;
		pthread_mutex_unlock(&ss->lock);

		ss->args[idx].rc = object_storage_fetch_range(
			ss->args[idx].object_key,
			ss->args[idx].file_offset,
			ss->args[idx].len,
			ss->args[idx].dst,
			OBJSTOR_SRC_PREFETCH);
	}
	return NULL;
}

/*
 * Scan pmes[] once, collect (file_offset, len) for every entry that is
 * PE_PRESENT but NOT PE_LAZY and NOT PE_PARENT. File offset is cumulative
 * over all PE_PRESENT entries in order, mirroring how pi_off advances
 * inside the real walk. Adjacent or small-gap eager ranges are merged
 * into a single GET to minimize per-request overhead. Returns 0 on
 * success with *out_ranges / *out_n / *out_total_bytes populated (caller
 * owns the array).
 */
static int collect_eager_ranges(struct page_read *pr,
				struct eager_range **out_ranges,
				int *out_n, size_t *out_total_bytes)
{
	struct eager_range *arr;
	int cap = 64, n = 0, i;
	off_t cur_off = 0;
	size_t total = 0;
	/* Merge ranges closer than this many bytes into one GET. The
	 * per-request S3 overhead is ~25 ms; any gap smaller than a
	 * few hundred KB is cheaper to pay in extra bytes than in a
	 * second round-trip. */
	const size_t merge_slack = 256 * 1024;

	*out_ranges = NULL;
	*out_n = 0;
	*out_total_bytes = 0;

	arr = xmalloc(cap * sizeof(*arr));
	if (!arr)
		return -1;

	for (i = 0; i < pr->nr_pmes; i++) {
		PagemapEntry *pe = pr->pmes[i];
		size_t len;
		bool eager;

		if (!pagemap_present(pe))
			continue; /* no bytes in current pages-N.img */

		len = pagemap_len(pe);
		eager = !pagemap_lazy(pe) && !pagemap_in_parent(pe);

		if (eager) {
			if (n > 0) {
				struct eager_range *last = &arr[n - 1];
				off_t gap = cur_off - (last->file_offset + last->len);
				if (gap <= (off_t)merge_slack) {
					/* Absorb the gap into the merged range. */
					last->len = (cur_off - last->file_offset) + len;
					cur_off += len;
					continue;
				}
			}
			if (n == cap) {
				struct eager_range *nw;
				cap *= 2;
				nw = xrealloc(arr, cap * sizeof(*arr));
				if (!nw) {
					xfree(arr);
					return -1;
				}
				arr = nw;
			}
			arr[n].file_offset = cur_off;
			arr[n].len = len;
			arr[n].buf_offset = 0; /* assigned after final merge */
			n++;
		}

		cur_off += len;
	}

	/* Assign packed buf_offsets and compute total buffer size. */
	for (i = 0; i < n; i++) {
		arr[i].buf_offset = total;
		total += arr[i].len;
	}

	*out_ranges = arr;
	*out_n = n;
	*out_total_bytes = total;
	return 0;
}

/*
 * Call once at open_page_read_at time, right after init_pagemaps. Collects
 * eager ranges, allocates a packed buffer, parallel-fetches every range
 * with a small worker pool, and stores the result in pr->eager_buf. On
 * any failure the buffer is freed and eager_buf stays NULL — the page_read
 * then falls through to the existing read-ahead / direct fetch paths with
 * no correctness regression.
 */
static int prefetch_eager_ranges(struct page_read *pr)
{
	struct eager_range *ranges = NULL;
	int nr_ranges = 0;
	size_t total_bytes = 0;
	char object_key[PATH_MAX];
	char image_name[64];
	const char *prefix;
	int nw, i, created;
	pthread_t *tids = NULL;
	struct eager_worker_arg *args = NULL;
	struct timespec t0, t1;
	double wall_ms;

	/* Only applies to object-storage page_reads */
	if (!opts.enable_object_storage || pr->maybe_read_page != maybe_read_page_object_storage)
		return 0;

	/*
	 * Compressed mode routes every read through decompress_range(), which
	 * has its own internal seek-table-aware caching. The eager prefetch
	 * buffer assumes byte offsets into a raw file, so skip it.
	 */
	if (pr->compressed_mode)
		return 0;

	if (collect_eager_ranges(pr, &ranges, &nr_ranges, &total_bytes) != 0)
		return -1;

	if (nr_ranges == 0 || total_bytes == 0) {
		if (ranges)
			xfree(ranges);
		return 0;
	}

	/* Skip prefetch if the total is too small to be worth the worker
	 * pool overhead. The per-page_read ra_buf window already handles
	 * tiny workloads well. */
	if (total_bytes < (256UL * 1024)) {
		xfree(ranges);
		return 0;
	}

	pr_info("eager prefetch: %d ranges, %lu bytes total\n",
		nr_ranges, (unsigned long)total_bytes);

	pr->eager_buf = xmalloc(total_bytes);
	if (!pr->eager_buf) {
		pr_warn("eager prefetch: xmalloc(%lu) failed, skipping\n",
			(unsigned long)total_bytes);
		xfree(ranges);
		return 0;
	}
	pr->eager_buf_cap = total_bytes;
	pr->eager_ranges = ranges;
	pr->nr_eager_ranges = nr_ranges;

	/* Build the full object key (matching maybe_read_page_object_storage) */
	snprintf(image_name, sizeof(image_name), "pages-%u.img", pr->pages_img_id);
	prefix = pr->object_storage_prefix ? pr->object_storage_prefix : opts.object_storage_object_prefix;
	if (prefix && strlen(prefix) > 0)
		snprintf(object_key, sizeof(object_key), "%s%s", prefix, image_name);
	else
		snprintf(object_key, sizeof(object_key), "%s", image_name);

	/* Worker count: same reasoning as obstor_prefetch — tiny number of
	 * threads to avoid the libcurl/OpenSSL TLS-handshake serialization
	 * pathology we hit before. 4 is the sweet spot on m5.8xlarge. */
	nw = nr_ranges;
	if (nw > 4)
		nw = 4;

	tids = xmalloc(nw * sizeof(pthread_t));
	args = xmalloc(nr_ranges * sizeof(*args));
	if (!tids || !args) {
		if (tids)
			xfree(tids);
		if (args)
			xfree(args);
		xfree(pr->eager_buf);
		pr->eager_buf = NULL;
		pr->eager_buf_cap = 0;
		xfree(pr->eager_ranges);
		pr->eager_ranges = NULL;
		pr->nr_eager_ranges = 0;
		return 0;
	}

	/* Prepare all work items (fixed object_key pointer — it outlives
	 * the join). */
	for (i = 0; i < nr_ranges; i++) {
		args[i].object_key = object_key;
		args[i].file_offset = ranges[i].file_offset;
		args[i].len = ranges[i].len;
		args[i].dst = (char *)pr->eager_buf + ranges[i].buf_offset;
		args[i].rc = -1;
	}

	clock_gettime(CLOCK_MONOTONIC, &t0);

	{
		struct eager_ss ss;
		ss.args = args;
		ss.total = nr_ranges;
		ss.next = 0;
		pthread_mutex_init(&ss.lock, NULL);

		created = 0;
		for (i = 0; i < nw; i++) {
			if (pthread_create(&tids[i], NULL, eager_drain_worker, &ss) != 0) {
				pr_warn("eager prefetch: pthread_create %d failed\n", i);
				break;
			}
			created++;
		}

		if (created == 0) {
			/* Drain on main thread as last-resort fallback */
			int idx;
			for (idx = 0; idx < nr_ranges; idx++) {
				args[idx].rc = object_storage_fetch_range(
					args[idx].object_key,
					args[idx].file_offset,
					args[idx].len,
					args[idx].dst,
					OBJSTOR_SRC_PREFETCH);
			}
		} else {
			for (i = 0; i < created; i++)
				pthread_join(tids[i], NULL);
		}

		pthread_mutex_destroy(&ss.lock);
	}

	clock_gettime(CLOCK_MONOTONIC, &t1);
	wall_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;

	/* Check all worker return codes; on any failure, disable eager_buf. */
	for (i = 0; i < nr_ranges; i++) {
		if (args[i].rc != 0) {
			pr_warn("eager prefetch: range %d (off=%ld len=%lu) failed (rc=%d), "
				"disabling eager_buf\n",
				i, (long)args[i].file_offset, (unsigned long)args[i].len,
				args[i].rc);
			xfree(pr->eager_buf);
			pr->eager_buf = NULL;
			pr->eager_buf_cap = 0;
			xfree(pr->eager_ranges);
			pr->eager_ranges = NULL;
			pr->nr_eager_ranges = 0;
			break;
		}
	}

	if (pr->eager_buf)
		pr_info("eager prefetch: %d ranges, %lu bytes in %.1f ms (%.1f MB/s)\n",
			nr_ranges, (unsigned long)total_bytes, wall_ms,
			(total_bytes / 1024.0 / 1024.0) / (wall_ms / 1000.0));

	xfree(tids);
	xfree(args);

	return 0;
}

/*
 * Look up a (pi_off, len) read in the eager buffer. Returns 0 and serves
 * the data via memcpy if the range is fully contained in any eager_range.
 * Returns -1 on miss (caller falls through to other paths).
 */
static int eager_buf_lookup(struct page_read *pr, void *buf, size_t len)
{
	int i;

	if (!pr->eager_buf || pr->nr_eager_ranges == 0)
		return -1;

	for (i = 0; i < pr->nr_eager_ranges; i++) {
		struct eager_range *r = &pr->eager_ranges[i];
		if (pr->pi_off >= r->file_offset &&
		    pr->pi_off + (off_t)len <= r->file_offset + (off_t)r->len) {
			size_t rel = (size_t)(pr->pi_off - r->file_offset);
			memcpy(buf, (char *)pr->eager_buf + r->buf_offset + rel, len);
			return 0;
		}
	}
	return -1;
}

/* Function to read page data from Object Storage */
static int maybe_read_page_object_storage(struct page_read *pr, unsigned long vaddr, int nr, void *buf, unsigned flags)
{
	int ret;
	unsigned long len = nr * PAGE_SIZE;
	char object_key[PATH_MAX];
	char image_name[64];

	/* Construct the dynamic image name using pages_img_id */
	snprintf(image_name, sizeof(image_name), "pages-%u.img", pr->pages_img_id);

	pr_info("Object Storage: Reading %d pages (len: %lu) from %s at offset %lu for vaddr %lx\n",
	        nr, len, image_name, pr->pi_off, vaddr);

	/* Construct the object key: use per-page_read prefix if set, else global */
	{
		const char *prefix = pr->object_storage_prefix ? pr->object_storage_prefix : opts.object_storage_object_prefix;
		if (prefix && strlen(prefix) > 0) {
			snprintf(object_key, sizeof(object_key), "%s%s", prefix, image_name);
		} else {
			snprintf(object_key, sizeof(object_key), "%s", image_name);
		}
	}

	/*
	 * Phase 6 M10: eager-prefetch buffer fast path.
	 *
	 * If prefetch_eager_ranges() already pulled this byte range in a
	 * parallel wave at open_page_read_at time, serve directly from
	 * memory — zero S3 RTT. Miss falls through to the ra_buf window
	 * and then to the direct-fetch path.
	 */
	if (eager_buf_lookup(pr, buf, len) == 0) {
		pr_debug("Object Storage: eager_buf HIT pi_off=%lu len=%lu\n",
			 (unsigned long)pr->pi_off, len);
		ret = 0;
		if (pr->io_complete) {
			ret = pr->io_complete(pr, vaddr, nr);
			if (ret < 0)
				pr_err("Object Storage: io_complete failed (eager hit) for vaddr %lx\n",
				       vaddr);
		}
		pr->pi_off += len;
		return ret;
	}

	/*
	 * Phase 6: per-page_read read-ahead fast path.
	 *
	 * cr-restore's eager pagemap walk issues many small sequential
	 * reads against the same pages-N.img. pi_off advances monotonically
	 * inside one page_read instance, so a contiguous in-memory window
	 * over [ra_start, ra_start + ra_len) absorbs subsequent reads with
	 * zero S3 GETs as long as they fit. On a miss we refill the window
	 * with a single GET of size max(len, ra_cap) starting at the
	 * current pi_off.
	 *
	 * io_complete and pi_off advance happen exactly as in the slow
	 * path — the buffer is purely a transport optimization. No file
	 * is created on the local filesystem; the buffer lives only as
	 * long as this page_read.
	 */
	if (pr->ra_cap > 0) {
		off_t hit_lo = pr->pi_off;
		off_t hit_hi = pr->pi_off + (off_t)len;

		/* Fast path: requested range is already inside the window. */
		if (pr->ra_len > 0 && hit_lo >= pr->ra_start &&
		    hit_hi <= pr->ra_start + (off_t)pr->ra_len) {
			memcpy(buf, (char *)pr->ra_buf + (hit_lo - pr->ra_start), len);
			pr_debug("Object Storage: read-ahead HIT pi_off=%lu len=%lu "
				 "(window [%ld..%ld])\n",
				 (unsigned long)pr->pi_off, len,
				 (long)pr->ra_start, (long)(pr->ra_start + pr->ra_len));
			ret = 0;
			if (pr->io_complete) {
				ret = pr->io_complete(pr, vaddr, nr);
				if (ret < 0) {
					pr_err("Object Storage: io_complete failed (ra hit) for vaddr %lx\n",
					       vaddr);
				}
			}
			pr->pi_off += len;
			return ret;
		}

		/*
		 * Miss: refill the window. Fetch max(len, ra_cap) bytes
		 * starting at pi_off into ra_buf, then copy the prefix the
		 * caller asked for. If the caller's request is larger than
		 * the window we still satisfy it by issuing a single
		 * GET-into-ra_buf of len bytes — an oversized request can
		 * still be served, the only loss is no future read-ahead
		 * benefit until the next refill.
		 */
		{
			size_t window = pr->ra_cap;
			if (window < len)
				window = len;
			if (window > pr->ra_cap) {
				/*
				 * Caller wants more than our buffer can hold.
				 * Fall back to the original direct-fetch path
				 * for THIS call only; leave the read-ahead
				 * window untouched so it can still serve the
				 * NEXT call.
				 */
				pr_debug("Object Storage: read-ahead bypass (len=%lu > ra_cap=%lu)\n",
					 len, pr->ra_cap);
				goto direct_fetch;
			}
			ret = object_storage_fetch_range(object_key, pr->pi_off, window,
							 pr->ra_buf, OBJSTOR_SRC_FAULT);
			if (ret == 0) {
				pr->ra_start = pr->pi_off;
				pr->ra_len = window;
				memcpy(buf, pr->ra_buf, len);
				pr_debug("Object Storage: read-ahead REFILL "
					 "pi_off=%lu window=%lu (consumed %lu)\n",
					 (unsigned long)pr->pi_off, (unsigned long)window, len);
				if (pr->io_complete) {
					ret = pr->io_complete(pr, vaddr, nr);
					if (ret < 0) {
						pr_err("Object Storage: io_complete failed (ra refill) "
						       "for vaddr %lx\n", vaddr);
					}
				}
				pr->pi_off += len;
				return ret;
			}
			/*
			 * Window fetch failed. The most common cause is a
			 * short read near the end of pages-*.img (S3 returns
			 * fewer bytes than we asked for because we overshot
			 * EOF). Disable further read-ahead on this page_read
			 * so we don't re-pay the same futile refill cost for
			 * every subsequent read — fall through to direct
			 * fetch which asks for the caller's exact `len`.
			 */
			pr->ra_len = 0;
			pr->ra_cap = 0;
			pr_warn("Object Storage: read-ahead refill failed (ret=%d), "
				"disabling read-ahead for this page_read\n", ret);
		}
	}

direct_fetch:
	/*
	 * Compressed path: pi_off is an uncompressed offset, so ask the
	 * seekable decoder to produce the raw bytes for us. It will issue
	 * its own compressed Range GETs via the s3_decomp_read_cb wired up
	 * in init_s3_compression().
	 */
	if (pr->compressed_mode && pr->decompress) {
		ret = decompress_range(pr->decompress, pr->pi_off, len, buf);
		if (ret == 0) {
			if (pr->io_complete) {
				ret = pr->io_complete(pr, vaddr, nr);
				if (ret < 0)
					pr_err("Object Storage(compressed): io_complete failed for vaddr %lx\n",
					       vaddr);
			}
		} else {
			pr_err("Object Storage(compressed): decompress_range(off=%lu len=%lu) failed\n",
			       pr->pi_off, len);
		}
		pr->pi_off += len;
		return ret;
	}

	/* Fetch data from object storage (fault-driven path: lazy-pages
	 * daemon is reactively pulling pages for an outstanding UFFD fault). */
	ret = object_storage_fetch_range(object_key, pr->pi_off, len, buf, OBJSTOR_SRC_FAULT);

	if (ret == 0) {
		pr_debug("Object Storage: Fetch successful for offset %lu\n", pr->pi_off);
		/* Call io_complete callback if read was successful */
		if (pr->io_complete) {
			ret = pr->io_complete(pr, vaddr, nr);
			if (ret < 0) {
				pr_err("Object Storage: io_complete callback failed for vaddr %lx\n", vaddr);
			}
		}
	} else {
		pr_err("Object Storage: Failed to fetch range for object '%s', offset %lu, len %lu (ret: %d)\n",
		       object_key, pr->pi_off, len, ret);
	}

	/* Always advance the offset */
	pr->pi_off += len;

	return ret;
}

static int maybe_read_page_remote(struct page_read *pr, unsigned long vaddr, int nr, void *buf, unsigned flags)
{
	int ret;

	/* We always do PR_ASAP mode here (FIXME?) */
	ret = request_remote_pages(pr->img_id, vaddr, nr);
	if (!ret)
		ret = page_server_start_read(buf, nr, read_page_complete, pr, flags);
	return ret;
}

static int read_pagemap_page(struct page_read *pr, unsigned long vaddr, int nr, void *buf, unsigned flags)
{
	pr_info("pr%lu-%u Read %lx %u pages\n", pr->img_id, pr->id, vaddr, nr);
	pagemap_bound_check(pr->pe, vaddr, nr);

	if (pagemap_in_parent(pr->pe)) {
		if (read_parent_page(pr, vaddr, nr, buf, flags) < 0)
			return -1;
	} else {
		if (pr->maybe_read_page(pr, vaddr, nr, buf, flags) < 0)
			return -1;
	}

	pr->cvaddr += nr * PAGE_SIZE;

	return 1;
}

static void free_pagemaps(struct page_read *pr)
{
	int i;

	for (i = 0; i < pr->nr_pmes; i++)
		pagemap_entry__free_unpacked(pr->pmes[i], NULL);

	xfree(pr->pmes);
	pr->pmes = NULL;
}

static void advance_piov(struct page_read_iov *piov, ssize_t len)
{
	ssize_t olen = len;
	int onr = piov->nr;
	piov->from += len;

	while (len) {
		struct iovec *cur = piov->to;

		if (cur->iov_len <= len) {
			piov->to++;
			piov->nr--;
			len -= cur->iov_len;
			continue;
		}

		cur->iov_base += len;
		cur->iov_len -= len;
		break;
	}

	pr_debug("Advanced iov %zu bytes, %d->%d iovs, %zu tail\n", olen, onr, piov->nr, len);
}

static int process_async_reads(struct page_read *pr)
{
	int fd, ret = 0;
	struct page_read_iov *piov, *n;

	/* Handle NULL pr->pi for object storage mode */
	if (!pr->pi) {
		if (list_empty(&pr->async))
			return 0;
		pr_warn("Async reads requested but no pages image file available\n");
		return 0;
	}

	fd = img_raw_fd(pr->pi);
	list_for_each_entry_safe(piov, n, &pr->async, l) {
		ssize_t ret;
		struct iovec *iovs = piov->to;

		pr_debug("Read piov iovs %d, from %ju, len %ju, first %p:%zu\n", piov->nr, piov->from,
			 piov->end - piov->from, piov->to->iov_base, piov->to->iov_len);
	more:
		ret = preadv(fd, piov->to, piov->nr, piov->from);
		if (fault_injected(FI_PARTIAL_PAGES)) {
			/*
			 * We might have read everything, but for debug
			 * purposes let's try to force the advance_piov()
			 * and re-read tail.
			 */
			if (ret > 0 && piov->nr >= 2) {
				pr_debug("`- trim preadv %zu\n", ret);
				ret /= 2;
			}
		}

		if (ret < 0) {
			pr_err("Can't read async pr bytes (%zd / %ju read, %ju off, %d iovs)\n", ret,
			       piov->end - piov->from, piov->from, piov->nr);
			return -1;
		}

		if (opts.auto_dedup && punch_hole(pr, piov->from, ret, false))
			return -1;

		if (ret != piov->end - piov->from) {
			/*
			 * The preadv() can return less than requested. It's
			 * valid and doesn't mean error or EOF. We should advance
			 * the iovecs and continue
			 *
			 * Modify the piov in-place, we're going to drop this one
			 * anyway.
			 */

			advance_piov(piov, ret);
			goto more;
		}

		BUG_ON(pr->io_complete); /* FIXME -- implement once needed */

		list_del(&piov->l);
		xfree(iovs);
		xfree(piov);
	}

	if (pr->parent)
		ret = process_async_reads(pr->parent);

	return ret;
}

static void close_page_read(struct page_read *pr)
{
	int ret;

	BUG_ON(!list_empty(&pr->async));

	if (pr->bunch.iov_len > 0) {
		ret = punch_hole(pr, 0, 0, true);
		if (ret == -1)
			return;

		pr->bunch.iov_len = 0;
	}

	if (pr->parent) {
		close_page_read(pr->parent);
		xfree(pr->parent);
	}

	if (pr->pmi)
		close_image(pr->pmi);
	if (pr->pi)
		close_image(pr->pi);

	if (pr->pmes)
		free_pagemaps(pr);

	/*
	 * Free the zstd seekable decompressor first (it holds a pointer
	 * into ra_buf when compressed_mode is set).
	 */
	if (pr->decompress) {
		decompress_free(pr->decompress);
		pr->decompress = NULL;
		pr->compressed_mode = false;
	}
	if (pr->decompress_cookie) {
		xfree(pr->decompress_cookie);
		pr->decompress_cookie = NULL;
	}

	/* Phase 6: object-storage read-ahead buffer (per-page_read) */
	if (pr->ra_buf) {
		xfree(pr->ra_buf);
		pr->ra_buf = NULL;
		pr->ra_start = 0;
		pr->ra_len = 0;
		pr->ra_cap = 0;
	}

	/* Phase 6 M10: eager-prefetch buffer (per-page_read) */
	if (pr->eager_buf) {
		xfree(pr->eager_buf);
		pr->eager_buf = NULL;
		pr->eager_buf_cap = 0;
	}
	if (pr->eager_ranges) {
		xfree(pr->eager_ranges);
		pr->eager_ranges = NULL;
		pr->nr_eager_ranges = 0;
	}
}

static void reset_pagemap(struct page_read *pr)
{
	pr->cvaddr = 0;
	pr->pi_off = 0;
	pr->curr_pme = -1;
	pr->pe = NULL;

	/* FIXME: take care of bunch */

	if (pr->parent)
		reset_pagemap(pr->parent);
}

static int try_open_parent(int dfd, unsigned long id, struct page_read *pr, int pr_flags)
{
	int pfd, ret;
	struct page_read *parent = NULL;

	/* Image streaming lacks support for incremental images */
	if (opts.stream)
		goto out;

	if (open_parent(dfd, &pfd))
		goto err;
	if (pfd < 0) {
		/*
		 * No local parent symlink. Try to reconstruct from
		 * parent-prefix file (present when downloaded from S3).
		 */
		int ppfd;
		ppfd = openat(dfd, "parent-prefix", O_RDONLY);
		if (ppfd >= 0) {
			char pp_buf[1024];
			ssize_t nr;
			nr = read(ppfd, pp_buf, sizeof(pp_buf) - 1);
			close(ppfd);
			if (nr > 0) {
				char *last_slash;
				char *dir_name;
				char symtgt[1024];

				pp_buf[nr] = '\0';
				while (nr > 0 && (pp_buf[nr-1] == '/' || pp_buf[nr-1] == '\n'))
					pp_buf[--nr] = '\0';
				last_slash = strrchr(pp_buf, '/');
				dir_name = last_slash ? last_slash + 1 : pp_buf;
				snprintf(symtgt, sizeof(symtgt), "../%.1020s", dir_name);

				if (faccessat(dfd, symtgt, R_OK, 0) == 0) {
					if (symlinkat(symtgt, dfd, CR_PARENT_LINK) == 0 || errno == EEXIST) {
						pr_info("Reconstructed parent symlink in sub-dir: %s\n", symtgt);
						/* Retry open_parent */
						if (open_parent(dfd, &pfd) == 0 && pfd >= 0)
							goto have_parent;
					}
				}
			}
		}

		/*
		 * Still no parent. If object storage is enabled,
		 * try to fetch parent-prefix marker from S3 and set up
		 * parent page_read with the parent's S3 prefix.
		 */
		if (opts.enable_object_storage) {
			void *prefix_data = NULL;
			unsigned long prefix_len = 0;
			int s3_ret;
			char *parent_prefix;
			char *tmpdir;
			int tfd;

			s3_ret = object_storage_get_object("parent-prefix",
							   &prefix_data, &prefix_len);
			if (s3_ret != 0 || !prefix_data || prefix_len == 0) {
				if (prefix_data)
					free(prefix_data);
				pr_debug("No parent-prefix on S3, no parent chain\n");
				goto out;
			}

			/* Null-terminate the prefix */
			parent_prefix = xmalloc(prefix_len + 1);
			if (!parent_prefix) {
				free(prefix_data);
				goto out;
			}
			memcpy(parent_prefix, prefix_data, prefix_len);
			parent_prefix[prefix_len] = '\0';
			free(prefix_data);

			pr_info("Found parent prefix on S3: %s\n", parent_prefix);

			/*
			 * Create a tmpdir and fetch parent metadata from S3.
			 * We temporarily swap the global prefix to parent prefix,
			 * open page_read (which triggers S3 fallback for metadata),
			 * then restore the original prefix.
			 */
			tmpdir = xstrdup("/tmp/criu-parent-XXXXXX");
			if (!tmpdir || !mkdtemp(tmpdir)) {
				xfree(parent_prefix);
				xfree(tmpdir);
				goto out;
			}

			tfd = open(tmpdir, O_RDONLY | O_DIRECTORY);
			if (tfd < 0) {
				xfree(parent_prefix);
				xfree(tmpdir);
				goto out;
			}

			parent = xmalloc(sizeof(*parent));
			if (!parent) {
				close(tfd);
				xfree(parent_prefix);
				xfree(tmpdir);
				goto out;
			}

			/* Swap prefix to parent's, open page_read, restore */
			{
				char *saved_prefix = opts.object_storage_object_prefix;
				opts.object_storage_object_prefix = parent_prefix;
				ret = open_page_read_at(tfd, id, parent, pr_flags);
				opts.object_storage_object_prefix = saved_prefix;
			}

			close(tfd);

			if (ret <= 0) {
				pr_debug("Could not open parent page_read from S3\n");
				xfree(parent);
				parent = NULL;
			} else {
				/* Set per-page_read prefix for parent pages fetch */
				parent->object_storage_prefix = parent_prefix;
				parent_prefix = NULL; /* ownership transferred */
			}

			if (parent_prefix)
				xfree(parent_prefix);

			/* Clean up tmpdir (files are in memfd, not on disk) */
			rmdir(tmpdir);
			xfree(tmpdir);
		}
		goto out;
	}

have_parent:
	parent = xmalloc(sizeof(*parent));
	if (!parent)
		goto err_cl;

	ret = open_page_read_at(pfd, id, parent, pr_flags);
	if (ret < 0)
		goto err_free;

	if (!ret) {
		xfree(parent);
		parent = NULL;
	}

	close(pfd);
out:
	pr->parent = parent;
	return 0;

err_free:
	xfree(parent);
err_cl:
	close(pfd);
err:
	return -1;
}

static void init_compat_pagemap_entry(PagemapEntry *pe)
{
	/*
	 * pagemap image generated with older version will either
	 * contain a hole because the pages are in the parent
	 * snapshot or a pagemap that should be marked with
	 * PE_PRESENT
	 */
	if (pe->has_in_parent && pe->in_parent)
		pe->flags |= PE_PARENT;
	else if (!pe->has_flags)
		pe->flags = PE_PRESENT;
}

/*
 * The pagemap entry size is at least 8 bytes for small mappings with
 * low address and may get to 18 bytes or even more for large mappings
 * with high address and in_parent flag set. 16 seems to be nice round
 * number to minimize {over,under}-allocations
 */
#define PAGEMAP_ENTRY_SIZE_ESTIMATE 16

static int init_pagemaps(struct page_read *pr)
{
	off_t fsize;
	int nr_pmes, nr_realloc;

	if (opts.stream) {
		/*
		 * TODO - There is no easy way to estimate the size of the
		 * pagemap that is still to be read from the pipe. Possible
		 * solution is to ask the image streamer for the size of the
		 * image. 1024 is a wild guess (more space is allocated if
		 * needed).
		 */
		fsize = 1024;
	} else {
		fsize = img_raw_size(pr->pmi);
	}

	if (fsize < 0)
		return -1;

	nr_pmes = fsize / PAGEMAP_ENTRY_SIZE_ESTIMATE + 1;
	nr_realloc = nr_pmes / 2;

	pr->pmes = xzalloc(nr_pmes * sizeof(*pr->pmes));
	if (!pr->pmes)
		return -1;

	pr->nr_pmes = 0;
	pr->curr_pme = -1;

	while (1) {
		int ret = pb_read_one_eof(pr->pmi, &pr->pmes[pr->nr_pmes], PB_PAGEMAP);
		if (ret < 0)
			goto free_pagemaps;
		if (ret == 0)
			break;

		init_compat_pagemap_entry(pr->pmes[pr->nr_pmes]);

		pr->nr_pmes++;
		if (pr->nr_pmes >= nr_pmes) {
			PagemapEntry **new;
			nr_pmes += nr_realloc;
			new = xrealloc(pr->pmes, nr_pmes * sizeof(*pr->pmes));
			if (!new)
				goto free_pagemaps;
			pr->pmes = new;
		}
	}

	close_image(pr->pmi);
	pr->pmi = NULL;

	return 0;

free_pagemaps:
	free_pagemaps(pr);
	return -1;
}

int open_page_read_at(int dfd, unsigned long img_id, struct page_read *pr, int pr_flags)
{
	int flags, i_typ;
	static unsigned ids = 1;
	bool remote = pr_flags & PR_REMOTE;

	/*
	 * Only the top-most page-read can be remote, all the
	 * others are always local.
	 */
	pr_flags &= ~PR_REMOTE;
	if (opts.auto_dedup)
		pr_flags |= PR_MOD;
	if (pr_flags & PR_MOD)
		flags = O_RDWR;
	else
		flags = O_RSTR;

	switch (pr_flags & PR_TYPE_MASK) {
	case PR_TASK:
		i_typ = CR_FD_PAGEMAP;
		break;
	case PR_SHMEM:
		i_typ = CR_FD_SHMEM_PAGEMAP;
		break;
	default:
		BUG();
		return -1;
	}

	INIT_LIST_HEAD(&pr->async);
	pr->pe = NULL;
	pr->parent = NULL;
	pr->object_storage_prefix = NULL;
	pr->cvaddr = 0;
	pr->pi_off = 0;
	pr->bunch.iov_len = 0;
	pr->bunch.iov_base = NULL;
	pr->pmes = NULL;
	pr->pieok = false;
	pr->disable_dedup = false;
	pr->ra_buf = NULL;
	pr->ra_start = 0;
	pr->ra_len = 0;
	pr->ra_cap = 0;
	pr->eager_buf = NULL;
	pr->eager_buf_cap = 0;
	pr->eager_ranges = NULL;
	pr->nr_eager_ranges = 0;

	pr->pmi = open_image_at(dfd, i_typ, O_RSTR, img_id);
	if (!pr->pmi)
		return -1;

	if (empty_image(pr->pmi)) {
		close_image(pr->pmi);
		return 0;
	}

	if (try_open_parent(dfd, img_id, pr, pr_flags)) {
		close_image(pr->pmi);
		return -1;
	}

	pr->pi = open_pages_image_at(dfd, flags, pr->pmi, &pr->pages_img_id);
	if (!pr->pi || (pr->pi && empty_image(pr->pi))) {
		/* If object storage is enabled, we don't need local pages.img */
		if (opts.enable_object_storage) {
			pr_info("No local pages-%u.img, using object storage mode.\n",
			        pr->pages_img_id);
			if (pr->pi) {
				close_image(pr->pi);
				pr->pi = NULL;
			}
		} else if (!pr->pi) {
			pr_err("Failed to open pages image (id: %u)\n", pr->pages_img_id);
			close_page_read(pr);
			return -1;
		}
	}

	if (init_pagemaps(pr)) {
		close_page_read(pr);
		return -1;
	}

	pr->read_pages = read_pagemap_page;
	pr->advance = advance;
	pr->close = close_page_read;
	pr->skip_pages = skip_pagemap_pages;
	pr->sync = process_async_reads;
	pr->seek_pagemap = seek_pagemap;
	pr->reset = reset_pagemap;
	pr->io_complete = NULL; /* set up by the client if needed */
	pr->id = ids++;
	pr->img_id = img_id;

	/* Determine the correct page reading function */
	if (remote) {
		pr->maybe_read_page = maybe_read_page_remote;
	} else if (opts.stream) {
		pr->maybe_read_page = maybe_read_page_img_streamer;
	} else if (opts.enable_object_storage) {
		/* Object Storage: fetch pages from S3/MinIO/compatible storage */
		char probe_key[PATH_MAX];
		char probe_image_name[64];
		const char *probe_prefix;

		pr_info("Assigning maybe_read_page_object_storage (lazy_pages: %d, enable_object_storage: %d)\n",
		        opts.lazy_pages, opts.enable_object_storage);
		pr->maybe_read_page = maybe_read_page_object_storage;
		pr->pieok = false;

		/*
		 * Probe the pages-*.img tail for the zstd seekable magic; if
		 * present, wire up pr->decompress so every maybe_read_page
		 * call runs through decompress_range instead of a raw range
		 * fetch.
		 */
		snprintf(probe_image_name, sizeof(probe_image_name),
			 "pages-%u.img", pr->pages_img_id);
		probe_prefix = pr->object_storage_prefix ? pr->object_storage_prefix
							 : opts.object_storage_object_prefix;
		if (probe_prefix && strlen(probe_prefix) > 0)
			snprintf(probe_key, sizeof(probe_key), "%s%s",
				 probe_prefix, probe_image_name);
		else
			snprintf(probe_key, sizeof(probe_key), "%s",
				 probe_image_name);
		if (init_s3_compression(pr, probe_key) < 0)
			return -1;

		/*
		 * Phase 6: per-page_read read-ahead buffer.
		 *
		 * cr-restore's eager pagemap walk hits maybe_read_page_object_storage()
		 * with many small (1–37 page) sequential requests against the same
		 * pages-N.img. Without this buffer each call pays one S3 RTT
		 * (~25 ms same-region, ~80 ms cold). The buffer absorbs subsequent
		 * reads inside the same window — pi_off advances monotonically
		 * inside one page_read, so a large window covers a long burst of
		 * nearby small reads with a single refill. We use 16 MB here —
		 * a 4 MB window showed only 35% HIT rate because real pagemap
		 * walks hop across regions larger than 4 MB before coming back.
		 * At 16 MB the expected HIT rate is 70%+ and the extra memory
		 * cost is negligible (16 MB × per-task page_reads ≪ a typical
		 * workload's actual memory).
		 *
		 * Allocation is best-effort. If xmalloc fails, ra_cap stays 0 and
		 * the per-call fast path falls through to the existing
		 * single-fetch code unchanged.
		 */
		/*
		 * Compressed images route reads through decompress_range(),
		 * which uses the seekable decoder's own internal caching. No
		 * point allocating a 16 MB raw-byte read-ahead window on top.
		 */
		if (pr->compressed_mode) {
			pr->ra_cap = 0;
			pr->ra_buf = NULL;
		} else {
			pr->ra_cap = 16UL << 20; /* 16 MB */
			pr->ra_buf = xmalloc(pr->ra_cap);
			if (!pr->ra_buf) {
				pr_warn("page_read[%u]: read-ahead buffer alloc failed; "
					"falling back to per-call S3 fetches\n", pr->id);
				pr->ra_cap = 0;
			}
		}
		pr->ra_start = 0;
		pr->ra_len = 0;

		/*
		 * Phase 6 M10: eager prefetch. Kick off a short parallel
		 * fetch wave for all non-lazy PE_PRESENT entries so the
		 * main pagemap walk serves them from memory.
		 */
		prefetch_eager_ranges(pr);
	} else {
		/* Default to local file reading */
		pr_info("Assigning maybe_read_page_local (lazy_pages: %d, enable_object_storage: %d)\n",
		        opts.lazy_pages, opts.enable_object_storage);
		pr->maybe_read_page = maybe_read_page_local;

		/*
		 * Auto-detect zstd seekable format: the last 4 bytes of a
		 * seekable file are the seek-table magic (0x8F92EAB1). If we
		 * see it, slurp the whole pages-*.img into memory and hand it
		 * to decompress_create_from_buffer. Small enough to keep in
		 * RAM for local restore; the S3 restore path uses the lazy
		 * callback flavor to avoid that requirement.
		 */
		if (init_local_compression(pr) < 0)
			return -1;

		/*
		 * pieok lets parasite engine pread() raw page bytes directly
		 * out of pages-*.img — we can't do that on a compressed file
		 * because the parasite runs in restored-process context and
		 * doesn't link zstd. Force pages through the userspace path
		 * (maybe_read_page_local -> read_local_page -> decompress)
		 * whenever the image is compressed.
		 */
		if (!pr->parent && !opts.lazy_pages && !pr->compressed_mode)
			pr->pieok = true;
		else
			pr->pieok = false;
	}

	pr_debug("Opened %s page read %u (parent %u)\n", remote ? "remote" : "local", pr->id,
		 pr->parent ? pr->parent->id : 0);

	return 1;
}

int open_page_read(unsigned long img_id, struct page_read *pr, int pr_flags)
{
	return open_page_read_at(get_service_fd(IMG_FD_OFF), img_id, pr, pr_flags);
}

#define DUP_IDS_BASE 1000

void page_read_disable_dedup(struct page_read *pr)
{
	pr_debug("disable dedup, id: %d\n", pr->id);
	pr->disable_dedup = true;
	if (pr->parent)
		page_read_disable_dedup(pr->parent);
}

void dup_page_read(struct page_read *src, struct page_read *dst)
{
	static int dup_ids = 1;

	memcpy(dst, src, sizeof(*dst));
	INIT_LIST_HEAD(&dst->async);
	dst->id = src->id + DUP_IDS_BASE * dup_ids++;
	dst->reset(dst);
}
