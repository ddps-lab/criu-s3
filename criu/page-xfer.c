#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/falloc.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>

#undef LOG_PREFIX
#define LOG_PREFIX "page-xfer: "

#include "types.h"
#include "cr_options.h"
#include "servicefd.h"
#include "image.h"
#include "page-xfer.h"
#include "page-pipe.h"
#include "object-storage.h"
#include "compression.h"
#include "compress_pipeline.h"
#include "upload_pool.h"
#include "auto_nic.h"
#include "util.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"
#include "fcntl.h"
#include "pstree.h"
#include "parasite-syscall.h"
#include "rst_info.h"
#include "stats.h"
#include "tls.h"

static int page_server_sk = -1;

struct page_server_iov {
	u32 cmd;
	u32 nr_pages;
	u64 vaddr;
	u64 dst_id;
};

static void psi2iovec(struct page_server_iov *ps, struct iovec *iov)
{
	iov->iov_base = decode_pointer(ps->vaddr);
	iov->iov_len = ps->nr_pages * PAGE_SIZE;
}

#define PS_IOV_ADD    1
#define PS_IOV_HOLE   2
#define PS_IOV_OPEN   3
#define PS_IOV_OPEN2  4
#define PS_IOV_PARENT 5
#define PS_IOV_ADD_F  6
#define PS_IOV_GET    7

#define PS_IOV_CLOSE	   0x1023
#define PS_IOV_FORCE_CLOSE 0x1024

#define PS_CMD_BITS 16
#define PS_CMD_MASK ((1 << PS_CMD_BITS) - 1)

#define PS_TYPE_BITS 8
#define PS_TYPE_MASK ((1 << PS_TYPE_BITS) - 1)

#define PS_TYPE_PID   (1)
#define PS_TYPE_SHMEM (2)
/*
 * XXX: When adding new types here check decode_pm for legacy
 * numbers that can be met from older CRIUs
 */

static inline u64 encode_pm(int type, unsigned long id)
{
	if (type == CR_FD_PAGEMAP)
		type = PS_TYPE_PID;
	else if (type == CR_FD_SHMEM_PAGEMAP)
		type = PS_TYPE_SHMEM;
	else {
		BUG();
		return 0;
	}

	return ((u64)id) << PS_TYPE_BITS | type;
}

static int decode_pm(u64 dst_id, unsigned long *id)
{
	int type;

	/*
	 * Magic numbers below came from the older CRIU versions that
	 * erroneously used the changing CR_FD_* constants. The
	 * changes were made when we merged images together and moved
	 * the CR_FD_-s at the tail of the enum
	 */
	type = dst_id & PS_TYPE_MASK;
	switch (type) {
	case 10: /* 3.1 3.2 */
	case 11: /* 1.3 1.4 1.5 1.6 1.7 1.8 2.* 3.0 */
	case 16: /* 1.2 */
	case 17: /* 1.0 1.1 */
	case PS_TYPE_PID:
		*id = dst_id >> PS_TYPE_BITS;
		type = CR_FD_PAGEMAP;
		break;
	case 27: /* 1.3 */
	case 28: /* 1.4 1.5 */
	case 29: /* 1.6 1.7 */
	case 32: /* 1.2 1.8 */
	case 33: /* 1.0 1.1 3.1 3.2 */
	case 34: /* 2.* 3.0 */
	case PS_TYPE_SHMEM:
		*id = dst_id >> PS_TYPE_BITS;
		type = CR_FD_SHMEM_PAGEMAP;
		break;
	default:
		type = -1;
		break;
	}

	return type;
}

static inline u32 encode_ps_cmd(u32 cmd, u32 flags)
{
	return flags << PS_CMD_BITS | cmd;
}

static inline u32 decode_ps_cmd(u32 cmd)
{
	return cmd & PS_CMD_MASK;
}

static inline u32 decode_ps_flags(u32 cmd)
{
	return cmd >> PS_CMD_BITS;
}

static inline int __send(int sk, const void *buf, size_t sz, int fl)
{
	return opts.tls ? tls_send(buf, sz, fl) : send(sk, buf, sz, fl);
}

static inline int __recv(int sk, void *buf, size_t sz, int fl)
{
	return opts.tls ? tls_recv(buf, sz, fl) : recv(sk, buf, sz, fl);
}

static inline int send_psi_flags(int sk, struct page_server_iov *pi, int flags)
{
	if (__send(sk, pi, sizeof(*pi), flags) != sizeof(*pi)) {
		pr_perror("Can't send PSI %d to server", pi->cmd);
		return -1;
	}
	return 0;
}

static inline int send_psi(int sk, struct page_server_iov *pi)
{
	return send_psi_flags(sk, pi, 0);
}

static void tcp_cork(int sk, bool on)
{
	int val = on ? 1 : 0;
	if (setsockopt(sk, SOL_TCP, TCP_CORK, &val, sizeof(val)))
		pr_pwarn("Unable to set TCP_CORK=%d", val);
}

static void tcp_nodelay(int sk, bool on)
{
	int val = on ? 1 : 0;
	if (setsockopt(sk, SOL_TCP, TCP_NODELAY, &val, sizeof(val)))
		pr_pwarn("Unable to set TCP_NODELAY=%d", val);
}

/* page-server xfer */
static int write_pages_to_server(struct page_xfer *xfer, int p, unsigned long len)
{
	ssize_t ret, left = len;

	if (opts.tls) {
		pr_debug("Sending %lu bytes / %lu pages\n", len, len / PAGE_SIZE);

		if (tls_send_data_from_fd(p, len))
			return -1;
	} else {
		pr_debug("Splicing %lu bytes / %lu pages into socket\n", len, len / PAGE_SIZE);

		while (left > 0) {
			ret = splice(p, NULL, xfer->sk, NULL, left, SPLICE_F_MOVE);
			if (ret < 0) {
				pr_perror("Can't write pages to socket");
				return -1;
			}

			pr_debug("\tSpliced: %lu bytes sent\n", (unsigned long)ret);
			left -= ret;
		}
	}

	return 0;
}

static int write_pagemap_to_server(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	struct page_server_iov pi = {
		.cmd = encode_ps_cmd(PS_IOV_ADD_F, flags),
		.nr_pages = iov->iov_len / PAGE_SIZE,
		.vaddr = encode_pointer(iov->iov_base),
		.dst_id = xfer->dst_id,
	};

	return send_psi(xfer->sk, &pi);
}

static void close_server_xfer(struct page_xfer *xfer)
{
	xfer->sk = -1;
}

static int open_page_server_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	char has_parent;
	struct page_server_iov pi = {
		.cmd = PS_IOV_OPEN2,
	};

	xfer->sk = page_server_sk;
	xfer->write_pagemap = write_pagemap_to_server;
	xfer->write_pages = write_pages_to_server;
	xfer->close = close_server_xfer;
	xfer->dst_id = encode_pm(fd_type, img_id);
	xfer->parent = NULL;

	pi.dst_id = xfer->dst_id;
	if (send_psi(xfer->sk, &pi)) {
		pr_perror("Can't write to page server");
		return -1;
	}

	/* Push the command NOW */
	tcp_nodelay(xfer->sk, true);

	if (__recv(xfer->sk, &has_parent, 1, 0) != 1) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	if (has_parent)
		xfer->parent = (void *)1; /* This is required for generate_iovs() */

	return 0;
}

/* local xfer */
/*
 * Callback for compress_stream_add_frame: write compressed bytes to the
 * local pages-*.img via the image's raw fd. cookie is the fd.
 */
static int pxfer_loc_compress_write_cb(void *cookie, const void *buf, size_t len)
{
	int fd = (int)(intptr_t)cookie;
	const char *p = buf;
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, p + off, len - off);
		if (n <= 0) {
			pr_perror("page-xfer: compressed write failed");
			return -1;
		}
		off += (size_t)n;
	}
	return 0;
}

static int write_pages_loc(struct page_xfer *xfer, int p, unsigned long len)
{
	ssize_t ret;
	ssize_t curr = 0;

	/*
	 * Compressed local mode: read the full IOV into a staging buffer,
	 * feed it as one seekable frame (one pagemap entry = one frame), and
	 * write the compressed bytes out. Fall back to splice() when
	 * --compress is not set or we somehow ended up without a compressor.
	 */
	if (opts.compress && xfer->compress) {
		void *buf;
		size_t got = 0;
		int rc;

		buf = xmalloc(len);
		if (!buf)
			return -1;

		while (got < len) {
			ssize_t n = read(p, (char *)buf + got, len - got);
			if (n <= 0) {
				pr_perror("page-xfer: pipe read failed (compress)");
				xfree(buf);
				return -1;
			}
			got += (size_t)n;
		}

		rc = compress_stream_add_frame(xfer->compress, buf, len,
					       pxfer_loc_compress_write_cb,
					       (void *)(intptr_t)img_raw_fd(xfer->pi));
		xfree(buf);
		return rc;
	}

	while (1) {
		ret = splice(p, NULL, img_raw_fd(xfer->pi), NULL, len - curr, SPLICE_F_MOVE);
		if (ret == -1) {
			pr_perror("Unable to spice data");
			return -1;
		}
		if (ret == 0) {
			pr_err("A pipe was closed unexpectedly\n");
			return -1;
		}
		curr += ret;
		if (curr == len)
			break;
	}

	return 0;
}

static int check_pagehole_in_parent(struct page_read *p, struct iovec *iov)
{
	int ret;
	unsigned long off, end;

	/*
	 * Try to find pagemap entry in parent, from which
	 * the data will be read on restore.
	 *
	 * This is the optimized version of the page-by-page
	 * read_pagemap_page routine.
	 */

	pr_debug("Checking %p/%zu hole\n", iov->iov_base, iov->iov_len);
	off = (unsigned long)iov->iov_base;
	end = off + iov->iov_len;
	while (1) {
		unsigned long pend;

		ret = p->seek_pagemap(p, off);
		if (ret <= 0 || !p->pe) {
			pr_err("Missing %lx in parent pagemap\n", off);
			return -1;
		}

		pr_debug("\tFound %" PRIx64 "/%lu\n", p->pe->vaddr, pagemap_len(p->pe));

		/*
		 * The pagemap entry in parent may happen to be
		 * shorter, than the hole we write. In this case
		 * we should go ahead and check the remainder.
		 */

		pend = p->pe->vaddr + pagemap_len(p->pe);
		if (end <= pend)
			return 0;

		pr_debug("\t\tcontinue on %lx\n", pend);
		off = pend;
	}
}

static int write_pagemap_loc(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	int ret;
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	pe.vaddr = encode_pointer(iov->iov_base);
	pe.nr_pages = iov->iov_len / PAGE_SIZE;
	pe.has_flags = true;
	pe.flags = flags;

	if (flags & PE_PRESENT) {
		if (opts.auto_dedup && xfer->parent != NULL) {
			ret = dedup_one_iovec(xfer->parent, pe.vaddr, pagemap_len(&pe));
			if (ret == -1) {
				pr_perror("Auto-deduplication failed");
				return ret;
			}
		}
	} else if (flags & PE_PARENT) {
		if (xfer->parent != NULL) {
			ret = check_pagehole_in_parent(xfer->parent, iov);
			if (ret) {
				pr_err("Hole %p/%zu not found in parent\n", iov->iov_base, iov->iov_len);
				return -1;
			}
		}
	}

	if (pb_write_one(xfer->pmi, &pe, PB_PAGEMAP) < 0)
		return -1;

	return 0;
}

static void close_page_xfer(struct page_xfer *xfer)
{
	if (xfer->parent != NULL) {
		xfer->parent->close(xfer->parent);
		xfree(xfer->parent);
		xfer->parent = NULL;
	}
	/*
	 * Flush the seek table (trailing skippable frame) into the pages
	 * image before closing it. Any error here is logged but does not
	 * stop teardown — we still need to close the fds.
	 */
	if (xfer->compress && xfer->pi) {
		if (compress_stream_finalize(xfer->compress,
					     pxfer_loc_compress_write_cb,
					     (void *)(intptr_t)img_raw_fd(xfer->pi)) < 0)
			pr_err("page-xfer: compress_stream_finalize failed\n");
		compress_stream_free(xfer->compress);
		xfer->compress = NULL;
	}
	if (xfer->pi)
		close_image(xfer->pi);
	if (xfer->pmi)
		close_image(xfer->pmi);
}

static int open_page_local_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	u32 pages_id;

	xfer->pmi = open_image(fd_type, O_DUMP, img_id);
	if (!xfer->pmi)
		return -1;

	xfer->pi = open_pages_image(O_DUMP, xfer->pmi, &pages_id);
	if (!xfer->pi)
		goto err_pmi;

	/*
	 * The page_xfer struct lives on the caller's stack (cr-dump.c,
	 * shmem.c, mem.c) and is not zero-initialized. Clear fields that
	 * close_page_xfer branches on so stale stack data doesn't get
	 * dereferenced when --compress is not in effect.
	 */
	xfer->compress = NULL;

	/*
	 * Create the zstd seekable compressor for this pages-*.img when
	 * --compress is on. Only applies to the local write path; the S3
	 * mode uses a separate parallel pipeline (see open_page_object_storage_xfer).
	 */
	if (opts.compress && !opts.object_storage_upload) {
		xfer->compress = compress_stream_create(opts.compress_level);
		if (!xfer->compress) {
			pr_err("page-xfer: failed to init compressor for img_id=%lu\n",
			       img_id);
			goto err_pi;
		}
	}

	/*
	 * Open page-read for parent images (if it exists). It will
	 * be used for two things:
	 * 1) when writing a page, those from parent will be dedup-ed
	 * 2) when writing a hole, the respective place would be checked
	 *    to exist in parent (either pagemap or hole)
	 */
	xfer->parent = NULL;
	if (fd_type == CR_FD_PAGEMAP || fd_type == CR_FD_SHMEM_PAGEMAP) {
		int ret;
		int pfd;
		int pr_flags = (fd_type == CR_FD_PAGEMAP) ? PR_TASK : PR_SHMEM;

		/* Image streaming lacks support for incremental images */
		if (opts.stream)
			goto out;

		if (open_parent(get_service_fd(IMG_FD_OFF), &pfd))
			goto err_pi;
		if (pfd < 0)
			goto out;

		xfer->parent = xmalloc(sizeof(*xfer->parent));
		if (!xfer->parent) {
			close(pfd);
			goto err_pi;
		}

		/*
		 * When object-storage-upload is enabled, parent dir may be
		 * empty (S3-only mode). Swap prefix to parent's so that
		 * do_open_image() S3 fallback fetches from the right prefix.
		 */
		if (opts.object_storage_upload) {
			void *prefix_data = NULL;
			unsigned long prefix_len = 0;
			char *parent_prefix = NULL;
			char *saved_prefix;
			int s3_ret;

			s3_ret = object_storage_get_object("parent-prefix",
							   &prefix_data, &prefix_len);
			if (s3_ret == 0 && prefix_data && prefix_len > 0) {
				parent_prefix = xmalloc(prefix_len + 1);
				if (parent_prefix) {
					memcpy(parent_prefix, prefix_data, prefix_len);
					parent_prefix[prefix_len] = '\0';
				}
			}
			if (prefix_data)
				free(prefix_data);

			if (parent_prefix) {
				pr_info("page-xfer: using parent prefix: %s\n", parent_prefix);
				saved_prefix = opts.object_storage_object_prefix;
				opts.object_storage_object_prefix = parent_prefix;
				ret = open_page_read_at(pfd, img_id, xfer->parent, pr_flags);
				opts.object_storage_object_prefix = saved_prefix;
				xfree(parent_prefix);
			} else {
				ret = open_page_read_at(pfd, img_id, xfer->parent, pr_flags);
			}
		} else {
			ret = open_page_read_at(pfd, img_id, xfer->parent, pr_flags);
		}

		if (ret <= 0) {
			pr_perror("No parent image found, though parent directory is set");
			xfree(xfer->parent);
			xfer->parent = NULL;
			close(pfd);
			goto out;
		}
		close(pfd);
	}

out:
	xfer->write_pagemap = write_pagemap_loc;
	xfer->write_pages = write_pages_loc;
	xfer->close = close_page_xfer;
	return 0;

err_pi:
	close_image(xfer->pi);
err_pmi:
	close_image(xfer->pmi);
	return -1;
}

/*
 * S3 upload wrapper functions (dual-write: local + S3).
 * Local xfer functions handle the actual file I/O.
 * S3 functions upload pages data via multipart and pagemap via put_object.
 */

#define OBJECT_STORAGE_PART_SIZE (8 * 1024 * 1024) /* 8MB per multipart part */

/*
 * Deferred close list — enables parallel cross-file upload.
 *
 * For multi-process workloads (memcached, redis) CRIU closes several
 * page_xfer instances in sequence. Pre-refactor, close_page_xfer
 * blocked on upload_pool_wait for each file before moving on, so
 * pages-1.img and pages-2.img serialized. Instead, we keep the
 * upload_pool alive after the final submit and push it onto this list;
 * TCP continues shipping the last in-flight parts while the next
 * process's pipe-read + submit loop runs. At end of dump
 * page_xfer_drain_deferred_uploads() walks this list, pumps each pool
 * to collect responses, and issues the multipart_complete.
 */
struct deferred_close_entry {
	struct upload_pool *pool;
	char pages_key[512];
	char upload_id[256];
	struct deferred_close_entry *next;
};
static struct deferred_close_entry *g_deferred_closes = NULL;

static void _deferred_push(struct upload_pool *pool,
			   const char *pages_key,
			   const char *upload_id)
{
	struct deferred_close_entry *e;
	int failed = 0;
	const char **etags = NULL;
	int n_parts = 0;

	e = xmalloc(sizeof(*e));
	if (!e) {
		/* Can't record; drain what we have now to not leak. */
		pr_warn("deferred_push: xmalloc failed, resorting to synchronous drain\n");
		if (upload_pool_wait(pool, &failed) == 0 &&
		    upload_pool_get_etags(pool, &etags, &n_parts) == 0 &&
		    n_parts > 0) {
			object_storage_multipart_complete(pages_key, upload_id,
							  n_parts, etags);
		} else {
			object_storage_multipart_abort(pages_key, upload_id);
		}
		upload_pool_destroy(pool);
		return;
	}
	e->pool = pool;
	snprintf(e->pages_key, sizeof(e->pages_key), "%s", pages_key);
	snprintf(e->upload_id, sizeof(e->upload_id), "%s", upload_id);
	e->next = g_deferred_closes;
	g_deferred_closes = e;
}

int page_xfer_drain_deferred_uploads(void)
{
	int overall = 0;
	struct deferred_close_entry *e;

	while ((e = g_deferred_closes) != NULL) {
		const char **etags = NULL;
		int n_parts = 0;
		int failed = 0;
		int rc;

		g_deferred_closes = e->next;

		rc = upload_pool_wait(e->pool, &failed);
		if (rc < 0) {
			pr_err("drain_deferred: pool for %s failed at part %d\n",
			       e->pages_key, failed);
			object_storage_multipart_abort(e->pages_key, e->upload_id);
			upload_pool_destroy(e->pool);
			xfree(e);
			overall = -1;
			continue;
		}

		rc = upload_pool_get_etags(e->pool, &etags, &n_parts);
		if (rc < 0 || !etags || n_parts == 0) {
			pr_err("drain_deferred: empty etags for %s\n", e->pages_key);
			object_storage_multipart_abort(e->pages_key, e->upload_id);
			upload_pool_destroy(e->pool);
			xfree(e);
			overall = -1;
			continue;
		}

		rc = object_storage_multipart_complete(e->pages_key,
						       e->upload_id,
						       n_parts, etags);
		if (rc < 0) {
			pr_err("drain_deferred: multipart complete failed for %s\n",
			       e->pages_key);
			overall = -1;
		}
		upload_pool_destroy(e->pool);
		xfree(e);
	}
	return overall;
}

/*
 * Lazily bring up the CURLM upload pool on first flush. We defer this until
 * the first actual PUT because earlier in the dump the parasite is still
 * running in the target process and some libcurl code paths can interact
 * badly with the parasite RPC fd plumbing. By the time we flush a part,
 * page data is already streaming in and it's safe to spin up the pool.
 */
static int _resolve_upload_workers(void)
{
	int nw;

	/* Explicit --upload-workers N wins. 0 means "auto-detect". */
	if (opts.upload_workers > 0)
		return opts.upload_workers;

	{
		int nic = auto_nic_mbps();
		int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
		/* S3 PUT: ~280 Mbps per libcurl slot in our measurements */
		nw = auto_pool_workers(nic, ncpu, 64, 280);
		opts.upload_workers = nw; /* cache so subsequent calls skip detect */
		pr_info("upload_workers auto: %d (NIC %d Mbps, ncpu %d)\n",
			nw, nic, ncpu);
	}
	return nw;
}

static int _ensure_upload_pool(struct page_xfer *xfer)
{
	struct upload_pool *pool;
	int workers;

	if (xfer->object_storage.upload_pool)
		return 0;
	workers = _resolve_upload_workers();
	if (workers <= 1)
		return 0;

	pool = upload_pool_create(xfer->object_storage.pages_key,
				  xfer->object_storage.upload_id,
				  workers);
	if (!pool) {
		pr_warn("object_storage: upload_pool_create failed, "
			"falling back to serial PUT\n");
		return 0;
	}
	xfer->object_storage.upload_pool = pool;
	pr_info("object_storage: parallel upload pool started (%d workers)\n",
		workers);
	return 0;
}

static int _flush_object_storage_part(struct page_xfer *xfer)
{
	char etag[256];
	int ret;
	int part_num;

	part_num = ++xfer->object_storage.part_number;

	if (_ensure_upload_pool(xfer) < 0)
		return -1;

	/*
	 * Parallel path: hand the full 8MB buffer to the pool and allocate
	 * a fresh one so the dump thread can keep filling it. The pool
	 * takes ownership of the buffer and frees it when the PUT lands.
	 */
	if (xfer->object_storage.upload_pool) {
		void *new_buf;

		new_buf = xmalloc(xfer->object_storage.part_buf_cap);
		if (!new_buf)
			return -1;

		ret = upload_pool_submit(xfer->object_storage.upload_pool,
					 part_num,
					 xfer->object_storage.part_buf,
					 xfer->object_storage.part_buf_used);
		if (ret < 0) {
			pr_err("object_storage: upload_pool_submit part %d failed\n",
			       part_num);
			xfree(new_buf);
			return -1;
		}
		xfer->object_storage.part_buf = new_buf;
		xfer->object_storage.part_buf_used = 0;
		return 0;
	}

	/* Serial fallback (opts.upload_workers <= 1 or pool create failed) */
	if (xfer->object_storage.etags_count >= xfer->object_storage.etags_cap) {
		int new_cap = xfer->object_storage.etags_cap * 2;
		char **new_etags = xrealloc(xfer->object_storage.etags, new_cap * sizeof(char *));
		if (!new_etags)
			return -1;
		xfer->object_storage.etags = new_etags;
		xfer->object_storage.etags_cap = new_cap;
	}

	ret = object_storage_multipart_upload_part(
		xfer->object_storage.pages_key, xfer->object_storage.upload_id,
		part_num,
		xfer->object_storage.part_buf, xfer->object_storage.part_buf_used,
		etag, sizeof(etag));
	if (ret < 0) {
		pr_err("object_storage: multipart upload part %d failed\n",
		       part_num);
		return -1;
	}
	xfer->object_storage.etags[xfer->object_storage.etags_count] = xstrdup(etag);
	xfer->object_storage.etags_count++;
	xfer->object_storage.part_buf_used = 0;
	return 0;
}

static int write_pages_object_storage(struct page_xfer *xfer, int p, unsigned long len)
{
	unsigned long remaining;
	ssize_t nread;
	int ret;

	/*
	 * --compress path: drain this full IOV into a staging buffer and
	 * hand it to the parallel compress pipeline as a single zstd frame.
	 * compress_pipeline_submit() returns immediately after queueing;
	 * compress and S3 upload run in background threads.
	 *
	 * The pipeline itself is created lazily on first write to avoid
	 * launching worker threads while CRIU is still running parasite
	 * RPCs in the target process.
	 */
	if (opts.compress && !xfer->object_storage.compress_pipe) {
		int nc = opts.compress_workers;
		/*
		 * Both compressed and raw paths share the same CURLM
		 * upload_pool, sized by opts.upload_workers (auto-detected
		 * from NIC bandwidth if user didn't pass --upload-workers).
		 */
		int nu = _resolve_upload_workers();
		if (nc <= 0) {
			/*
			 * Auto-tune: leave 1 CPU for the main dump thread
			 * (parasite RPC + pipe reads), use the rest for
			 * compress workers capped at 8. Previous formula was
			 * ncpu/4 which underutilized m5.xlarge / m5.2xlarge
			 * (1-2 workers instead of 3-7). Cap at 8 because
			 * writer_drain is single-threaded and saturates with
			 * ~4-8 compress workers feeding it.
			 */
			int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
			if (ncpu <= 1)
				nc = 1;
			else if (ncpu >= 9)
				nc = 8;
			else
				nc = ncpu - 1;
		} else {
			int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
			if (nc > ncpu)
				pr_warn("compress-workers=%d exceeds CPU count %d; "
					"main-thread starvation possible\n", nc, ncpu);
		}
		if (nu <= 0)
			nu = 8;
		xfer->object_storage.compress_pipe = compress_pipeline_create(
			xfer->object_storage.pages_key,
			xfer->object_storage.upload_id,
			opts.compress_level, nc, nu);
		if (!xfer->object_storage.compress_pipe) {
			pr_err("object_storage(compress): pipeline init failed\n");
			return -1;
		}
		pr_info("object_storage(compress): pipeline started "
			"(%d compress, %d upload workers, level %d)\n",
			nc, nu, opts.compress_level);
	}

	if (xfer->object_storage.compress_pipe) {
		void *buf;
		unsigned long got = 0;

		buf = xmalloc(len);
		if (!buf)
			return -1;
		while (got < len) {
			ssize_t n = read(p, (char *)buf + got, len - got);
			if (n <= 0) {
				pr_err("object_storage(compress): pipe read failed\n");
				xfree(buf);
				return -1;
			}
			got += (unsigned long)n;
		}
		/* ownership transfer: pipeline frees buf (success or fail). */
		return compress_pipeline_submit(xfer->object_storage.compress_pipe,
						buf, len);
	}

	/*
	 * Read pages from pipe directly into buffer for both local write
	 * and object storage upload. We read from the pipe into a temp buffer,
	 * write to local file, and accumulate in the part buffer for upload.
	 */
	remaining = len;
	while (remaining > 0) {
		unsigned long chunk_size;
		unsigned long space;
		char *dst;

		space = xfer->object_storage.part_buf_cap - xfer->object_storage.part_buf_used;
		chunk_size = remaining < space ? remaining : space;

		/* Read from pipe into part buffer */
		dst = (char *)xfer->object_storage.part_buf + xfer->object_storage.part_buf_used;
		nread = read(p, dst, chunk_size);
		if (nread <= 0) {
			pr_err("object_storage: failed to read from pipe\n");
			return -1;
		}

		/* Write to local pages file (skip in S3-only mode) */
		if (xfer->pi) {
			ssize_t nw;
			unsigned long wr = 0;
			while (wr < (unsigned long)nread) {
				nw = write(img_raw_fd(xfer->pi), dst + wr, nread - wr);
				if (nw <= 0) {
					pr_err("object_storage: failed to write to local pages file\n");
					return -1;
				}
				wr += nw;
			}
		}

		xfer->object_storage.part_buf_used += nread;
		remaining -= nread;

		/* Flush part when buffer is full */
		if (xfer->object_storage.part_buf_used >= xfer->object_storage.part_buf_cap) {
			ret = _flush_object_storage_part(xfer);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

static int write_pagemap_object_storage(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	/* Write to local file first */
	return write_pagemap_loc(xfer, iov, flags);
	/* Pagemap is uploaded on close via put_object from the local file */
}

static void close_page_xfer_object_storage(struct page_xfer *xfer)
{
	int i;

	if (xfer->object_storage.active) {
		/*
		 * --compress path: drain the parallel pipeline. Compress
		 * workers finish their remaining frames, writer appends the
		 * seek table to the last part, upload workers land all parts.
		 * Etags come back owned by us.
		 */
		if (xfer->object_storage.compress_pipe) {
			char **etags = NULL;
			int n_parts = 0;
			int rc;

			rc = compress_pipeline_finalize(
					xfer->object_storage.compress_pipe,
					&etags, &n_parts);
			compress_pipeline_destroy(xfer->object_storage.compress_pipe);
			xfer->object_storage.compress_pipe = NULL;

			if (rc < 0 || !etags || n_parts == 0) {
				pr_err("object_storage(compress): pipeline failed; aborting upload\n");
				object_storage_multipart_abort(
					xfer->object_storage.pages_key,
					xfer->object_storage.upload_id);
				if (etags) {
					for (i = 0; i < n_parts; i++)
						xfree(etags[i]);
					xfree(etags);
				}
				goto cleanup;
			}

			rc = object_storage_multipart_complete(
				xfer->object_storage.pages_key,
				xfer->object_storage.upload_id,
				n_parts, (const char **)etags);
			if (rc < 0)
				pr_err("object_storage(compress): multipart complete failed for %s\n",
				       xfer->object_storage.pages_key);

			for (i = 0; i < n_parts; i++)
				xfree(etags[i]);
			xfree(etags);

			goto upload_pagemap;
		}

		/*
		 * Parallel upload path: submit the final (possibly partial) part
		 * via the pool, then block until all in-flight uploads land and
		 * issue multipart complete with the ordered etag array owned by
		 * the pool.
		 */
		if (xfer->object_storage.upload_pool) {
			struct upload_pool *pool = xfer->object_storage.upload_pool;
			int rc;

			if (xfer->object_storage.part_buf_used > 0 ||
			    xfer->object_storage.part_number == 0) {
				int final_pn = ++xfer->object_storage.part_number;
				void *new_buf = xmalloc(1);  /* placeholder so free path works */

				rc = upload_pool_submit(pool, final_pn,
							xfer->object_storage.part_buf,
							xfer->object_storage.part_buf_used);
				if (rc < 0) {
					pr_err("object_storage: final part submit failed\n");
					object_storage_multipart_abort(
						xfer->object_storage.pages_key,
						xfer->object_storage.upload_id);
					xfree(new_buf);
					goto cleanup;
				}
				/* buf ownership moved to pool */
				xfer->object_storage.part_buf = new_buf;
				xfer->object_storage.part_buf_used = 0;
			}

			/*
			 * DEFER upload_pool_wait + multipart_complete until the
			 * end of all dumps (page_xfer_drain_deferred_uploads).
			 * The kernel TCP stack keeps shipping this pool's last
			 * parts autonomously while the next process's pipe-
			 * reading + pool submits proceed on the same thread.
			 * By the time the drain runs, most responses have
			 * already landed in the socket RCV buffer — we just
			 * pump curl_multi_perform to collect them and issue
			 * the multipart_complete. Net effect: proc 1's upload
			 * tail overlaps with proc 2's dump body, halving the
			 * wall time for multi-process workloads (mc/redis).
			 */
			_deferred_push(pool, xfer->object_storage.pages_key,
				       xfer->object_storage.upload_id);
			xfer->object_storage.upload_pool = NULL;
			goto upload_pagemap;
		}

		/* Flush remaining part buffer (serial fallback) */
		if (xfer->object_storage.part_buf_used > 0 || xfer->object_storage.part_number == 0) {
			char etag[256];
			int ret;

			if (xfer->object_storage.etags_count >= xfer->object_storage.etags_cap) {
				int new_cap = xfer->object_storage.etags_cap + 1;
				char **new_etags = xrealloc(xfer->object_storage.etags, new_cap * sizeof(char *));
				if (new_etags) {
					xfer->object_storage.etags = new_etags;
					xfer->object_storage.etags_cap = new_cap;
				}
			}

			if (xfer->object_storage.part_buf_used > 0 || xfer->object_storage.part_number == 0) {
				xfer->object_storage.part_number++;
				ret = object_storage_multipart_upload_part(
					xfer->object_storage.pages_key, xfer->object_storage.upload_id,
					xfer->object_storage.part_number,
					xfer->object_storage.part_buf,
					xfer->object_storage.part_buf_used > 0 ? xfer->object_storage.part_buf_used : 0,
					etag, sizeof(etag));
				if (ret < 0) {
					pr_err("object_storage: final part upload failed, aborting\n");
					object_storage_multipart_abort(xfer->object_storage.pages_key,
								       xfer->object_storage.upload_id);
					goto cleanup;
				}
				xfer->object_storage.etags[xfer->object_storage.etags_count] = xstrdup(etag);
				xfer->object_storage.etags_count++;
			}
		}

		/* Complete multipart upload */
		if (xfer->object_storage.etags_count > 0) {
			int ret;
			ret = object_storage_multipart_complete(
				xfer->object_storage.pages_key, xfer->object_storage.upload_id,
				xfer->object_storage.etags_count, (const char **)xfer->object_storage.etags);
			if (ret < 0)
				pr_err("object_storage: multipart complete failed for %s\n", xfer->object_storage.pages_key);
		}

upload_pagemap:

		/*
		 * Upload pagemap: close local files first to flush buffered writes,
		 * then reopen the pagemap file to read and upload to object storage.
		 */
		{
			char pagemap_key_copy[512];
			snprintf(pagemap_key_copy, sizeof(pagemap_key_copy), "%s",
				 xfer->object_storage.pagemap_key);

			/* Close local files (flushes buffers) */
			close_page_xfer(xfer);

			/* Reopen pagemap from images-dir and upload */
			{
				int pmi_fd;
				off_t pmi_size;

				pmi_fd = openat(get_service_fd(IMG_FD_OFF), pagemap_key_copy, O_RDONLY);
				if (pmi_fd >= 0) {
					pmi_size = lseek(pmi_fd, 0, SEEK_END);
					if (pmi_size > 0) {
						void *pmi_data;
						ssize_t nr;
						unsigned long rd;

						lseek(pmi_fd, 0, SEEK_SET);
						pmi_data = xmalloc(pmi_size);
						if (pmi_data) {
							rd = 0;
							while (rd < (unsigned long)pmi_size) {
								nr = read(pmi_fd, (char *)pmi_data + rd,
									  pmi_size - rd);
								if (nr <= 0)
									break;
								rd += nr;
							}
							if (rd == (unsigned long)pmi_size)
								object_storage_put_object(pagemap_key_copy,
											  pmi_data, pmi_size);
							xfree(pmi_data);
						}
					}
					close(pmi_fd);
				}
			}
		}

		goto cleanup_storage;

cleanup:
		/* Close local files (if not already closed above) */
		close_page_xfer(xfer);

cleanup_storage:
		/* Free etags */
		for (i = 0; i < xfer->object_storage.etags_count; i++)
			xfree(xfer->object_storage.etags[i]);
		xfree(xfer->object_storage.etags);
		xfree(xfer->object_storage.part_buf);
		xfer->object_storage.active = 0;
	}
}

static int open_page_object_storage_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	int ret;

	/*
	 * Open local xfer first (creates pagemap + pages files locally).
	 * We need local pagemap for pb_write_one() buffering.
	 * Pages file is only needed in dual-write mode.
	 */
	ret = open_page_local_xfer(xfer, fd_type, img_id);
	if (ret < 0)
		return ret;

	/* Initialize object storage upload state */
	memset(&xfer->object_storage, 0, sizeof(xfer->object_storage));

	/*
	 * Construct object storage keys from actual local filenames.
	 * pages file uses sequential page_ids (1,2,3...), not PID.
	 * pagemap file uses PID (img_id). Use path from cr_img if available.
	 */
	if (xfer->pi && xfer->pi->path) {
		snprintf(xfer->object_storage.pages_key, sizeof(xfer->object_storage.pages_key),
			 "%s", xfer->pi->path);
	} else {
		snprintf(xfer->object_storage.pages_key, sizeof(xfer->object_storage.pages_key),
			 "pages-%lu.img", img_id);
	}
	if (xfer->pmi && xfer->pmi->path) {
		snprintf(xfer->object_storage.pagemap_key, sizeof(xfer->object_storage.pagemap_key),
			 "%s", xfer->pmi->path);
	} else {
		snprintf(xfer->object_storage.pagemap_key, sizeof(xfer->object_storage.pagemap_key),
			 "pagemap-%lu.img", img_id);
	}

	/*
	 * Close local pages file — pages data goes only to object storage.
	 * This eliminates disk I/O for the bulk data (pages are 99%+ of size).
	 * Pagemap stays local for pb_write_one() buffering, uploaded on close.
	 */
	if (xfer->pi) {
		close_image(xfer->pi);
		xfer->pi = NULL;
	}

	/*
	 * Part size is configurable via --upload-part-mb (S3 multipart
	 * part size). Default 8 MB matches S3's own examples; larger
	 * (32 MB) can reduce per-request overhead for big dumps.
	 */
	{
		size_t part_sz = (size_t)(opts.upload_part_mb > 0 ?
					  opts.upload_part_mb : 8) * 1024UL * 1024UL;
		xfer->object_storage.part_buf_cap = part_sz;
		xfer->object_storage.part_buf = xmalloc(part_sz);
	}
	if (!xfer->object_storage.part_buf)
		return -1;
	xfer->object_storage.part_buf_used = 0;
	xfer->object_storage.part_number = 0;

	/* Allocate etags array */
	xfer->object_storage.etags_cap = 64;
	xfer->object_storage.etags = xmalloc(xfer->object_storage.etags_cap * sizeof(char *));
	if (!xfer->object_storage.etags) {
		xfree(xfer->object_storage.part_buf);
		return -1;
	}
	xfer->object_storage.etags_count = 0;

	/* Initiate multipart upload for pages */
	ret = object_storage_multipart_init(xfer->object_storage.pages_key,
					    xfer->object_storage.upload_id,
					    sizeof(xfer->object_storage.upload_id));
	if (ret < 0) {
		pr_err("object_storage: failed to initiate multipart upload for %s\n",
		       xfer->object_storage.pages_key);
		xfree(xfer->object_storage.part_buf);
		xfree(xfer->object_storage.etags);
		return -1;
	}

	xfer->object_storage.active = 1;

	/*
	 * Pipeline creation is deferred to the first write_pages call —
	 * spawning compress worker threads here (while CRIU is still
	 * negotiating with the parasite via a separate control pipe) makes
	 * the parasite RPC hang with "Trimmed message received". By the
	 * time write_pages is invoked, the parasite->main page stream is
	 * already flowing and worker thread creation is safe.
	 */

	/* Override write/close functions with S3 wrappers */
	xfer->write_pagemap = write_pagemap_object_storage;
	xfer->write_pages = write_pages_object_storage;
	xfer->close = close_page_xfer_object_storage;

	return 0;
}

int open_page_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	xfer->offset = 0;
	xfer->transfer_lazy = true;

	if (opts.use_page_server)
		return open_page_server_xfer(xfer, fd_type, img_id);
	else if (opts.object_storage_upload)
		return open_page_object_storage_xfer(xfer, fd_type, img_id);
	else
		return open_page_local_xfer(xfer, fd_type, img_id);
}

static int page_xfer_dump_hole(struct page_xfer *xfer, struct iovec *hole, u32 flags)
{
	BUG_ON(hole->iov_base < (void *)xfer->offset);
	hole->iov_base -= xfer->offset;
	pr_debug("\th %p [%u]\n", hole->iov_base, (unsigned int)(hole->iov_len / PAGE_SIZE));

	if (xfer->write_pagemap(xfer, hole, flags))
		return -1;

	return 0;
}

static int get_hole_flags(struct page_pipe *pp, int n)
{
	unsigned int hole_flags = pp->hole_flags[n];

	if (hole_flags == PP_HOLE_PARENT)
		return PE_PARENT;
	else
		BUG();

	return -1;
}

static int dump_holes(struct page_xfer *xfer, struct page_pipe *pp, unsigned int *cur_hole, void *limit)
{
	int ret;

	for (; *cur_hole < pp->free_hole; (*cur_hole)++) {
		struct iovec hole = pp->holes[*cur_hole];
		u32 hole_flags;

		if (limit && hole.iov_base >= limit)
			break;

		hole_flags = get_hole_flags(pp, *cur_hole);
		ret = page_xfer_dump_hole(xfer, &hole, hole_flags);
		if (ret)
			return ret;
	}

	return 0;
}

static inline u32 ppb_xfer_flags(struct page_xfer *xfer, struct page_pipe_buf *ppb)
{
	if (ppb->flags & PPB_LAZY)
		/*
		 * Pages that can be lazily restored are always marked as such.
		 * In the case we actually transfer them into image mark them
		 * as present as well.
		 */
		return (xfer->transfer_lazy ? PE_PRESENT : 0) | PE_LAZY;
	else
		return PE_PRESENT;
}

/*
 * Optimized pre-dump algorithm
 * ==============================
 *
 * Note: Please refer man(2) page of process_vm_readv syscall.
 *
 * The following discussion covers the possibly faulty-iov
 * locations in an iovec, which hinders process_vm_readv from
 * dumping the entire iovec in a single invocation.
 *
 * Memory layout of target process:
 *
 * Pages: A        B        C
 *	  +--------+--------+--------+--------+--------+--------+
 *	  |||||||||||||||||||||||||||||||||||||||||||||||||||||||
 *	  +--------+--------+--------+--------+--------+--------+
 *
 * Single "iov" representation: {starting_address, length_in_bytes}
 * An iovec is array of iov-s.
 *
 * NOTE: For easy representation and discussion purpose, we carry
 *	 out further discussion at "page granularity".
 *	 length_in_bytes will represent page count in iov instead
 *	 of byte count. Same assumption applies for the syscall's
 *	 return value. Instead of returning the number of bytes
 *	 read, it returns a page count.
 *
 * For above memory mapping, generated iovec: {A,1}{B,1}{C,4}
 *
 * This iovec remains unmodified once generated. At the same
 * time some of memory regions listed in iovec may get modified
 * (unmap/change protection) by the target process while syscall
 * is trying to dump iovec regions.
 *
 * Case 1:
 *	A is unmapped, {A,1} become faulty iov
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      |        ||||||||||||||||||||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^        ^
 *      |        |
 *      start    |
 *      (1)      |
 *               start
 *               (2)
 *
 *	process_vm_readv will return -1. Increment start pointer(2),
 *	syscall will process {B,1}{C,4} in one go and copy 5 pages
 *	to userbuf from iov-B and iov-C.
 *
 * Case 2:
 *	B is unmapped, {B,1} become faulty iov
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      |||||||||         |||||||||||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                 ^
 *      |                 |
 *      start             |
 *      (1)               |
 *                        start
 *                        (2)
 *
 *	process_vm_readv will return 1, i.e. page A copied to
 *	userbuf successfully and syscall stopped, since B got
 *	unmapped.
 *
 *	Increment the start pointer to C(2) and invoke syscall.
 *	Userbuf contains 5 pages overall from iov-A and iov-C.
 *
 * Case 3:
 *	This case deals with partial unmapping of iov representing
 *	more than one pagesize region.
 *
 *	Syscall can't process such faulty iov as whole. So we
 *	process such regions part-by-part and form new sub-iovs
 *	in aux_iov from successfully processed pages.
 *
 *
 *	Part 3.1:
 *		First page of C is unmapped
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      ||||||||||||||||||         ||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                          ^
 *      |                          |
 *      start                      |
 *      (1)                        |
 *                                 dummy
 *                                 (2)
 *
 *	process_vm_readv will return 2, i.e. pages A and B copied.
 *	We identify length of iov-C is more than 1 page, that is
 *	where this case differs from Case 2.
 *
 *	dummy-iov is introduced(2) as: {C+1,3}. dummy-iov can be
 *	directly placed at next page to failing page. This will copy
 *	remaining 3 pages from iov-C to userbuf. Finally create
 *	modified iov entry in aux_iov. Complete aux_iov look like:
 *
 *	aux_iov: {A,1}{B,1}{C+1,3}*
 *
 *
 *	Part 3.2:
 *		In between page of C is unmapped, let's say third
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      ||||||||||||||||||||||||||||||||||||         ||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                                            ^
 *      |                 |-----------------|        |
 *      start              partial_read_bytes        |
 *      (1)                                          |
 *                                                   dummy
 *                                                   (2)
 *
 *	process_vm_readv will return 4, i.e. pages A and B copied
 *	completely and first two pages of C are also copied.
 *
 *	Since, iov-C is not processed completely, we need to find
 *	"partial_read_byte" count to place out dummy-iov for
 *	remaining processing of iov-C. This function is performed by
 *	analyze_iov function.
 *
 *	dummy-iov will be(2): {C+3,1}. dummy-iov will be placed
 *	next to first failing address to process remaining iov-C.
 *	New entries in aux_iov will look like:
 *
 *	aux_iov: {A,1}{B,1}{C,2}*{C+3,1}*
 */

unsigned long handle_faulty_iov(int pid, struct iovec *riov, unsigned long faulty_index, struct iovec *bufvec,
				struct iovec *aux_iov, unsigned long *aux_len)
{
	struct iovec dummy;
	ssize_t bytes_read;
	unsigned long final_read_cnt = 0;

	/* Handling Case 3-Part 3.2*/
	dummy.iov_base = riov[faulty_index].iov_base;
	dummy.iov_len = riov[faulty_index].iov_len;

	while (dummy.iov_len) {
		bytes_read = process_vm_readv(pid, bufvec, 1, &dummy, 1, 0);
		if (bytes_read == -1) {
			/* Handling faulty page read in faulty iov */
			cnt_sub(CNT_PAGES_WRITTEN, 1);
			dummy.iov_base += PAGE_SIZE;
			dummy.iov_len -= PAGE_SIZE;
			continue;
		}

		/* If aux-iov can merge and expand or new entry required */
		if (aux_iov[(*aux_len) - 1].iov_base + aux_iov[(*aux_len) - 1].iov_len == dummy.iov_base)
			aux_iov[(*aux_len) - 1].iov_len += bytes_read;
		else {
			aux_iov[*aux_len].iov_base = dummy.iov_base;
			aux_iov[*aux_len].iov_len = bytes_read;
			(*aux_len) += 1;
		}

		dummy.iov_base += bytes_read;
		dummy.iov_len -= bytes_read;
		bufvec->iov_base += bytes_read;
		bufvec->iov_len -= bytes_read;
		final_read_cnt += bytes_read;
	}

	return final_read_cnt;
}

/*
 * This function will position start pointer to the latest
 * successfully read iov in iovec.
 */
static unsigned long analyze_iov(ssize_t bytes_read, struct iovec *riov, unsigned long *index, struct iovec *aux_iov,
				 unsigned long *aux_len)
{
	ssize_t processed_bytes = 0;

	/* correlating iovs with read bytes */
	while (processed_bytes < bytes_read) {
		processed_bytes += riov[*index].iov_len;
		aux_iov[*aux_len].iov_base = riov[*index].iov_base;
		aux_iov[*aux_len].iov_len = riov[*index].iov_len;

		(*aux_len) += 1;
		(*index) += 1;
	}

	/* handling partially processed faulty iov*/
	if (processed_bytes - bytes_read) {
		unsigned long partial_read_bytes = 0;

		(*index) -= 1;

		partial_read_bytes = riov[*index].iov_len - (processed_bytes - bytes_read);
		aux_iov[*aux_len - 1].iov_len = partial_read_bytes;
		riov[*index].iov_base += partial_read_bytes;
		riov[*index].iov_len -= partial_read_bytes;
	}

	return 0;
}

/*
 * This function iterates over complete ppb->iov entries and pass
 * them to process_vm_readv syscall.
 *
 * Since process_vm_readv returns count of successfully read bytes.
 * It does not point to iovec entry associated to last successful
 * byte read. The correlation between bytes read and corresponding
 * iovec is setup through analyze_iov function.
 *
 * If all iovecs are not processed in one go, it means there exists
 * some faulty iov entry(memory mapping modified after it was grabbed)
 * in iovec. process_vm_readv syscall stops at such faulty iov and
 * skip processing further any entry in iovec. This is handled by
 * handle_faulty_iov function.
 */
static long fill_userbuf(int pid, struct page_pipe_buf *ppb, struct iovec *bufvec, struct iovec *aux_iov,
			 unsigned long *aux_len)
{
	struct iovec *riov = ppb->iov;
	ssize_t bytes_read;
	unsigned long total_read = 0;
	unsigned long start = 0;

	while (start < ppb->nr_segs) {
		bytes_read = process_vm_readv(pid, bufvec, 1, &riov[start], ppb->nr_segs - start, 0);
		if (bytes_read == -1) {
			if (errno == ESRCH) {
				pr_debug("Target process PID:%d not found\n", pid);
				return -ESRCH;
			}
			if (errno != EFAULT) {
				pr_perror("process_vm_readv failed");
				return -1;
			}
			/* Handling Case 1*/
			if (riov[start].iov_len == PAGE_SIZE) {
				cnt_sub(CNT_PAGES_WRITTEN, 1);
				start += 1;
				continue;
			}
			total_read += handle_faulty_iov(pid, riov, start, bufvec, aux_iov, aux_len);
			start += 1;
			continue;
		}

		if (bytes_read > 0) {
			if (analyze_iov(bytes_read, riov, &start, aux_iov, aux_len) < 0)
				return -1;
			bufvec->iov_base += bytes_read;
			bufvec->iov_len -= bytes_read;
			total_read += bytes_read;
		}
	}

	return total_read;
}

/*
 * This function is similar to page_xfer_dump_pages, instead it uses
 * auxiliary_iov array for pagemap generation.
 *
 * The entries of ppb->iov may mismatch with actual process mappings
 * present at time of pre-dump. Such entries need to be adjusted as per
 * the pages read by process_vm_readv syscall. These adjusted entries
 * along with unmodified entries are present in aux_iov array.
 */

int page_xfer_predump_pages(int pid, struct page_xfer *xfer, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	unsigned int cur_hole = 0, i;
	unsigned long ret, bytes_read;
	unsigned long userbuf_len;
	struct iovec bufvec;

	struct iovec *aux_iov;
	unsigned long aux_len;
	void *userbuf;

	userbuf_len = PIPE_MAX_BUFFER_SIZE;
	userbuf = mmap(NULL, userbuf_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (userbuf == MAP_FAILED) {
		pr_perror("Unable to mmap a buffer");
		return -1;
	}
	aux_iov = xmalloc(userbuf_len / PAGE_SIZE * sizeof(aux_iov[0]));
	if (!aux_iov)
		goto err;

	list_for_each_entry(ppb, &pp->bufs, l) {
		if (ppb->pipe_size * PAGE_SIZE > userbuf_len) {
			void *addr;

			addr = mremap(userbuf, userbuf_len, ppb->pipe_size * PAGE_SIZE, MREMAP_MAYMOVE);
			if (addr == MAP_FAILED) {
				pr_perror("Unable to mmap a buffer");
				goto err;
			}
			userbuf_len = ppb->pipe_size * PAGE_SIZE;
			userbuf = addr;
			addr = xrealloc(aux_iov, ppb->pipe_size * sizeof(aux_iov[0]));
			if (!addr)
				goto err;
			aux_iov = addr;
		}
		timing_start(TIME_MEMDUMP);

		aux_len = 0;
		bufvec.iov_len = userbuf_len;
		bufvec.iov_base = userbuf;

		bytes_read = fill_userbuf(pid, ppb, &bufvec, aux_iov, &aux_len);
		if (bytes_read == -ESRCH) {
			timing_stop(TIME_MEMDUMP);
			munmap(userbuf, userbuf_len);
			xfree(aux_iov);
			return 0;
		}
		if (bytes_read < 0)
			goto err;

		bufvec.iov_base = userbuf;
		bufvec.iov_len = bytes_read;
		ret = vmsplice(ppb->p[1], &bufvec, 1, SPLICE_F_NONBLOCK | SPLICE_F_GIFT);

		if (ret == -1 || ret != bytes_read) {
			pr_err("vmsplice: Failed to splice user buffer to pipe %ld\n", ret);
			goto err;
		}

		timing_stop(TIME_MEMDUMP);
		timing_start(TIME_MEMWRITE);

		/* generating pagemap */
		for (i = 0; i < aux_len; i++) {
			struct iovec iov = aux_iov[i];
			u32 flags;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base);
			if (ret)
				goto err;

			BUG_ON(iov.iov_base < (void *)xfer->offset);
			iov.iov_base -= xfer->offset;
			pr_debug("\t p %p [%u]\n", iov.iov_base, (unsigned int)(iov.iov_len / PAGE_SIZE));

			flags = ppb_xfer_flags(xfer, ppb);

			if (xfer->write_pagemap(xfer, &iov, flags))
				goto err;

			if (xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
				goto err;
		}

		timing_stop(TIME_MEMWRITE);
	}

	munmap(userbuf, userbuf_len);
	xfree(aux_iov);
	timing_start(TIME_MEMWRITE);

	return dump_holes(xfer, pp, &cur_hole, NULL);
err:
	munmap(userbuf, userbuf_len);
	xfree(aux_iov);
	return -1;
}

int page_xfer_dump_pages(struct page_xfer *xfer, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	unsigned int cur_hole = 0;
	int ret;

	pr_debug("Transferring pages:\n");

	list_for_each_entry(ppb, &pp->bufs, l) {
		unsigned int i;

		pr_debug("\tbuf %d/%d\n", ppb->pages_in, ppb->nr_segs);

		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];
			u32 flags;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base);
			if (ret)
				return ret;

			BUG_ON(iov.iov_base < (void *)xfer->offset);
			iov.iov_base -= xfer->offset;
			pr_debug("\tp %p [%u]\n", iov.iov_base, (unsigned int)(iov.iov_len / PAGE_SIZE));

			flags = ppb_xfer_flags(xfer, ppb);

			if (xfer->write_pagemap(xfer, &iov, flags))
				return -1;
			if ((flags & PE_PRESENT) && xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
				return -1;
		}
	}

	return dump_holes(xfer, pp, &cur_hole, NULL);
}

/*
 * Return:
 *	 1 - if a parent image exists
 *	 0 - if a parent image doesn't exist
 *	-1 - in error cases
 */
int check_parent_local_xfer(int fd_type, unsigned long img_id)
{
	char path[PATH_MAX];
	struct stat st;
	int ret, pfd;

	/* Image streaming lacks support for incremental images */
	if (opts.stream)
		return 0;

	if (open_parent(get_service_fd(IMG_FD_OFF), &pfd))
		return -1;
	if (pfd < 0)
		return 0;

	snprintf(path, sizeof(path), imgset_template[fd_type].fmt, img_id);
	ret = fstatat(pfd, path, &st, 0);
	if (ret == -1 && errno != ENOENT) {
		pr_perror("Unable to stat %s", path);
		close(pfd);
		return -1;
	}

	close(pfd);
	return (ret == 0);
}

/* page server */
static int page_server_check_parent(int sk, struct page_server_iov *pi)
{
	int type, ret;
	unsigned long id;

	type = decode_pm(pi->dst_id, &id);
	if (type == -1) {
		pr_err("Unknown pagemap type received\n");
		return -1;
	}

	ret = check_parent_local_xfer(type, id);
	if (ret < 0)
		return -1;

	if (__send(sk, &ret, sizeof(ret), 0) != sizeof(ret)) {
		pr_perror("Unable to send response");
		return -1;
	}

	return 0;
}

static int check_parent_server_xfer(int fd_type, unsigned long img_id)
{
	struct page_server_iov pi = {};
	int has_parent;

	pi.cmd = PS_IOV_PARENT;
	pi.dst_id = encode_pm(fd_type, img_id);

	if (send_psi(page_server_sk, &pi))
		return -1;

	tcp_nodelay(page_server_sk, true);

	if (__recv(page_server_sk, &has_parent, sizeof(int), 0) != sizeof(int)) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	return has_parent;
}

int check_parent_page_xfer(int fd_type, unsigned long img_id)
{
	if (opts.use_page_server)
		return check_parent_server_xfer(fd_type, img_id);
	else
		return check_parent_local_xfer(fd_type, img_id);
}

struct page_xfer_job {
	u64 dst_id;
	int p[2];
	unsigned pipe_size;
	struct page_xfer loc_xfer;
};

static struct page_xfer_job cxfer = {
	.dst_id = ~0,
};

static struct pipe_read_dest pipe_read_dest = {
	.sink_fd = -1,
};

static void page_server_close(void)
{
	if (cxfer.dst_id != ~0)
		cxfer.loc_xfer.close(&cxfer.loc_xfer);
	if (pipe_read_dest.sink_fd != -1) {
		close(pipe_read_dest.sink_fd);
		close(pipe_read_dest.p[0]);
		close(pipe_read_dest.p[1]);
	}
}

static int page_server_open(int sk, struct page_server_iov *pi)
{
	int type;
	unsigned long id;

	type = decode_pm(pi->dst_id, &id);
	if (type == -1) {
		pr_err("Unknown pagemap type received\n");
		return -1;
	}

	pr_info("Opening %d/%lu\n", type, id);

	page_server_close();

	if (open_page_local_xfer(&cxfer.loc_xfer, type, id))
		return -1;

	cxfer.dst_id = pi->dst_id;

	if (sk >= 0) {
		char has_parent = !!cxfer.loc_xfer.parent;
		if (__send(sk, &has_parent, 1, 0) != 1) {
			pr_perror("Unable to send response");
			close_page_xfer(&cxfer.loc_xfer);
			return -1;
		}
	}

	return 0;
}

static int prep_loc_xfer(struct page_server_iov *pi)
{
	if (cxfer.dst_id != pi->dst_id) {
		pr_warn("Deprecated IO w/o open\n");
		return page_server_open(-1, pi);
	} else
		return 0;
}

static int page_server_add(int sk, struct page_server_iov *pi, u32 flags)
{
	size_t len;
	struct page_xfer *lxfer = &cxfer.loc_xfer;
	struct iovec iov;

	pr_debug("Adding %" PRIx64 "/%u\n", pi->vaddr, pi->nr_pages);

	if (prep_loc_xfer(pi))
		return -1;

	psi2iovec(pi, &iov);
	if (lxfer->write_pagemap(lxfer, &iov, flags))
		return -1;

	if (!(flags & PE_PRESENT))
		return 0;

	len = iov.iov_len;
	while (len > 0) {
		ssize_t chunk;

		chunk = len;
		if (chunk > cxfer.pipe_size)
			chunk = cxfer.pipe_size;

		/*
		 * Splicing into a pipe may end up blocking if pipe is "full",
		 * and we need the SPLICE_F_NONBLOCK flag here. At the same time
		 * splicing from UNIX socket with this flag aborts splice with
		 * the EAGAIN if there's no data in it (TCP looks at the socket
		 * O_NONBLOCK flag _only_ and waits for data), so before doing
		 * the non-blocking splice we need to explicitly wait.
		 */

		if (sk_wait_data(sk) < 0) {
			pr_perror("Can't poll socket");
			return -1;
		}

		if (opts.tls) {
			if (tls_recv_data_to_fd(cxfer.p[1], chunk)) {
				pr_err("Can't read from socket\n");
				return -1;
			}
		} else {
			chunk = splice(sk, NULL, cxfer.p[1], NULL, chunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

			if (chunk < 0) {
				pr_perror("Can't read from socket");
				return -1;
			}
			if (chunk == 0) {
				pr_err("A socket was closed unexpectedly\n");
				return -1;
			}
		}

		if (lxfer->write_pages(lxfer, cxfer.p[0], chunk))
			return -1;

		len -= chunk;
	}

	return 0;
}

static int page_server_get_pages(int sk, struct page_server_iov *pi)
{
	struct pstree_item *item;
	struct page_pipe *pp;
	unsigned long len;
	int ret;

	item = pstree_item_by_virt(pi->dst_id);
	pp = dmpi(item)->mem_pp;

	ret = page_pipe_read(pp, &pipe_read_dest, pi->vaddr, &pi->nr_pages, PPB_LAZY);
	if (ret)
		return ret;

	/*
	 * The pi is reused for send_psi here, so .nr_pages, .vaddr and
	 * .dst_id all remain intact.
	 */

	if (pi->nr_pages == 0) {
		pr_debug("no iovs found, zero pages\n");
		return -1;
	}

	pi->cmd = encode_ps_cmd(PS_IOV_ADD_F, PE_PRESENT);
	if (send_psi(sk, pi))
		return -1;

	len = pi->nr_pages * PAGE_SIZE;

	if (opts.tls) {
		if (tls_send_data_from_fd(pipe_read_dest.p[0], len))
			return -1;
	} else {
		ret = splice(pipe_read_dest.p[0], NULL, sk, NULL, len, SPLICE_F_MOVE);
		if (ret != len)
			return -1;
	}

	tcp_nodelay(sk, true);

	return 0;
}

static int page_server_serve(int sk)
{
	int ret = -1;
	bool flushed = false;
	bool receiving_pages = !opts.lazy_pages;

	if (receiving_pages) {
		/*
		 * This socket only accepts data except one thing -- it
		 * writes back the has_parent bit from time to time, so
		 * make it NODELAY all the time.
		 */
		tcp_nodelay(sk, true);

		if (pipe(cxfer.p)) {
			pr_perror("Can't make pipe for xfer");
			close(sk);
			return -1;
		}

		cxfer.pipe_size = fcntl(cxfer.p[0], F_GETPIPE_SZ, 0);
		pr_debug("Created xfer pipe size %u\n", cxfer.pipe_size);
	} else {
		pipe_read_dest_init(&pipe_read_dest);
		tcp_cork(sk, true);
	}

	while (1) {
		struct page_server_iov pi;
		u32 cmd;

		ret = __recv(sk, &pi, sizeof(pi), MSG_WAITALL);
		if (!ret)
			break;

		if (ret != sizeof(pi)) {
			pr_perror("Can't read pagemap from socket");
			ret = -1;
			break;
		}

		flushed = false;
		cmd = decode_ps_cmd(pi.cmd);

		switch (cmd) {
		case PS_IOV_OPEN:
			ret = page_server_open(-1, &pi);
			break;
		case PS_IOV_OPEN2:
			ret = page_server_open(sk, &pi);
			break;
		case PS_IOV_PARENT:
			ret = page_server_check_parent(sk, &pi);
			break;
		case PS_IOV_ADD_F:
		case PS_IOV_ADD:
		case PS_IOV_HOLE: {
			u32 flags;

			if (likely(cmd == PS_IOV_ADD_F))
				flags = decode_ps_flags(pi.cmd);
			else if (cmd == PS_IOV_ADD)
				flags = PE_PRESENT;
			else /* PS_IOV_HOLE */
				flags = PE_PARENT;

			ret = page_server_add(sk, &pi, flags);
			break;
		}
		case PS_IOV_CLOSE:
		case PS_IOV_FORCE_CLOSE: {
			int32_t status = 0;

			ret = 0;

			/*
			 * An answer must be sent back to inform another side,
			 * that all data were received
			 */
			if (__send(sk, &status, sizeof(status), 0) != sizeof(status)) {
				pr_perror("Can't send the final package");
				ret = -1;
			}

			flushed = true;
			break;
		}
		case PS_IOV_GET:
			ret = page_server_get_pages(sk, &pi);
			break;
		default:
			pr_err("Unknown command %u\n", pi.cmd);
			ret = -1;
			break;
		}

		if (ret)
			break;
		if (pi.cmd == PS_IOV_CLOSE || pi.cmd == PS_IOV_FORCE_CLOSE)
			break;
	}

	if (receiving_pages && !ret && !flushed) {
		pr_err("The data were not flushed\n");
		ret = -1;
	}

	tls_terminate_session(ret != 0);

	if (ret == 0 && opts.ps_socket == -1) {
		char c;

		/*
		 * Wait when a remote side closes the connection
		 * to avoid TIME_WAIT bucket
		 */
		if (read(sk, &c, sizeof(c)) != 0) {
			pr_perror("Unexpected data");
			ret = -1;
		}
	}

	page_server_close();

	pr_info("Session over\n");

	close(sk);
	return ret;
}

static int fill_page_pipe(struct page_read *pr, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	int i, ret;

	pr->reset(pr);

	while (pr->advance(pr)) {
		unsigned long vaddr = pr->pe->vaddr;

		for (i = 0; i < pr->pe->nr_pages; i++, vaddr += PAGE_SIZE) {
			if (pagemap_in_parent(pr->pe))
				ret = page_pipe_add_hole(pp, vaddr, PP_HOLE_PARENT);
			else
				ret = page_pipe_add_page(pp, vaddr, pagemap_lazy(pr->pe) ? PPB_LAZY : 0);
			if (ret) {
				pr_err("Failed adding page at %lx\n", vaddr);
				return -1;
			}
		}
	}

	list_for_each_entry(ppb, &pp->bufs, l) {
		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];

			if (splice(img_raw_fd(pr->pi), NULL, ppb->p[1], NULL, iov.iov_len, SPLICE_F_MOVE) !=
			    iov.iov_len) {
				pr_perror("Splice failed");
				return -1;
			}
		}
	}

	debug_show_page_pipe(pp);

	return 0;
}

static int page_pipe_from_pagemap(struct page_pipe **pp, int pid)
{
	struct page_read pr;
	int nr_pages = 0;

	if (open_page_read(pid, &pr, PR_TASK) <= 0) {
		pr_err("Failed to open page read for %d\n", pid);
		return -1;
	}

	while (pr.advance(&pr))
		if (pagemap_present(pr.pe))
			nr_pages += pr.pe->nr_pages;

	*pp = create_page_pipe(nr_pages, NULL, 0);
	if (!*pp) {
		pr_err("Cannot create page pipe for %d\n", pid);
		return -1;
	}

	if (fill_page_pipe(&pr, *pp))
		return -1;

	return 0;
}

static int page_server_init_send(void)
{
	struct pstree_item *pi;
	struct page_pipe *pp;

	BUILD_BUG_ON(sizeof(struct dmp_info) > sizeof(struct rst_info));

	if (prepare_dummy_pstree())
		return -1;

	for_each_pstree_item(pi) {
		if (prepare_dummy_task_state(pi))
			return -1;

		if (!task_alive(pi))
			continue;

		if (page_pipe_from_pagemap(&pp, vpid(pi))) {
			pr_err("%d: failed to open page-read\n", vpid(pi));
			return -1;
		}

		/*
		 * prepare_dummy_pstree presumes 'restore' behaviour,
		 * but page_server_get_pages uses dmpi() to get access
		 * to the page-pipe, so we are faking it here.
		 */
		memset(rsti(pi), 0, sizeof(struct rst_info));
		dmpi(pi)->mem_pp = pp;
	}

	return 0;
}

int cr_page_server(bool daemon_mode, bool lazy_dump, int cfd)
{
	int ask = -1;
	int sk = -1;
	int ret;

	if (init_stats(DUMP_STATS))
		return -1;

	if (!opts.lazy_pages)
		up_page_ids_base();
	else if (!lazy_dump)
		if (page_server_init_send())
			return -1;

	if (opts.ps_socket != -1) {
		ask = opts.ps_socket;
		pr_info("Reusing ps socket %d\n", ask);
		goto no_server;
	}

	sk = setup_tcp_server("page", opts.addr, &opts.port);
	if (sk == -1)
		return -1;
no_server:

	if (!daemon_mode && cfd >= 0) {
		struct ps_info info = { .pid = getpid(), .port = opts.port };
		int count;

		count = write(cfd, &info, sizeof(info));
		close_safe(&cfd);
		if (count != sizeof(info)) {
			pr_perror("Unable to write ps_info");
			exit(1);
		}
	}

	ret = run_tcp_server(daemon_mode, &ask, cfd, sk);
	if (ret != 0)
		return ret > 0 ? 0 : -1;

	if (tls_x509_init(ask, true)) {
		close_safe(&sk);
		return -1;
	}

	if (ask >= 0)
		ret = page_server_serve(ask);

	if (daemon_mode)
		exit(ret);

	return ret;
}

static int connect_to_page_server(void)
{
	if (!opts.use_page_server)
		return 0;

	if (opts.ps_socket != -1) {
		page_server_sk = opts.ps_socket;
		pr_info("Reusing ps socket %d\n", page_server_sk);
		goto out;
	}

	page_server_sk = setup_tcp_client(opts.addr);
	if (page_server_sk == -1)
		return -1;

	if (tls_x509_init(page_server_sk, false)) {
		close(page_server_sk);
		return -1;
	}
out:
	/*
	 * CORK the socket at the very beginning. As per ANK
	 * the corked by default socket with sporadic NODELAY-s
	 * on urgent data is the smartest mode ever.
	 */
	tcp_cork(page_server_sk, true);
	return 0;
}

int connect_to_page_server_to_send(void)
{
	return connect_to_page_server();
}

int disconnect_from_page_server(void)
{
	struct page_server_iov pi = {};
	int32_t status = -1;
	int ret = -1;

	if (!opts.use_page_server)
		return 0;

	if (page_server_sk == -1)
		return 0;

	pr_info("Disconnect from the page server\n");

	if (opts.ps_socket != -1)
		/*
		 * The socket might not get closed (held by
		 * the parent process) so we must order the
		 * page-server to terminate itself.
		 */
		pi.cmd = PS_IOV_FORCE_CLOSE;
	else
		pi.cmd = PS_IOV_CLOSE;

	if (send_psi(page_server_sk, &pi))
		goto out;

	if (__recv(page_server_sk, &status, sizeof(status), 0) != sizeof(status)) {
		pr_perror("The page server doesn't answer");
		goto out;
	}

	ret = 0;
out:
	tls_terminate_session(ret != 0);
	close_safe(&page_server_sk);

	return ret ?: status;
}

struct ps_async_read {
	unsigned long rb; /* read bytes */
	unsigned long goal;
	unsigned long nr_pages;

	struct page_server_iov pi;
	void *pages;

	ps_async_read_complete complete;
	void *priv;

	struct list_head l;
};

static LIST_HEAD(async_reads);

static inline void async_read_set_goal(struct ps_async_read *ar, int nr_pages)
{
	ar->goal = sizeof(ar->pi) + nr_pages * PAGE_SIZE;
	ar->nr_pages = nr_pages;
}

static void init_ps_async_read(struct ps_async_read *ar, void *buf, int nr_pages, ps_async_read_complete complete,
			       void *priv)
{
	ar->pages = buf;
	ar->rb = 0;
	ar->complete = complete;
	ar->priv = priv;
	async_read_set_goal(ar, nr_pages);
}

static int page_server_start_async_read(void *buf, int nr_pages, ps_async_read_complete complete, void *priv)
{
	struct ps_async_read *ar;

	ar = xmalloc(sizeof(*ar));
	if (ar == NULL)
		return -1;

	init_ps_async_read(ar, buf, nr_pages, complete, priv);
	list_add_tail(&ar->l, &async_reads);
	return 0;
}

/*
 * There are two possible event types we need to handle:
 * - page info is available as a reply to request_remote_page
 * - page data is available, and it follows page info we've just received
 * Since the on dump side communications are completely synchronous,
 * we can return to epoll right after the reception of page info and
 * for sure the next time socket event will occur we'll get page data
 * related to info we've just received
 */
static int page_server_read(struct ps_async_read *ar, int flags)
{
	int ret, need;
	void *buf;

	if (ar->rb < sizeof(ar->pi)) {
		/* Header */
		buf = ((void *)&ar->pi) + ar->rb;
		need = sizeof(ar->pi) - ar->rb;
	} else {
		/* page-serer may return less pages than we asked for */
		if (ar->pi.nr_pages < ar->nr_pages)
			async_read_set_goal(ar, ar->pi.nr_pages);
		/* Page(s) data itself */
		buf = ar->pages + (ar->rb - sizeof(ar->pi));
		need = ar->goal - ar->rb;
	}

	ret = __recv(page_server_sk, buf, need, flags);
	if (ret < 0) {
		if (flags == MSG_DONTWAIT && (errno == EAGAIN || errno == EINTR)) {
			ret = 0;
		} else {
			pr_perror("Error reading data from page server");
			return -1;
		}
	}

	ar->rb += ret;
	if (ar->rb < ar->goal)
		return 1;

	/*
	 * IO complete -- notify the caller and drop the request
	 */
	BUG_ON(ar->rb > ar->goal);
	return ar->complete((int)ar->pi.dst_id, (unsigned long)ar->pi.vaddr, (int)ar->pi.nr_pages, ar->priv);
}

static int page_server_async_read(struct epoll_rfd *f)
{
	struct ps_async_read *ar;
	int ret;

	BUG_ON(list_empty(&async_reads));
	ar = list_first_entry(&async_reads, struct ps_async_read, l);
	ret = page_server_read(ar, MSG_DONTWAIT);

	if (ret > 0)
		return 0;
	if (!ret) {
		list_del(&ar->l);
		xfree(ar);
	}

	return ret;
}

static int page_server_hangup_event(struct epoll_rfd *rfd)
{
	pr_err("Remote side closed connection\n");
	return -1;
}

static struct epoll_rfd ps_rfd;

int connect_to_page_server_to_recv(int epfd)
{
	if (connect_to_page_server())
		return -1;

	ps_rfd.fd = page_server_sk;
	ps_rfd.read_event = page_server_async_read;
	ps_rfd.hangup_event = page_server_hangup_event;

	return epoll_add_rfd(epfd, &ps_rfd);
}

int request_remote_pages(unsigned long img_id, unsigned long addr, int nr_pages)
{
	struct page_server_iov pi = {
		.cmd = PS_IOV_GET,
		.nr_pages = nr_pages,
		.vaddr = addr,
		.dst_id = img_id,
	};

	/* XXX: why MSG_DONTWAIT here? */
	if (send_psi_flags(page_server_sk, &pi, MSG_DONTWAIT))
		return -1;

	tcp_nodelay(page_server_sk, true);
	return 0;
}

static int page_server_start_sync_read(void *buf, int nr, ps_async_read_complete complete, void *priv)
{
	struct ps_async_read ar;
	int ret = 1;

	init_ps_async_read(&ar, buf, nr, complete, priv);
	while (ret == 1)
		ret = page_server_read(&ar, MSG_WAITALL);
	return ret;
}

int page_server_start_read(void *buf, int nr, ps_async_read_complete complete, void *priv, unsigned flags)
{
	if (flags & PR_ASYNC)
		return page_server_start_async_read(buf, nr, complete, priv);
	else
		return page_server_start_sync_read(buf, nr, complete, priv);
}
