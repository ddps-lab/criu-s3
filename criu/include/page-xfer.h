#ifndef __CR_PAGE_XFER__H__
#define __CR_PAGE_XFER__H__
#include "pagemap.h"

struct ps_info {
	int pid;
	unsigned short port;
};

extern int cr_page_server(bool daemon_mode, bool lazy_dump, int cfd);

/* User buffer for read-mode pre-dump*/
#define PIPE_MAX_BUFFER_SIZE (PIPE_MAX_SIZE << PAGE_SHIFT)

/*
 * page_xfer -- transfer pages into image file.
 * Two images backends are implemented -- local image file
 * and page-server image file.
 */

struct page_xfer {
	/* transfers one vaddr:len entry */
	int (*write_pagemap)(struct page_xfer *self, struct iovec *iov, u32 flags);
	/* transfers pages related to previous pagemap */
	int (*write_pages)(struct page_xfer *self, int pipe, unsigned long len);
	void (*close)(struct page_xfer *self);

	/*
	 * In case we need to dump pagemaps not as-is, but
	 * relative to some address. Used, e.g. by shmem.
	 */
	unsigned long offset;
	bool transfer_lazy;

	/* private data for every page-xfer engine */
	union {
		struct /* local */ {
			struct cr_img *pmi; /* pagemaps */
			struct cr_img *pi;  /* pages */
		};

		struct /* page-server */ {
			int sk;
			u64 dst_id;
		};
	};

	/* S3 upload state (used alongside local when --object-storage-upload) */
	struct {
		char upload_id[256];
		char pages_key[512];
		char pagemap_key[512];
		void *part_buf;
		unsigned long part_buf_used;
		unsigned long part_buf_cap;
		int part_number;
		char **etags;
		int etags_count;
		int etags_cap;
		int active;		/* 1 if S3 upload is in progress */

		/*
		 * When --compress is set and this is the S3 upload path, the
		 * per-IOV frames and multipart parts flow through the
		 * parallel pipeline in compress_pipeline.c instead of the
		 * serial part_buf above. Exactly one of {part_buf path,
		 * compress_pipe path} is active at a time.
		 */
		struct compress_pipeline *compress_pipe;

		/*
		 * Non-compressed S3 upload: optional CURLM-backed parallel
		 * upload pool. When opts.upload_workers > 1 (default), parts
		 * are submitted to this pool instead of being PUT synchronously
		 * by the dump thread, raising effective upload throughput from
		 * ~45 MB/s to aws-s3-cp class (~400 MB/s). See upload_pool.h.
		 */
		struct upload_pool *upload_pool;
	} object_storage;

	/* zstd seekable compression state (set when opts.compress) — local path */
	struct compress_stream *compress;

	struct page_read *parent;
};

extern int open_page_xfer(struct page_xfer *xfer, int fd_type, unsigned long id);
struct page_pipe;
extern int page_xfer_dump_pages(struct page_xfer *, struct page_pipe *);
extern int page_xfer_predump_pages(int pid, struct page_xfer *, struct page_pipe *);
extern int connect_to_page_server_to_send(void);
extern int connect_to_page_server_to_recv(int epfd);
extern int disconnect_from_page_server(void);

extern int check_parent_page_xfer(int fd_type, unsigned long id);

/*
 * Drain any upload_pool instances left pending after per-process page
 * transfers. Each multi-process workload (memcached, redis) closes
 * several page_xfer objects in sequence; the raw-path upload_pools now
 * defer their final upload_pool_wait / multipart_complete so the next
 * process's dump can overlap with the TCP-level tail of the previous
 * uploads. This function blocks until every pending pool has all PUTs
 * accepted and issues the multipart completes. Safe to call when no
 * pools are pending (no-op). Returns 0 on success, -1 if any pool
 * failed.
 */
extern int page_xfer_drain_deferred_uploads(void);

/*
 * The post-copy migration makes it necessary to receive pages from
 * remote dump. The protocol we use for that is quite simple:
 * - lazy-pages sends request containing PS_IOV_GET(nr_pages, vaddr, pid)
 * - dump-side page server responds with PS_IOV_ADD(nr_pages, vaddr,
     pid) or PS_IOV_ADD(0, 0, 0) if it failed to locate the required
     pages
 * - dump-side page server sends the raw page data
 */

/* async request/receive of remote pages */
extern int request_remote_pages(unsigned long img_id, unsigned long addr, int nr_pages);

typedef int (*ps_async_read_complete)(unsigned long img_id, unsigned long vaddr, int nr_pages, void *);
extern int page_server_start_read(void *buf, int nr_pages, ps_async_read_complete complete, void *priv, unsigned flags);

#endif /* __CR_PAGE_XFER__H__ */
