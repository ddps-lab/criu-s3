#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include "crtools.h"
#include "cr_options.h"
#include "imgset.h"
#include "image.h"
#include "pstree.h"
#include "stats.h"
#include "cgroup.h"
#include "lsm.h"
#include "protobuf.h"
#include "xmalloc.h"
#include "images/inventory.pb-c.h"
#include "images/pagemap.pb-c.h"
#include "proc_parse.h"
#include "img-streamer.h"
#include "namespaces.h"
#include "object-storage.h"
#include "obstor_prefetch.h"
#include "compression.h"

bool ns_per_id = false;
bool img_common_magic = true;
TaskKobjIdsEntry *root_ids;
u32 root_cg_set;
Lsmtype image_lsm;
char dump_criu_run_id[RUN_ID_HASH_LENGTH];

struct inventory_plugin {
	struct list_head node;
	char *name;
};

struct list_head inventory_plugins_list = LIST_HEAD_INIT(inventory_plugins_list);
static int n_inventory_plugins;

int check_img_inventory(bool restore)
{
	int ret = -1;
	struct cr_img *img;
	InventoryEntry *he;

	img = open_image(CR_FD_INVENTORY, O_RSTR);
	if (!img)
		return -1;

	if (pb_read_one(img, &he, PB_INVENTORY) < 0)
		goto out_close;

	if (!he->has_fdinfo_per_id || !he->fdinfo_per_id) {
		pr_err("Too old image, no longer supported\n");
		goto out_close;
	}

	ns_per_id = he->has_ns_per_id ? he->ns_per_id : false;

	if (he->root_ids) {
		root_ids = xmalloc(sizeof(*root_ids));
		if (!root_ids)
			goto out_err;

		memcpy(root_ids, he->root_ids, sizeof(*root_ids));
	}

	if (he->has_root_cg_set) {
		if (he->root_cg_set == 0) {
			pr_err("Corrupted root cgset\n");
			goto out_err;
		}

		root_cg_set = he->root_cg_set;
	}

	if (he->has_lsmtype)
		image_lsm = he->lsmtype;
	else
		image_lsm = LSMTYPE__NO_LSM;

	switch (he->img_version) {
	case CRTOOLS_IMAGES_V1:
		/* good old images. OK */
		img_common_magic = false;
		break;
	case CRTOOLS_IMAGES_V1_1:
		/* newer images with extra magic in the head */
		break;
	default:
		pr_err("Not supported images version %u\n", he->img_version);
		goto out_err;
	}

	if (restore && he->tcp_close && !opts.tcp_close) {
		pr_err("Need to set the --tcp-close options.\n");
		goto out_err;
	}

	if (restore) {
		if (!he->has_network_lock_method) {
			/*
			 * Image files were generated with an older version of CRIU
			 * so we should fall back to iptables because this is the
			 * network-lock mechanism used in older versions.
			 */
			pr_info("Network lock method not found in inventory image\n");
			pr_info("Falling back to iptables network lock method\n");
			opts.network_lock_method = NETWORK_LOCK_IPTABLES;
		} else {
			opts.network_lock_method = he->network_lock_method;
		}

		if (!he->plugins_entry) {
			/* backwards compatibility: if the 'plugins_entry' field is missing,
			 * all plugins should be enabled during restore.
			 */
			n_inventory_plugins = -1;
		} else {
			PluginsEntry *pe = he->plugins_entry;
			for (int i = 0; i < pe->n_plugins; i++) {
				if (add_inventory_plugin(pe->plugins[i]))
					goto out_err;
			}
		}

		/**
		 * This contains the criu_run_id during dumping of the process.
		 * For things like removing network locking (nftables) this
		 * information is needed to identify the name of the network
		 * locking table.
		 */
		if (he->dump_criu_run_id) {
			strncpy(dump_criu_run_id, he->dump_criu_run_id, sizeof(dump_criu_run_id) - 1);
			pr_info("Dump CRIU run id = %s\n", dump_criu_run_id);
		} else {
			/**
			 * If restoring from an old image this is a marker
			 * that no dump_criu_run_id exists.
			 */
			dump_criu_run_id[0] = NO_DUMP_CRIU_RUN_ID;
		}

	}

	ret = 0;

out_err:
	inventory_entry__free_unpacked(he, NULL);
out_close:
	close_image(img);
	return ret;
}

/**
 * Check if the 'plugins' field in the inventory image contains
 * the specified plugin name. If found, the plugin is removed
 * from the linked list.
 */
bool check_and_remove_inventory_plugin(const char *name, size_t n)
{
	if (n_inventory_plugins == -1)
		return true; /* backwards compatibility */

	if (n_inventory_plugins > 0) {
		struct inventory_plugin *p, *tmp;

		list_for_each_entry_safe(p, tmp, &inventory_plugins_list, node) {
			if (!strncmp(name, p->name, n)) {
				xfree(p->name);
				list_del(&p->node);
				xfree(p);
				n_inventory_plugins--;
				return true;
			}
		}
	}

	return false;
}

/**
 * We expect during restore all loaded plugins to be removed from
 * the inventory_plugins_list. If the list is not empty, show an
 * error message for each missing plugin.
 */
int check_inventory_plugins(void)
{
	struct inventory_plugin *p;

	if (n_inventory_plugins <= 0)
		return 0;

	list_for_each_entry(p, &inventory_plugins_list, node) {
		pr_err("Missing required plugin: %s\n", p->name);
	}

	return -1;
}

/**
 * Add plugin name to the inventory image. These values
 * can be used to identify required plugins during restore.
 */
int add_inventory_plugin(const char *name)
{
	struct inventory_plugin *p;

	p = xmalloc(sizeof(struct inventory_plugin));
	if (p == NULL)
		return -1;

	p->name = xstrdup(name);
	if (!p->name) {
		xfree(p);
		return -1;
	}
	list_add(&p->node, &inventory_plugins_list);
	n_inventory_plugins++;

	return 0;
}

void free_inventory_plugins_list(void)
{
	struct inventory_plugin *p, *tmp;

	if (!list_empty(&inventory_plugins_list)) {
		list_for_each_entry_safe(p, tmp, &inventory_plugins_list, node) {
			xfree(p->name);
			list_del(&p->node);
			xfree(p);
		}
	}
	n_inventory_plugins = 0;
}

int write_img_inventory(InventoryEntry *he)
{
	PluginsEntry pe = PLUGINS_ENTRY__INIT;
	struct cr_img *img;
	int ret;

	pr_info("Writing image inventory (version %u)\n", CRTOOLS_IMAGES_V1);

	img = open_image(CR_FD_INVENTORY, O_DUMP);
	if (!img)
		return -1;

	if (!list_empty(&inventory_plugins_list)) {
		struct inventory_plugin *p;
		int i = 0;

		pe.n_plugins = n_inventory_plugins;
		pe.plugins = xmalloc(n_inventory_plugins * sizeof(char *));
		if (!pe.plugins)
			return -1;

		list_for_each_entry(p, &inventory_plugins_list, node) {
			pe.plugins[i] = p->name;
			i++;
		}
	}
	he->plugins_entry = &pe;

	ret = pb_write_one(img, he, PB_INVENTORY);

	free_inventory_plugins_list();
	xfree(pe.plugins);

	xfree(he->root_ids);
	close_image(img);
	if (ret < 0)
		return -1;
	return 0;
}

int inventory_save_uptime(InventoryEntry *he)
{
	if (!opts.track_mem)
		return 0;

	/*
	 * dump_uptime is used to detect whether a process was handled
	 * before or it is a new process with the same pid.
	 */
	if (parse_uptime(&he->dump_uptime))
		return -1;

	he->has_dump_uptime = true;
	return 0;
}

/*
 * This function is intended to get an inventory image from previous (parent)
 * dump iteration. We use dump_uptime from the image in detect_pid_reuse().
 *
 * You see that these function never fails by itself, it only prints warnings
 * to better understand reasons why we don't found a proper image, failing here
 * is too early. We get to detect_pid_reuse() only if we have a parent pagemap
 * and that's the proper place to fail: we know that there is a parent pagemap
 * but we don't have (can't access, etc) parent inventory => can't detect
 * pid-reuse => fail.
 */

InventoryEntry *get_parent_inventory(void)
{
	struct cr_img *img;
	InventoryEntry *ie;
	int dir;
	char *saved_prefix = NULL;
	char *parent_prefix = NULL;

	if (open_parent(get_service_fd(IMG_FD_OFF), &dir)) {
		pr_warn("Failed to open parent directory\n");
		return NULL;
	}
	if (dir < 0)
		return NULL;

	/*
	 * When object storage is enabled, swap prefix to parent's
	 * so that S3 fallback fetches from the correct location.
	 */
	if (opts.enable_object_storage) {
		void *prefix_data = NULL;
		unsigned long prefix_len = 0;
		int s3_ret;

		s3_ret = object_storage_get_object("parent-prefix",
						   &prefix_data, &prefix_len);
		if (s3_ret == 0 && prefix_data && prefix_len > 0) {
			parent_prefix = xmalloc(prefix_len + 1);
			if (parent_prefix) {
				memcpy(parent_prefix, prefix_data, prefix_len);
				parent_prefix[prefix_len] = '\0';
				saved_prefix = opts.object_storage_object_prefix;
				opts.object_storage_object_prefix = parent_prefix;
			}
		}
		if (prefix_data)
			free(prefix_data);
	}

	img = open_image_at(dir, CR_FD_INVENTORY, O_RSTR);
	if (!img) {
		pr_warn("Failed to open parent pre-dump inventory image\n");
		if (saved_prefix) {
			opts.object_storage_object_prefix = saved_prefix;
			xfree(parent_prefix);
		}
		close(dir);
		return NULL;
	}

	if (pb_read_one(img, &ie, PB_INVENTORY) < 0) {
		pr_warn("Failed to read parent pre-dump inventory entry\n");
		close_image(img);
		if (saved_prefix) {
			opts.object_storage_object_prefix = saved_prefix;
			xfree(parent_prefix);
		}
		close(dir);
		return NULL;
	}

	/* Restore original prefix */
	if (saved_prefix) {
		opts.object_storage_object_prefix = saved_prefix;
		xfree(parent_prefix);
	}

	if (!ie->has_dump_uptime) {
		pr_warn("Parent pre-dump inventory has no uptime\n");
		inventory_entry__free_unpacked(ie, NULL);
		ie = NULL;
	}

	close_image(img);
	close(dir);
	return ie;
}

int prepare_inventory(InventoryEntry *he)
{
	struct pid pid;
	struct {
		struct pstree_item i;
		struct dmp_info d;
	} crt = { .i.pid = &pid };

	pr_info("Preparing image inventory (version %u)\n", CRTOOLS_IMAGES_V1);

	he->img_version = CRTOOLS_IMAGES_V1_1;
	he->fdinfo_per_id = true;
	he->has_fdinfo_per_id = true;
	he->ns_per_id = true;
	he->has_ns_per_id = true;
	he->has_lsmtype = true;
	he->lsmtype = host_lsm_type();

	crt.i.pid->state = TASK_ALIVE;
	crt.i.pid->real = getpid();
	if (get_task_ids(&crt.i))
		return -1;

	if (!opts.unprivileged)
		he->has_root_cg_set = true;
	if (dump_thread_cgroup(NULL, &he->root_cg_set, NULL, -1))
		return -1;

	he->root_ids = crt.i.ids;

	/* tcp_close has to be set on restore if it has been set on dump. */
	if (opts.tcp_close) {
		he->tcp_close = true;
		he->has_tcp_close = true;
	}

	/* Save network lock method to reuse in restore */
	he->has_network_lock_method = true;
	he->network_lock_method = opts.network_lock_method;

	/**
	 * This contains the criu_run_id during dumping of the process.
	 * For things like removing network locking (nftables) this
	 * information is needed to identify the name of the network
	 * locking table.
	 */
	he->dump_criu_run_id = xstrdup(criu_run_id);

	if (!he->dump_criu_run_id)
		return -1;

	return 0;
}

static struct cr_imgset *alloc_cr_imgset(int nr)
{
	struct cr_imgset *cr_imgset;
	unsigned int i;

	cr_imgset = xmalloc(sizeof(*cr_imgset));
	if (cr_imgset == NULL)
		return NULL;

	cr_imgset->_imgs = xmalloc(nr * sizeof(struct cr_img *));
	if (cr_imgset->_imgs == NULL) {
		xfree(cr_imgset);
		return NULL;
	}

	for (i = 0; i < nr; i++)
		cr_imgset->_imgs[i] = NULL;
	cr_imgset->fd_nr = nr;
	return cr_imgset;
}

static void __close_cr_imgset(struct cr_imgset *cr_imgset)
{
	unsigned int i;

	if (!cr_imgset)
		return;

	for (i = 0; i < cr_imgset->fd_nr; i++) {
		if (!cr_imgset->_imgs[i])
			continue;
		close_image(cr_imgset->_imgs[i]);
		cr_imgset->_imgs[i] = NULL;
	}
}

void close_cr_imgset(struct cr_imgset **cr_imgset)
{
	if (!cr_imgset || !*cr_imgset)
		return;

	__close_cr_imgset(*cr_imgset);

	xfree((*cr_imgset)->_imgs);
	xfree(*cr_imgset);
	*cr_imgset = NULL;
}

struct cr_imgset *cr_imgset_open_range(int pid, int from, int to, unsigned long flags)
{
	struct cr_imgset *imgset;
	unsigned int i;

	imgset = alloc_cr_imgset(to - from);
	if (!imgset)
		goto err;

	from++;
	imgset->fd_off = from;
	for (i = from; i < to; i++) {
		struct cr_img *img;

		img = open_image(i, flags, pid);
		if (!img) {
			if (!(flags & O_CREAT))
				/* caller should check himself */
				continue;
			goto err;
		}

		imgset->_imgs[i - from] = img;
	}

	return imgset;

err:
	close_cr_imgset(&imgset);
	return NULL;
}

struct cr_imgset *cr_task_imgset_open(int pid, int mode)
{
	return cr_imgset_open(pid, TASK, mode);
}

struct cr_imgset *cr_glob_imgset_open(int mode)
{
	return cr_imgset_open(-1 /* ignored */, GLOB, mode);
}

static int do_open_image(struct cr_img *img, int dfd, int type, unsigned long flags, char *path);
static void maybe_swap_compressed_pages(struct cr_img *img, u32 pages_img_id);

struct cr_img *open_image_at(int dfd, int type, unsigned long flags, ...)
{
	struct cr_img *img;
	unsigned long oflags;
	char path[PATH_MAX];
	va_list args;
	bool lazy = false;

	if (dfd == -1) {
		dfd = get_service_fd(IMG_FD_OFF);
		lazy = (flags & O_CREAT);
	}

	img = xmalloc(sizeof(*img));
	if (!img)
		return NULL;
	img->path = NULL;

	oflags = flags | imgset_template[type].oflags;

	va_start(args, flags);
	vsnprintf(path, PATH_MAX, imgset_template[type].fmt, args);
	va_end(args);

	if (lazy) {
		img->fd = LAZY_IMG_FD;
		img->type = type;
		img->oflags = oflags;
		img->path = xstrdup(path);
		return img;
	} else
		img->fd = EMPTY_IMG_FD;

	if (do_open_image(img, dfd, type, oflags, path)) {
		close_image(img);
		return NULL;
	}

	/*
	 * Transparent zstd-seekable decompression for every restore-side open
	 * of a pages-*.img. Both open_pages_image_at() (page-read path) and
	 * open_image(CR_FD_PAGES, ...) (prepare_vma_ios parasite path) funnel
	 * through here, so any compressed pages image is swapped to a shared
	 * decompressed memfd before any caller sees the fd. Id is recovered
	 * from the already-formatted path so we don't have to change the
	 * public signature.
	 */
	if (type == CR_FD_PAGES && (oflags & O_ACCMODE) == O_RDONLY) {
		unsigned int pages_img_id = 0;
		if (sscanf(path, "pages-%u.img", &pages_img_id) == 1)
			maybe_swap_compressed_pages(img, (u32)pages_img_id);
	}

	return img;
}

static inline u32 head_magic(int oflags)
{
	return oflags & O_SERVICE ? IMG_SERVICE_MAGIC : IMG_COMMON_MAGIC;
}

static int img_check_magic(struct cr_img *img, int oflags, int type, char *path)
{
	u32 magic;

	if (read_img(img, &magic) < 0)
		return -1;

	if (img_common_magic && (type != CR_FD_INVENTORY)) {
		if (magic != head_magic(oflags)) {
			pr_err("Head magic doesn't match for %s\n", path);
			return -1;
		}

		if (read_img(img, &magic) < 0)
			return -1;
	}

	if (magic != imgset_template[type].magic) {
		pr_err("Magic doesn't match for %s\n", path);
		return -1;
	}

	return 0;
}

static int img_write_magic(struct cr_img *img, int oflags, int type)
{
	if (img_common_magic && (type != CR_FD_INVENTORY)) {
		u32 cmagic;

		cmagic = head_magic(oflags);
		if (write_img(img, &cmagic))
			return -1;
	}

	return write_img(img, &imgset_template[type].magic);
}

struct openat_args {
	char path[PATH_MAX];
	int flags;
	int err;
	int mode;
};

static int userns_openat(void *arg, int dfd, int pid)
{
	struct openat_args *pa = (struct openat_args *)arg;
	int ret;

	ret = openat(dfd, pa->path, pa->flags, pa->mode);
	if (ret < 0)
		pa->err = errno;

	return ret;
}

static int do_open_image(struct cr_img *img, int dfd, int type, unsigned long oflags, char *path)
{
	int ret, flags;

	flags = oflags & ~(O_NOBUF | O_SERVICE | O_FORCE_LOCAL);

	if (opts.stream && !(oflags & O_FORCE_LOCAL)) {
		ret = img_streamer_open(path, flags);
		errno = EIO; /* errno value is meaningless, only the ret value is meaningful */
	} else if (root_ns_mask & CLONE_NEWUSER && type == CR_FD_PAGES && oflags & O_RDWR) {
		/*
		 * For pages images dedup we need to open images read-write on
		 * restore, that may require proper capabilities, so we ask
		 * usernsd to do it for us
		 */
		struct openat_args pa = {
			.flags = flags,
			.err = 0,
			.mode = CR_FD_PERM,
		};
		snprintf(pa.path, PATH_MAX, "%s", path);
		ret = userns_call(userns_openat, UNS_FDOUT, &pa, sizeof(struct openat_args), dfd);
		if (ret < 0)
			errno = pa.err;
	} else if (opts.object_storage_upload && (flags & O_CREAT)) {
		/*
		 * Object storage upload mode: use memfd instead of local file.
		 * All writes go to memory, uploaded to S3 on close_image().
		 * Eliminates disk I/O entirely for metadata files.
		 */
		ret = memfd_create(path, 0);
	} else
		ret = openat(dfd, path, flags, CR_FD_PERM);
	if (ret < 0) {
		if (!(flags & O_CREAT) && (errno == ENOENT || ret == -ENOENT)) {
			/*
			 * File not found locally. If object storage is enabled,
			 * try fetching from S3 and create a memfd for it.
			 *
			 * Skip pages-*.img: when enable_object_storage is set,
			 * pages are read on-demand via
			 * maybe_read_page_object_storage() using range
			 * requests. Downloading the entire pages file into a
			 * memfd wastes bandwidth and occupies fd numbers that
			 * conflict with the restored process.
			 */
			if (opts.enable_object_storage &&
			    type != CR_FD_PAGES) {
				void *s3_data = NULL;
				unsigned long s3_len = 0;
				int s3_ret;
				int mfd;
				const void *cache_data = NULL;
				size_t cache_len = 0;
				bool from_cache = false;

				/*
				 * Phase 6 bulk metadata prefetch: if this file
				 * was pre-fetched at restore/lazy-pages init, serve
				 * it from the in-memory cache and skip the S3 GET.
				 * On miss: if the prefetch cache is authoritative
				 * (LIST succeeded), treat the miss as "object does
				 * not exist" so we skip a wasted 404 round-trip
				 * (CRIU opens many optional files that don't exist
				 * in any given checkpoint — each one costs ~25ms on
				 * real S3). If prefetch init failed, fall through
				 * to the existing sync path for safety.
				 */
				if (obstor_prefetch_lookup(path, &cache_data, &cache_len) == 0) {
					s3_data = xmalloc(cache_len ? cache_len : 1);
					if (s3_data) {
						if (cache_len)
							memcpy(s3_data, cache_data, cache_len);
						s3_len = cache_len;
						s3_ret = 0;
						from_cache = true;
					} else {
						s3_ret = -1;
					}
				} else if (obstor_prefetch_is_authoritative()) {
					s3_data = NULL;
					s3_len = 0;
					s3_ret = -ENOENT;
				} else {
					s3_ret = object_storage_get_object(path, &s3_data, &s3_len);
				}
				(void)from_cache;
				if (s3_ret == 0 && s3_data && s3_len > 0) {
					mfd = memfd_create(path, 0);
					if (mfd >= 0) {
						unsigned long wr = 0;
						ssize_t nw;

						mfd = relocate_internal_fd(mfd);

						while (wr < s3_len) {
							nw = write(mfd, (char *)s3_data + wr, s3_len - wr);
							if (nw <= 0)
								break;
							wr += nw;
						}
						free(s3_data);
						if (wr == s3_len) {
							lseek(mfd, 0, SEEK_SET);
							ret = mfd;
							pr_info("Fetched %s from object storage (%lu bytes)\n",
								path, s3_len);
							goto got_fd;
						}
						close(mfd);
					} else {
						free(s3_data);
					}
				} else if (s3_data) {
					free(s3_data);
				}
			}

			pr_info("No %s image\n", path);
			img->_x.fd = EMPTY_IMG_FD;
			goto skip_magic;
		}

		pr_perror("Unable to open %s", path);
		goto err;
	}

got_fd:

	img->_x.fd = ret;

	/*
	 * When object-storage-upload is enabled and we're writing (O_DUMP),
	 * save the filename so close_image() can upload to S3.
	 * We reuse the 'path' field that's normally only used for lazy images.
	 */
	if (opts.object_storage_upload && (flags & O_CREAT)) {
		img->path = xstrdup(path);
	}

	if (oflags & O_NOBUF)
		bfd_setraw(&img->_x);
	else {
		if (flags == O_RDONLY)
			ret = bfdopenr(&img->_x);
		else
			ret = bfdopenw(&img->_x);

		if (ret)
			goto err;
	}

	if (imgset_template[type].magic == RAW_IMAGE_MAGIC)
		goto skip_magic;

	if (flags == O_RDONLY)
		ret = img_check_magic(img, oflags, type, path);
	else
		ret = img_write_magic(img, oflags, type);
	if (ret)
		goto err;

skip_magic:
	return 0;

err:
	return -1;
}

int open_image_lazy(struct cr_img *img)
{
	int dfd;
	char *path = img->path;

	img->path = NULL;

	dfd = get_service_fd(IMG_FD_OFF);
	if (do_open_image(img, dfd, img->type, img->oflags, path)) {
		xfree(path);
		return -1;
	}

	xfree(path);
	return 0;
}

void close_image(struct cr_img *img)
{
	if (lazy_image(img)) {
		/*
		 * Remove the image file if it's there so that
		 * subsequent restore doesn't read wrong or fake
		 * data from it.
		 */
		unlinkat(get_service_fd(IMG_FD_OFF), img->path, 0);
		xfree(img->path);
	} else if (!empty_image(img)) {
		/*
		 * Upload metadata files to S3 on close (dual-write).
		 * Skip pages-*.img as those are handled by page-xfer S3 backend.
		 */
		if (opts.object_storage_upload && img->path &&
		    strncmp(img->path, "pages-", 6) != 0) {
			int fd;
			off_t file_size;

			/*
			 * Dup the fd before bclose() closes it, so we can
			 * read back the written data for S3 upload.
			 * Works with both memfd (S3-only) and local files (dual-write).
			 */
			fd = dup(img->_x.fd);
			bclose(&img->_x);

			if (fd >= 0) {
				file_size = lseek(fd, 0, SEEK_END);
				if (file_size > 0) {
					void *buf;
					ssize_t nr;
					unsigned long rd;

					lseek(fd, 0, SEEK_SET);
					buf = malloc(file_size);
					if (buf) {
						rd = 0;
						while (rd < (unsigned long)file_size) {
							nr = read(fd, (char *)buf + rd,
								  file_size - rd);
							if (nr <= 0)
								break;
							rd += nr;
						}
						if (rd == (unsigned long)file_size) {
							/*
							 * Hand the buffer to the async-put
							 * pool: workers PUT in parallel and
							 * free the data. cr_dump_finish
							 * drains the pool before writing
							 * manifest+bundle to ensure all
							 * uploads have landed.
							 */
							if (object_storage_put_object_async(
								    img->path, buf,
								    file_size) != 0) {
								/* Enqueue failed (OOM); fall back
								 * to sync PUT and free locally. */
								object_storage_put_object(
									img->path, buf,
									file_size);
								free(buf);
							}
						} else {
							free(buf);
						}
					}
				}
				close(fd);
			}
			xfree(img->path);
		} else {
			if (img->path)
				xfree(img->path);
			bclose(&img->_x);
		}
	}

	xfree(img);
}

struct cr_img *img_from_fd(int fd)
{
	struct cr_img *img;

	img = xmalloc(sizeof(*img));
	if (img) {
		img->_x.fd = fd;
		img->path = NULL;
		bfd_setraw(&img->_x);
	}

	return img;
}

/*
 * `mode` should be O_RSTR or O_DUMP depending on the intent.
 * This is used when opts.stream is enabled for picking the right streamer
 * socket name. `mode` is ignored when opts.stream is not enabled.
 */
int open_image_dir(char *dir, int mode)
{
	int fd, ret;

	fd = open(dir, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open dir %s", dir);
		return -1;
	}

	ret = install_service_fd(IMG_FD_OFF, fd);
	if (ret < 0) {
		pr_err("install_service_fd failed.\n");
		return -1;
	}
	fd = ret;

	if (opts.stream) {
		if (img_streamer_init(dir, mode) < 0)
			goto err;
	} else if (opts.img_parent) {
		if (faccessat(fd, opts.img_parent, R_OK, 0)) {
			if (!opts.enable_object_storage) {
				pr_perror("Invalid parent image directory provided");
				goto err;
			}
			pr_info("Parent dir %s not found locally, skipping symlink (object storage mode)\n",
				opts.img_parent);
		} else {
			ret = symlinkat(opts.img_parent, fd, CR_PARENT_LINK);
			if (ret < 0 && errno != EEXIST) {
				pr_perror("Can't link parent snapshot");
				goto err;
			}

			if (opts.img_parent[0] == '/')
				pr_warn("Absolute paths for parent links "
					"may not work on restore!\n");
		}

		/*
		 * Upload parent prefix info to S3 so restore can find parent.
		 * Convention: resolve --prev-images-dir relative to current prefix.
		 * E.g., prefix="ckpt/dump2/", parent="../dump1/" → "ckpt/dump1/"
		 */
		if (opts.object_storage_upload && opts.object_storage_object_prefix) {
			char parent_prefix[1024];
			const char *cur = opts.object_storage_object_prefix;
			const char *rel = opts.img_parent;
			size_t cur_len;
			size_t pp_len;

			/* Copy current prefix and resolve relative path */
			snprintf(parent_prefix, sizeof(parent_prefix), "%s", cur);
			cur_len = strlen(parent_prefix);
			/* Remove trailing slash */
			if (cur_len > 0 && parent_prefix[cur_len - 1] == '/')
				parent_prefix[--cur_len] = '\0';

			/* Process "../" segments */
			while (strncmp(rel, "../", 3) == 0) {
				char *last_slash;
				rel += 3;
				last_slash = strrchr(parent_prefix, '/');
				if (last_slash)
					*last_slash = '\0';
				else
					parent_prefix[0] = '\0';
			}
			/* Append remaining relative path */
			if (rel[0]) {
				pp_len = strlen(parent_prefix);
				if (pp_len > 0)
					snprintf(parent_prefix + pp_len,
						 sizeof(parent_prefix) - pp_len, "/%s", rel);
				else
					snprintf(parent_prefix, sizeof(parent_prefix), "%s", rel);
			}
			/* Ensure trailing slash */
			pp_len = strlen(parent_prefix);
			if (pp_len > 0 && parent_prefix[pp_len - 1] != '/') {
				parent_prefix[pp_len] = '/';
				parent_prefix[pp_len + 1] = '\0';
			}

			pr_info("Uploading parent prefix marker: %s\n", parent_prefix);
			object_storage_put_object("parent-prefix",
						  parent_prefix, strlen(parent_prefix));
		}
	}

	/*
	 * On restore: if images-dir contains a parent-prefix file
	 * (downloaded from S3) but no parent symlink, reconstruct
	 * the parent symlink from parent-prefix content.
	 *
	 * parent-prefix contains the S3 prefix of the parent dump
	 * (e.g., "chain/dump1/"). We extract the directory name
	 * (e.g., "dump1") and create a symlink "../dump1" → parent.
	 */
	if (mode == O_RSTR && !opts.img_parent) {
		struct stat st;
		if (fstatat(fd, CR_PARENT_LINK, &st, AT_SYMLINK_NOFOLLOW) != 0 &&
		    errno == ENOENT) {
			/* No parent symlink — check for parent-prefix file */
			int ppfd;
			ppfd = openat(fd, "parent-prefix", O_RDONLY);
			if (ppfd >= 0) {
				char pp_buf[1024];
				ssize_t nr;
				nr = read(ppfd, pp_buf, sizeof(pp_buf) - 1);
				close(ppfd);
				if (nr > 0) {
					char *last_slash;
					char *dir_name;
					char symlink_target[1024];

					pp_buf[nr] = '\0';
					/* Remove trailing slash/newline */
					while (nr > 0 && (pp_buf[nr-1] == '/' || pp_buf[nr-1] == '\n'))
						pp_buf[--nr] = '\0';

					/* Extract last component: "chain/dump1" → "dump1" */
					last_slash = strrchr(pp_buf, '/');
					dir_name = last_slash ? last_slash + 1 : pp_buf;

					/* Create symlink: ../dump1 */
					snprintf(symlink_target, sizeof(symlink_target),
						 "../%.1020s", dir_name);

					/* Verify target exists */
					if (faccessat(fd, symlink_target, R_OK, 0) == 0) {
						ret = symlinkat(symlink_target, fd, CR_PARENT_LINK);
						if (ret == 0 || errno == EEXIST)
							pr_info("Reconstructed parent symlink: %s\n",
								symlink_target);
						else
							pr_warn("Failed to create parent symlink %s\n",
								symlink_target);
					} else {
						pr_debug("Parent dir %s not found locally, "
							 "skipping symlink reconstruction\n",
							 symlink_target);
					}
				}
			}
		}
	}

	return 0;

err:
	close_image_dir();
	return -1;
}

void close_image_dir(void)
{
	if (opts.stream)
		img_streamer_finish();
	close_service_fd(IMG_FD_OFF);
}

int open_parent(int dfd, int *pfd)
{
	struct stat st;

	*pfd = -1;
	/* Check if the parent symlink exists */
	if (fstatat(dfd, CR_PARENT_LINK, &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT) {
		pr_debug("No parent images directory provided\n");
		return 0;
	}

	*pfd = openat(dfd, CR_PARENT_LINK, O_RDONLY);
	if (*pfd < 0) {
		pr_perror("Can't open parent path");
		return -1;
	}

	return 0;
}

static unsigned long page_ids = 1;

void up_page_ids_base(void)
{
	/*
	 * When page server and criu dump work on
	 * the same dir, the shmem pagemaps and regular
	 * pagemaps may have IDs conflicts. Fix this by
	 * making page server produce page images with
	 * higher IDs.
	 */

	BUG_ON(page_ids != 1);
	page_ids += 0x10000;
}

/*
 * =============================================================================
 * Transparent zstd-seekable decompression for pages-*.img on restore.
 *
 * A compressed pages-*.img can be opened from several places during restore
 * (open_page_read_at, prepare_vma_ios, dedup paths, ...). Each such open
 * returns a fresh fd that currently points at the on-disk compressed bytes.
 * The parasite preadv path expects raw page bytes, so the first parasite iov
 * gets 0-length reads and loops forever.
 *
 * Fix: on the first restore-side open of a given pages_img_id, detect the
 * seek-table magic at the file tail, decompress the whole file into a
 * memfd, and keep the memfd in a process-wide cache keyed on pages_img_id.
 * Every open_pages_image_at() that follows returns a dup of the cached
 * memfd, so any caller (page-read, prepare_vma_ios, parasite) sees raw
 * uncompressed bytes with identical semantics to a raw dump. The on-disk
 * compressed file is kept only long enough for the initial decompress read.
 *
 * Cache lifetime is whole-process; the memfd is dropped by fork/exec or
 * criu exit. Good enough for one-shot restores.
 * =============================================================================
 */

struct pages_mfd_cache_entry {
	u32 pages_img_id;
	int mfd;		/* decompressed memfd, shared */
	struct pages_mfd_cache_entry *next;
};

static struct pages_mfd_cache_entry *pages_mfd_cache;

static int pages_mfd_cache_get(u32 pages_img_id)
{
	struct pages_mfd_cache_entry *e;
	for (e = pages_mfd_cache; e; e = e->next) {
		if (e->pages_img_id == pages_img_id)
			return e->mfd;
	}
	return -1;
}

static int pages_mfd_cache_put(u32 pages_img_id, int mfd)
{
	struct pages_mfd_cache_entry *e = xzalloc(sizeof(*e));
	if (!e)
		return -1;
	e->pages_img_id = pages_img_id;
	e->mfd = mfd;
	e->next = pages_mfd_cache;
	pages_mfd_cache = e;
	return 0;
}

/*
 * Decompress the fd's contents (a zstd-seekable pages-*.img) into a memfd
 * and return the memfd (with cursor at 0). Returns -1 on failure.
 */
static int decompress_pages_to_memfd(int src_fd)
{
	struct stat st;
	uint8_t tail[4];
	void *src_buf = NULL;
	struct decompress_ctx *dctx = NULL;
	int mfd = -1;
	unsigned long long total_raw;
	void *map;

	if (fstat(src_fd, &st) < 0 || st.st_size < 4)
		return -1;
	if (pread(src_fd, tail, 4, st.st_size - 4) != 4)
		return -1;
	if (decompress_probe(tail, sizeof(tail)) != 1)
		return -1;

	src_buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, src_fd, 0);
	if (src_buf == MAP_FAILED) {
		pr_perror("pages-compress: mmap src");
		return -1;
	}

	dctx = decompress_create_from_buffer(src_buf, st.st_size);
	if (!dctx)
		goto err;
	total_raw = decompress_total_raw_size(dctx);

	mfd = syscall(SYS_memfd_create, "criu-decompressed-pages", 0);
	if (mfd < 0) {
		pr_perror("pages-compress: memfd_create");
		goto err;
	}
	if (ftruncate(mfd, total_raw) < 0) {
		pr_perror("pages-compress: ftruncate memfd");
		goto err;
	}
	map = mmap(NULL, total_raw, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
	if (map == MAP_FAILED) {
		pr_perror("pages-compress: mmap memfd");
		goto err;
	}
	if (decompress_range(dctx, 0, total_raw, map) < 0) {
		pr_err("pages-compress: decompress_range failed\n");
		munmap(map, total_raw);
		goto err;
	}
	munmap(map, total_raw);
	if (lseek(mfd, 0, SEEK_SET) < 0) {
		pr_perror("pages-compress: lseek memfd");
		goto err;
	}

	decompress_free(dctx);
	munmap(src_buf, st.st_size);
	pr_info("pages-compress: decompressed %lld B -> %llu B memfd\n",
		(long long)st.st_size, total_raw);
	return mfd;

err:
	if (mfd >= 0)
		close(mfd);
	if (dctx)
		decompress_free(dctx);
	if (src_buf && src_buf != MAP_FAILED)
		munmap(src_buf, st.st_size);
	return -1;
}

/*
 * If the pages image is zstd-seekable, swap img->_x.fd to a decompressed
 * memfd shared across every restore-side open of the same pages_img_id.
 * Raw (non-compressed) images are left untouched.
 */
static void maybe_swap_compressed_pages(struct cr_img *img, u32 pages_img_id)
{
	int cached, new_fd, mfd;

	if (!img || img->_x.fd < 0 || empty_image(img) || lazy_image(img))
		return;

	/* Cache hit: dup and install. */
	cached = pages_mfd_cache_get(pages_img_id);
	if (cached >= 0) {
		new_fd = dup(cached);
		if (new_fd < 0) {
			pr_perror("pages-compress: dup cached memfd");
			return;
		}
		close(img->_x.fd);
		img->_x.fd = new_fd;
		return;
	}

	/* Miss: probe + decompress + cache. */
	mfd = decompress_pages_to_memfd(img->_x.fd);
	if (mfd < 0)
		return;	/* not compressed or decompress failed */
	if (pages_mfd_cache_put(pages_img_id, mfd) < 0) {
		close(mfd);
		return;
	}
	new_fd = dup(mfd);
	if (new_fd < 0) {
		pr_perror("pages-compress: dup fresh memfd");
		return;
	}
	close(img->_x.fd);
	img->_x.fd = new_fd;
}

struct cr_img *open_pages_image_at(int dfd, unsigned long flags, struct cr_img *pmi, u32 *id)
{
	if (flags == O_RDONLY || flags == O_RDWR) {
		PagemapHead *h;
		if (pb_read_one(pmi, &h, PB_PAGEMAP_HEAD) < 0)
			return NULL;
		*id = h->pages_id;
		pagemap_head__free_unpacked(h, NULL);
	} else {
		PagemapHead h = PAGEMAP_HEAD__INIT;
		*id = h.pages_id = page_ids++;
		if (pb_write_one(pmi, &h, PB_PAGEMAP_HEAD) < 0)
			return NULL;
	}

	/*
	 * Compression handling is centralized in open_image_at() — it fires
	 * for every restore-side CR_FD_PAGES open regardless of whether the
	 * caller routes through here or through open_image() directly.
	 */
	return open_image_at(dfd, CR_FD_PAGES, flags, *id);
}

struct cr_img *open_pages_image(unsigned long flags, struct cr_img *pmi, u32 *id)
{
	return open_pages_image_at(get_service_fd(IMG_FD_OFF), flags, pmi, id);
}

/*
 * Write buffer @ptr of @size bytes into @fd file
 * Returns
 *	0  on success
 *	-1 on error (error message is printed)
 */
int write_img_buf(struct cr_img *img, const void *ptr, int size)
{
	int ret;

	ret = bwrite(&img->_x, ptr, size);
	if (ret == size)
		return 0;

	if (ret < 0)
		pr_perror("Can't write img file");
	else
		pr_err("Img trimmed %d/%d\n", ret, size);
	return -1;
}

/*
 * Read buffer @ptr of @size bytes from @fd file
 * Returns
 *	1  on success
 *	0  on EOF (silently)
 *	-1 on error (error message is printed)
 */
int read_img_buf_eof(struct cr_img *img, void *ptr, int size)
{
	int ret;

	ret = bread(&img->_x, ptr, size);
	if (ret == size)
		return 1;
	if (ret == 0)
		return 0;

	if (ret < 0)
		pr_perror("Can't read img file");
	else
		pr_err("Img trimmed %d/%d\n", ret, size);
	return -1;
}

/*
 * Read buffer @ptr of @size bytes from @fd file
 * Returns
 *	1  on success
 *	-1 on error or EOF (error message is printed)
 */
int read_img_buf(struct cr_img *img, void *ptr, int size)
{
	int ret;

	ret = read_img_buf_eof(img, ptr, size);
	if (ret == 0) {
		pr_err("Unexpected EOF\n");
		ret = -1;
	}

	return ret;
}

/*
 * read_img_str -- same as read_img_buf, but allocates memory for
 * the buffer and puts the '\0' at the end
 */

int read_img_str(struct cr_img *img, char **pstr, int size)
{
	int ret;
	char *str;

	str = xmalloc(size + 1);
	if (!str)
		return -1;

	ret = read_img_buf(img, str, size);
	if (ret < 0) {
		xfree(str);
		return -1;
	}

	str[size] = '\0';
	*pstr = str;
	return 0;
}

off_t img_raw_size(struct cr_img *img)
{
	struct stat stat;

	if (fstat(img->_x.fd, &stat)) {
		pr_perror("Failed to get image stats");
		return -1;
	}

	return stat.st_size;
}
