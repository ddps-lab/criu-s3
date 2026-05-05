#ifndef __CR_OBSTOR_PREFETCH_H__
#define __CR_OBSTOR_PREFETCH_H__

#include <stdbool.h>
#include <stddef.h>

/*
 * Default worker count for object-storage parallel fetch — used by both
 * the lazy-pages prefetch pool (criu/obstor_xfer.c) and the cr-restore
 * eager prefetch wave (criu/pagemap.c::prefetch_eager_ranges). Bumped
 * from 8 to 32 to match the cross-region S3 calibration knee.
 */
#define OBSTOR_DEFAULT_WORKERS 32

/*
 * Metadata prefetch for object-storage lazy restore.
 *
 * At restore / lazy-pages daemon startup, enumerate all object keys under
 * the checkpoint prefix (following parent-prefix chains for pre-dump) using
 * S3 ListObjectsV2, then fetch every non-pages image file in parallel via a
 * bounded pthread worker pool and cache the bytes in an in-memory hashmap
 * keyed on the full object path. Subsequent open_image_at() calls hit the
 * cache instead of doing one serial S3 GET per file.
 *
 * This turns ~4.3s of sequential metadata fetches (mc-4gb: 34 files at
 * ~125ms each) into ~200-400ms dominated by a single ListObjectsV2 RTT
 * plus one parallel GET wave.
 *
 * pages-*.img / pages-*.img.idx are intentionally excluded: they are read
 * via range requests in the lazy-pages fault path (see
 * maybe_read_page_object_storage) and a single file can be multi-GB.
 */

/*
 * Initialize the prefetch cache. Discovers the parent-prefix chain, issues
 * one LIST per prefix, then drains the resulting key queue through N worker
 * threads, each storing the fetched bytes into the cache.
 *
 * num_workers <= 0 → defaults to opts.prefetch_workers or a sensible value.
 *
 * Safe to call more than once from different processes (e.g. cr-restore and
 * lazy-pages daemon each initialize their own in-process cache). No-op if
 * object storage is not enabled.
 *
 * Returns 0 on success, -1 on failure. A failure does NOT abort restore —
 * open_image_at() falls back to its existing synchronous GET path.
 */
int obstor_prefetch_init(int num_workers);

/*
 * Look up a cached object by its path. The path is the same string that
 * open_image_at() passes to object_storage_get_object() (i.e. typically the
 * bare filename like "inventory.img" or "core-1941.img"; the prefix handling
 * happens inside object-storage.c via opts.object_storage_object_prefix).
 *
 * On hit: *out_data points to cache-owned bytes (DO NOT free; valid until
 * obstor_prefetch_fini), *out_len is the length, returns 0.
 * On miss: returns -1.
 */
int obstor_prefetch_lookup(const char *path, const void **out_data, size_t *out_len);

/*
 * True iff a previous obstor_prefetch_init() successfully LISTed and
 * populated the cache. If true, a lookup miss means the file does not
 * exist in object storage — callers can skip any sync fallback GET.
 */
bool obstor_prefetch_is_authoritative(void);

/*
 * Free all cache entries. Called at shutdown.
 */
void obstor_prefetch_fini(void);

#endif /* __CR_OBSTOR_PREFETCH_H__ */
