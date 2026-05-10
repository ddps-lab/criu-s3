#ifndef __CR_OBSTOR_PREFETCH_H__
#define __CR_OBSTOR_PREFETCH_H__

#include <stdbool.h>
#include <stddef.h>

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
 * Look up the LIST-reported byte size for `path`. Available for every key
 * the LIST wave saw, including pages-*.img (which we don't fetch into the
 * data cache). Lets HEAD short-circuit avoid a per-pages round-trip.
 *
 * On hit: *out_size set to the size from <Size>, returns 0.
 * On miss: returns -1.
 */
int obstor_prefetch_lookup_size(const char *path, unsigned long *out_size);

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

/*
 * Tail cache for compressed pages-*.img files.
 *
 * A typical lazy-prefetch restore opens N compressed pages-*.img files
 * back-to-back inside per-task prepare_mappings(). Each open issues a
 * Range GET for the trailing seek-table region; cross-region these
 * sequential 1-RTT fetches accumulate (mc-1gb: 3 tasks × ~600 ms TLS
 * handshake = ~1.8 s).
 *
 * obstor_prefetch_init populates this cache by issuing all the tail
 * GETs in parallel (one wave, one TLS handshake per worker) so the
 * per-task init_s3_compression call is a memory hit instead of a fresh
 * round-trip.
 *
 * On hit: *out_tail / *out_tail_len point to cache-owned bytes (DO NOT
 * free; valid until obstor_prefetch_fini), *out_total_size is the file's
 * total length, returns 0.
 * On miss / not-compressed / authoritative empty: returns -1.
 */
int obstor_prefetch_tail_lookup(const char *full_key,
				const void **out_tail, size_t *out_tail_len,
				unsigned long *out_total_size);

/*
 * Companion lookup for the prefetched head region. Pre-populated by the
 * same wave that does the tail preload. Lets s3_decomp_read_cb serve
 * the decompressor's frame-body reads at offset 0..head_len from memory
 * instead of issuing a fresh per-task Range GET. Returns -1 on miss.
 */
int obstor_prefetch_head_lookup(const char *full_key,
				const void **out_head, size_t *out_head_len);

#endif /* __CR_OBSTOR_PREFETCH_H__ */
