#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/compiler.h"
#include "common/list.h"
#include "cr_options.h"
#include "log.h"
#include "object-storage.h"
#include "obstor_prefetch.h"
#include "xmalloc.h"

#undef LOG_PREFIX
#define LOG_PREFIX "obstor_prefetch: "

#define OBSTOR_PREFETCH_BUCKETS 1024

struct cache_entry {
	char *path;
	void *data;          /* NULL when only size is known (e.g. pages-*.img) */
	size_t len;          /* 0 when data is NULL */
	unsigned long size;  /* object size on S3 from LIST <Size> */
	struct cache_entry *next;
};

static struct cache_entry *g_cache[OBSTOR_PREFETCH_BUCKETS];
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static size_t g_cache_bytes;
static size_t g_cache_entries;
static bool g_prefetch_initialized;
static bool g_prefetch_authoritative; /* LIST succeeded → miss == does-not-exist */

/*
 * Work queue of keys that need to be fetched. Populated by the LIST step,
 * drained by worker threads. Keys are owned by the queue until popped.
 */
struct work_queue {
	char **items;
	size_t n;
	size_t cap;
	size_t head;
	pthread_mutex_t lock;
};

static unsigned long _path_hash(const char *s)
{
	/* djb2 */
	unsigned long h = 5381;
	int c;
	while ((c = (unsigned char)*s++) != 0)
		h = ((h << 5) + h) + c;
	return h;
}

/*
 * Record the LIST-reported object size for `path`. Inserts a new size-only
 * entry (data=NULL) when none exists, or updates the size on an existing
 * entry. Used at LIST time before any data has been fetched, so HEAD
 * short-circuit can find the size even for keys we don't download (e.g.
 * pages-*.img).
 */
static int _cache_record_size(const char *path, unsigned long size)
{
	struct cache_entry *e, *cur;
	unsigned long bkt;

	bkt = _path_hash(path) % OBSTOR_PREFETCH_BUCKETS;

	pthread_mutex_lock(&g_cache_lock);
	for (cur = g_cache[bkt]; cur; cur = cur->next) {
		if (strcmp(cur->path, path) == 0) {
			cur->size = size;
			pthread_mutex_unlock(&g_cache_lock);
			return 0;
		}
	}
	pthread_mutex_unlock(&g_cache_lock);

	e = xmalloc(sizeof(*e));
	if (!e)
		return -1;
	e->path = xstrdup(path);
	if (!e->path) {
		xfree(e);
		return -1;
	}
	e->data = NULL;
	e->len = 0;
	e->size = size;

	pthread_mutex_lock(&g_cache_lock);
	/* Re-check under lock to avoid duplicate insert under concurrency. */
	for (cur = g_cache[bkt]; cur; cur = cur->next) {
		if (strcmp(cur->path, path) == 0) {
			cur->size = size;
			pthread_mutex_unlock(&g_cache_lock);
			xfree(e->path);
			xfree(e);
			return 0;
		}
	}
	e->next = g_cache[bkt];
	g_cache[bkt] = e;
	g_cache_entries++;
	pthread_mutex_unlock(&g_cache_lock);

	return 0;
}

/*
 * Record fetched object bytes for `path`. Updates an existing entry in
 * place (typically the size-only entry inserted at LIST time) or inserts a
 * new entry if none exists. Takes ownership of `data` on success.
 */
static int _cache_record_data(const char *path, void *data, size_t len)
{
	struct cache_entry *e;
	unsigned long bkt;

	bkt = _path_hash(path) % OBSTOR_PREFETCH_BUCKETS;

	pthread_mutex_lock(&g_cache_lock);
	for (e = g_cache[bkt]; e; e = e->next) {
		if (strcmp(e->path, path) == 0) {
			if (e->data) {
				g_cache_bytes -= e->len;
				free(e->data);
			}
			e->data = data;
			e->len = len;
			if (e->size == 0)
				e->size = len;
			g_cache_bytes += len;
			pthread_mutex_unlock(&g_cache_lock);
			return 0;
		}
	}
	pthread_mutex_unlock(&g_cache_lock);

	e = xmalloc(sizeof(*e));
	if (!e)
		return -1;
	e->path = xstrdup(path);
	if (!e->path) {
		xfree(e);
		return -1;
	}
	e->data = data;
	e->len = len;
	e->size = len;

	pthread_mutex_lock(&g_cache_lock);
	e->next = g_cache[bkt];
	g_cache[bkt] = e;
	g_cache_bytes += len;
	g_cache_entries++;
	pthread_mutex_unlock(&g_cache_lock);

	return 0;
}

/*
 * Normalize an object prefix to the same form used when building cache
 * keys: strip leading '/', ensure a trailing '/' (unless empty). Result
 * is written into dst, which must be large enough.
 */
static void _normalize_prefix(const char *prefix, char *dst, size_t cap)
{
	size_t len;

	if (!prefix || !prefix[0]) {
		dst[0] = '\0';
		return;
	}
	if (prefix[0] == '/')
		prefix++;
	snprintf(dst, cap, "%s", prefix);
	len = strlen(dst);
	if (len == 0)
		return;
	if (dst[len - 1] != '/' && len + 1 < cap) {
		dst[len] = '/';
		dst[len + 1] = '\0';
	}
}

int obstor_prefetch_lookup(const char *path, const void **out_data, size_t *out_len)
{
	struct cache_entry *e;
	unsigned long bkt;
	char normalized[512];
	char full_key[1024];

	if (!g_prefetch_initialized || !path)
		return -1;

	/*
	 * Build the full key the same way we did at insert time. Mirror the
	 * convention used by _construct_object_url() in object-storage.c:
	 * any key containing '/' is already absolute (e.g., probe keys built
	 * as "<prefix>/pages-N.img"), bare filenames need the active prefix
	 * prepended. Without this, full-path callers (HEAD / range probes)
	 * always miss because we'd double up the prefix.
	 */
	if (strchr(path, '/')) {
		snprintf(full_key, sizeof(full_key), "%s", path);
	} else {
		_normalize_prefix(opts.object_storage_object_prefix, normalized,
				  sizeof(normalized));
		snprintf(full_key, sizeof(full_key), "%s%s", normalized, path);
	}

	bkt = _path_hash(full_key) % OBSTOR_PREFETCH_BUCKETS;

	pthread_mutex_lock(&g_cache_lock);
	for (e = g_cache[bkt]; e; e = e->next) {
		if (strcmp(e->path, full_key) == 0) {
			/* Size-only entry: data not in cache (e.g. pages-*.img
			 * skipped at fetch wave). Treat as miss for data lookup
			 * so caller falls back to a real GET. Authoritative
			 * miss check below still covers the doesn't-exist case. */
			if (!e->data) {
				pthread_mutex_unlock(&g_cache_lock);
				return -1;
			}
			*out_data = e->data;
			*out_len = e->len;
			pthread_mutex_unlock(&g_cache_lock);
			return 0;
		}
	}
	pthread_mutex_unlock(&g_cache_lock);
	return -1;
}

int obstor_prefetch_lookup_size(const char *path, unsigned long *out_size)
{
	struct cache_entry *e;
	unsigned long bkt;
	char normalized[512];
	char full_key[1024];

	if (!g_prefetch_initialized || !path || !out_size)
		return -1;

	/*
	 * Mirror _construct_object_url(): keys with '/' are already absolute
	 * (e.g., "<prefix>/pages-N.img" passed by init_s3_compression and the
	 * lazy-pages compression probe), bare names get the prefix prepended.
	 * Cache keys are always stored in absolute form.
	 */
	if (strchr(path, '/')) {
		snprintf(full_key, sizeof(full_key), "%s", path);
	} else {
		_normalize_prefix(opts.object_storage_object_prefix, normalized,
				  sizeof(normalized));
		snprintf(full_key, sizeof(full_key), "%s%s", normalized, path);
	}

	bkt = _path_hash(full_key) % OBSTOR_PREFETCH_BUCKETS;

	pthread_mutex_lock(&g_cache_lock);
	for (e = g_cache[bkt]; e; e = e->next) {
		if (strcmp(e->path, full_key) == 0) {
			*out_size = e->size;
			pthread_mutex_unlock(&g_cache_lock);
			return 0;
		}
	}
	pthread_mutex_unlock(&g_cache_lock);
	return -1;
}

bool obstor_prefetch_is_authoritative(void)
{
	return g_prefetch_authoritative;
}

void obstor_prefetch_fini(void)
{
	int i;
	struct cache_entry *e, *next;

	pthread_mutex_lock(&g_cache_lock);
	for (i = 0; i < OBSTOR_PREFETCH_BUCKETS; i++) {
		for (e = g_cache[i]; e; e = next) {
			next = e->next;
			xfree(e->path);
			free(e->data);
			xfree(e);
		}
		g_cache[i] = NULL;
	}
	g_cache_bytes = 0;
	g_cache_entries = 0;
	g_prefetch_initialized = false;
	g_prefetch_authoritative = false;
	pthread_mutex_unlock(&g_cache_lock);
}

/*
 * Return true if a stripped key (path relative to current prefix) should
 * NOT be cached. Reasons:
 *   - pages-*.img / pages-*.img.idx: range-fetched in the fault path, never
 *     opened via open_image_at().
 *   - Any key containing '/': lives in a subdirectory, so it belongs to a
 *     nested namespace (e.g., mis-uploaded parent/ contents from an
 *     aws-s3-sync-with-symlinks pathway, or nested ns images that upstream
 *     CRIU opens via a different dfd). Caching these would collide with
 *     same-basename entries from other prefixes.
 */
static bool _should_skip_key(const char *stripped)
{
	if (strchr(stripped, '/'))
		return true;
	if (strncmp(stripped, "pages-", 6) == 0) {
		const char *dot = strrchr(stripped, '.');
		if (dot && (strcmp(dot, ".img") == 0 || strcmp(dot, ".idx") == 0))
			return true;
	}
	return false;
}

/*
 * Convert a LIST-returned key (which is the full S3 path including any
 * configured prefix, e.g. "memcached-4gb/inventory.img") into the basename
 * under the current prefix that open_image_at() will pass to the fetch
 * function ("inventory.img"). If the key does not live under prefix,
 * returns NULL.
 */
static const char *_strip_prefix(const char *key, const char *prefix)
{
	size_t plen;

	if (!prefix || !prefix[0])
		return key;
	if (prefix[0] == '/')
		prefix++;
	plen = strlen(prefix);
	if (plen == 0)
		return key;

	if (strncmp(key, prefix, plen) != 0)
		return NULL;

	/* Prefix already ended in '/': tail starts right after plen. */
	if (prefix[plen - 1] == '/')
		return key + plen;

	/* Prefix did not end in '/': need a path boundary after the match. */
	if (key[plen] == '/')
		return key + plen + 1;
	if (key[plen] == '\0')
		return key + plen;
	return NULL;
}

/*
 * Worker thread: dequeue work items and fetch each. Each item carries both
 * the stripped path (to pass to object_storage_get_object, which appends
 * the current prefix) and the full key (with prefix) used for caching.
 */
/*
 * Work item: the full S3 key to fetch AND the normalized prefix under which
 * it should be cached. object_storage_get_object() uses the current value of
 * opts.object_storage_object_prefix to build URLs; since parent-chain
 * walking temporarily swaps that global, the worker needs to pass the
 * stripped path (relative to prefix) to the fetch function AND re-build
 * the full key for cache insert. Worker takes both via wq items.
 */
struct work_item {
	char *stripped;   /* path to pass to object_storage_get_object */
	char *full_key;   /* cache key = normalized(prefix) + stripped */
};

static struct work_item *_wq_pop_item(struct work_queue *wq)
{
	struct work_item *item = NULL;
	pthread_mutex_lock(&wq->lock);
	if (wq->head < wq->n)
		item = (struct work_item *)wq->items[wq->head++];
	pthread_mutex_unlock(&wq->lock);
	return item;
}

static void *_prefetch_worker(void *arg)
{
	struct work_queue *wq = (struct work_queue *)arg;
	struct work_item *item;

	while ((item = _wq_pop_item(wq)) != NULL) {
		void *data = NULL;
		unsigned long len = 0;
		int rc;

		rc = object_storage_get_object(item->stripped, &data, &len);

		if (rc == 0 && data && len > 0) {
			if (_cache_record_data(item->full_key, data, len) != 0) {
				pr_warn("cache insert failed for %s\n", item->full_key);
				free(data);
			}
		} else if (data) {
			free(data);
		}
		xfree(item->stripped);
		xfree(item->full_key);
		xfree(item);
	}
	return NULL;
}

/*
 * Run one LIST + parallel-fetch wave over the current
 * opts.object_storage_object_prefix. Items are cached with full keys of the
 * form `<normalized_prefix><stripped_path>` so that subsequent lookups from
 * different prefix contexts (parent chain) don't collide on the same
 * basename.
 *
 * parent_prefix_out: if a "parent-prefix" file was discovered and cached,
 * its contents are copied here (NUL-terminated) so the caller can chase the
 * pre-dump chain. Empty string if no parent.
 */
static int _prefetch_current_prefix(int num_workers, char *parent_prefix_out, size_t parent_cap)
{
	char **keys = NULL;
	unsigned long *sizes = NULL;
	size_t nkeys = 0, i;
	struct work_queue wq;
	pthread_t *tids = NULL;
	int nw, t, created = 0;
	const char *current_prefix;
	char normalized[512];
	char pp_key[1024];
	const void *ppdata;
	size_t pplen;

	parent_prefix_out[0] = '\0';

	current_prefix = opts.object_storage_object_prefix ? opts.object_storage_object_prefix : "";
	_normalize_prefix(current_prefix, normalized, sizeof(normalized));

	if (object_storage_list_objects(current_prefix, &keys, &sizes, &nkeys) != 0) {
		pr_err("LIST failed for prefix '%s'\n", current_prefix);
		return -1;
	}
	if (nkeys == 0) {
		pr_info("LIST returned 0 keys for prefix '%s'\n", current_prefix);
		free(keys);
		if (sizes)
			free(sizes);
		return 0;
	}

	/*
	 * Record (key → size) for every LISTed key, including pages-*.img
	 * which we don't fetch into the cache. Lets HEAD short-circuit
	 * resolve sizes from the LIST result instead of paying a per-pages
	 * round-trip in the compression-detection probe.
	 */
	for (i = 0; i < nkeys; i++) {
		const char *stripped = _strip_prefix(keys[i], current_prefix);
		char full_key[1024];

		if (!stripped || !stripped[0])
			continue;
		snprintf(full_key, sizeof(full_key), "%s%s", normalized, stripped);
		_cache_record_size(full_key, sizes[i]);
	}

	wq.items = xmalloc(nkeys * sizeof(char *));
	if (!wq.items) {
		for (i = 0; i < nkeys; i++)
			xfree(keys[i]);
		free(keys);
		free(sizes);
		return -1;
	}
	wq.n = 0;
	wq.cap = nkeys;
	wq.head = 0;
	pthread_mutex_init(&wq.lock, NULL);

	for (i = 0; i < nkeys; i++) {
		const char *stripped = _strip_prefix(keys[i], current_prefix);
		struct work_item *item;
		char full_key[1024];

		if (!stripped || !stripped[0]) {
			xfree(keys[i]);
			continue;
		}
		if (_should_skip_key(stripped)) {
			xfree(keys[i]);
			continue;
		}

		snprintf(full_key, sizeof(full_key), "%s%s", normalized, stripped);

		item = xmalloc(sizeof(*item));
		if (!item) {
			xfree(keys[i]);
			continue;
		}
		item->stripped = xstrdup(stripped);
		item->full_key = xstrdup(full_key);
		wq.items[wq.n++] = (char *)item;
		xfree(keys[i]);
	}
	free(keys);
	if (sizes)
		free(sizes);

	pr_info("prefix '%s': enqueued %zu keys (skipped pages-*/subdirs)\n", current_prefix, wq.n);

	if (wq.n == 0) {
		xfree(wq.items);
		pthread_mutex_destroy(&wq.lock);
		return 0;
	}

	/*
	 * Metadata prefetch is latency-bound, not bandwidth-bound: ~30 tiny
	 * files × 25ms warm GET ≈ 750ms of serial work with perfect
	 * connection reuse. Spawning 32 worker threads for this actively
	 * hurts: 32 concurrent fresh TLS handshakes serialize inside
	 * OpenSSL/libcurl (empirically 770–1005ms each on m5.8xlarge →
	 * ~1050ms wave wall) while a small worker count can warm the TCP+TLS
	 * connection cache and then amortize subsequent GETs at ~25ms each.
	 *
	 * Cap at 4 workers for the metadata wave regardless of the caller's
	 * num_workers request. (obstor_xfer for pages-*.img fetches keeps
	 * its full worker count — those are bandwidth-bound, not
	 * latency-bound, and have their own scaling story.)
	 */
	nw = num_workers > 0 ? num_workers : 4;
	if (nw > 4)
		nw = 4;
	if ((size_t)nw > wq.n)
		nw = (int)wq.n;

	tids = xmalloc(nw * sizeof(pthread_t));
	if (!tids) {
		for (i = 0; i < wq.n; i++) {
			struct work_item *it = (struct work_item *)wq.items[i];
			xfree(it->stripped);
			xfree(it->full_key);
			xfree(it);
		}
		xfree(wq.items);
		pthread_mutex_destroy(&wq.lock);
		return -1;
	}
	for (t = 0; t < nw; t++) {
		if (pthread_create(&tids[t], NULL, _prefetch_worker, &wq) != 0) {
			pr_warn("failed to create worker %d/%d; continuing with fewer\n", t, nw);
			break;
		}
		created++;
	}
	if (created == 0) {
		_prefetch_worker(&wq);
	} else {
		for (t = 0; t < created; t++)
			pthread_join(tids[t], NULL);
	}

	xfree(tids);
	xfree(wq.items);
	pthread_mutex_destroy(&wq.lock);

	/*
	 * Check whether parent-prefix was cached during this wave. The cache
	 * key is normalized_prefix + "parent-prefix".
	 */
	snprintf(pp_key, sizeof(pp_key), "%sparent-prefix", normalized);
	{
		struct cache_entry *e;
		unsigned long bkt = _path_hash(pp_key) % OBSTOR_PREFETCH_BUCKETS;
		pthread_mutex_lock(&g_cache_lock);
		for (e = g_cache[bkt]; e; e = e->next) {
			if (strcmp(e->path, pp_key) == 0) {
				pplen = e->len;
				ppdata = e->data;
				if (pplen > 0 && pplen < parent_cap) {
					memcpy(parent_prefix_out, ppdata, pplen);
					parent_prefix_out[pplen] = '\0';
					/* Strip trailing newline/slash noise */
					while (pplen > 0 &&
					       (parent_prefix_out[pplen - 1] == '\n' ||
						parent_prefix_out[pplen - 1] == ' ' ||
						parent_prefix_out[pplen - 1] == '\r')) {
						parent_prefix_out[--pplen] = '\0';
					}
				}
				break;
			}
		}
		pthread_mutex_unlock(&g_cache_lock);
	}

	return 0;
}

int obstor_prefetch_init(int num_workers)
{
	char parent_prefix[512];
	char *original_prefix;
	char *cur_prefix_storage = NULL;
	int chain_depth = 0;
	bool chain_ok = true;

	if (!opts.enable_object_storage)
		return 0;
	if (g_prefetch_initialized)
		return 0;

	g_prefetch_initialized = true;

	pr_info("initializing (workers=%d, prefix='%s')\n", num_workers,
		opts.object_storage_object_prefix ? opts.object_storage_object_prefix : "");

	/*
	 * Force a single-threaded curl re-init BEFORE spawning workers.
	 *
	 * Without this, every worker thread's first curl_easy_init() +
	 * first TLS connection post-fork races into libcurl / OpenSSL
	 * global lazy-init state and serializes on a global lock. On mc-4gb
	 * EC2 this reproduced as 26 threads each taking 835–1043 ms for a
	 * 2 KB GET — the classic "all threads queue on one mutex" wall-time
	 * shape. A single serial re-init here makes the subsequent parallel
	 * fetch wave hit warm globals and actually overlap.
	 */
	if (object_storage_reinit_after_fork() != 0) {
		pr_warn("reinit_after_fork failed; worker wave may serialize\n");
	}

	original_prefix = opts.object_storage_object_prefix;

	if (_prefetch_current_prefix(num_workers, parent_prefix, sizeof(parent_prefix)) != 0) {
		pr_err("current-prefix prefetch failed\n");
		chain_ok = false;
	}

	/*
	 * Chase parent-prefix chain. Pre-dump creates snapshots at distinct
	 * S3 prefixes (e.g. pdtest/pd_dump/ ← pdtest/pd1/ ← pdtest/pd0/),
	 * linked by a "parent-prefix" marker object. Upstream criu-s3
	 * resolves this lazily inside try_open_parent() by synchronously
	 * GETting the marker, swapping opts.object_storage_object_prefix to
	 * the parent, and recursively opening a new page_read — which then
	 * issues one serial S3 GET per parent metadata image.
	 *
	 * We walk the same chain here but use LIST + a parallel wave per
	 * level. Worker-thread curl handles + full-prefix cache keys make
	 * the lookup at parent-open time a pure hashmap hit.
	 */
	while (chain_ok && parent_prefix[0] && chain_depth < 16) {
		char next_parent[512];

		pr_info("walking parent chain (depth=%d): '%s'\n", chain_depth, parent_prefix);

		xfree(cur_prefix_storage);
		cur_prefix_storage = xstrdup(parent_prefix);
		if (!cur_prefix_storage) {
			chain_ok = false;
			break;
		}
		opts.object_storage_object_prefix = cur_prefix_storage;

		if (_prefetch_current_prefix(num_workers, next_parent, sizeof(next_parent)) != 0) {
			pr_err("parent-prefix prefetch failed at depth %d\n", chain_depth);
			chain_ok = false;
			break;
		}

		chain_depth++;
		snprintf(parent_prefix, sizeof(parent_prefix), "%s", next_parent);
	}

	opts.object_storage_object_prefix = original_prefix;
	xfree(cur_prefix_storage);

	if (chain_depth >= 16)
		pr_warn("parent chain exceeded depth 16 — truncated\n");

	if (chain_ok)
		g_prefetch_authoritative = true;

	pthread_mutex_lock(&g_cache_lock);
	pr_info("init complete: %zu entries, %zu bytes cached (chain depth=%d, authoritative=%d)\n",
		g_cache_entries, g_cache_bytes, chain_depth, (int)g_prefetch_authoritative);
	pthread_mutex_unlock(&g_cache_lock);

	return 0;
}
