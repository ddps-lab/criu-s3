/*
 * Cloud-instance NIC bandwidth detection — see include/auto_nic.h for
 * the detection order and caching semantics. Used to auto-size the S3
 * upload_pool and restore prefetch worker pools without forcing the
 * user to hand-tune per host.
 */

#undef LOG_PREFIX
#define LOG_PREFIX "auto_nic: "

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <curl/curl.h>

#include "auto_nic.h"
#include "log.h"
#include "xmalloc.h"

#include "nic_table_gen.h"  /* built from contrib/nic-table.csv */

static pthread_once_t g_detect_once = PTHREAD_ONCE_INIT;
static int g_detected_mbps = -1;

/* ------------------------------------------------------------------------- *
 * Table lookup.
 * ------------------------------------------------------------------------- */

static int nic_table_cmp(const void *a, const void *b)
{
	const struct nic_table_row *ka = a;
	const struct nic_table_row *kb = b;
	int c = strcmp(ka->provider, kb->provider);
	if (c)
		return c;
	return strcmp(ka->itype, kb->itype);
}

static int nic_lookup_mbps(const char *provider, const char *itype)
{
	struct nic_table_row key;
	struct nic_table_row *hit;

	if (!provider || !itype || !*itype)
		return -1;
	key.provider = provider;
	key.itype = itype;
	key.nic_mbps = 0;
	hit = bsearch(&key, NIC_TABLE, NIC_TABLE_N,
		      sizeof(NIC_TABLE[0]), nic_table_cmp);
	if (!hit)
		return -1;
	return hit->nic_mbps;
}

/* ------------------------------------------------------------------------- *
 * IMDSv2 — AWS only for now. Cost = 1 PUT + 1 GET (~tens of ms locally,
 * ~100 ms timeout if non-AWS). Runs once per process via pthread_once.
 * ------------------------------------------------------------------------- */

struct fetch_buf {
	char *data;
	size_t len;
	size_t cap;
};

static size_t fetch_write_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
	struct fetch_buf *b = userp;
	size_t n = size * nmemb;
	if (b->len + n + 1 > b->cap) {
		size_t new_cap = b->cap ? b->cap * 2 : 256;
		char *nd;
		while (new_cap < b->len + n + 1)
			new_cap *= 2;
		nd = realloc(b->data, new_cap);
		if (!nd)
			return 0;
		b->data = nd;
		b->cap = new_cap;
	}
	memcpy(b->data + b->len, ptr, n);
	b->len += n;
	b->data[b->len] = '\0';
	return n;
}

static int imdsv2_http_call(const char *url, const char *token_hdr,
			    int put_mode, char *out, size_t out_sz,
			    long timeout_ms)
{
	CURL *curl;
	CURLcode rc;
	struct curl_slist *headers = NULL;
	struct fetch_buf buf = { NULL, 0, 0 };
	long http_code = 0;
	int ret = -1;

	curl = curl_easy_init();
	if (!curl)
		return -1;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetch_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout_ms);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	if (put_mode) {
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
		/* Token TTL header for IMDSv2 session */
		headers = curl_slist_append(headers,
			"X-aws-ec2-metadata-token-ttl-seconds: 60");
	}
	if (token_hdr) {
		char th[256];
		snprintf(th, sizeof(th),
			 "X-aws-ec2-metadata-token: %s", token_hdr);
		headers = curl_slist_append(headers, th);
	}
	if (headers)
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	rc = curl_easy_perform(curl);
	if (rc == CURLE_OK) {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code == 200 && buf.data && out && out_sz > 0) {
			/* Strip trailing whitespace/newline. */
			while (buf.len > 0 &&
			       (buf.data[buf.len - 1] == '\n' ||
				buf.data[buf.len - 1] == '\r' ||
				buf.data[buf.len - 1] == ' '))
				buf.data[--buf.len] = '\0';
			snprintf(out, out_sz, "%s", buf.data);
			ret = 0;
		}
	}

	if (headers)
		curl_slist_free_all(headers);
	free(buf.data);
	curl_easy_cleanup(curl);
	return ret;
}

static int aws_query_instance_type(char *out, size_t out_sz)
{
	char token[128] = "";
	if (imdsv2_http_call("http://169.254.169.254/latest/api/token",
			     NULL, 1, token, sizeof(token), 150) != 0)
		return -1;
	if (!token[0])
		return -1;
	return imdsv2_http_call(
		"http://169.254.169.254/latest/meta-data/instance-type",
		token, 0, out, out_sz, 150);
}

/*
 * Azure IMDS (placeholder). Future impl:
 *   GET http://169.254.169.254/metadata/instance?api-version=2021-02-01
 *     Headers: Metadata: true
 *   Parse JSON → compute.vmSize field (e.g., "Standard_D8_v3").
 */
static int azure_query_instance_type(char *out, size_t out_sz)
{
	(void)out;
	(void)out_sz;
	return -1;
}

/*
 * GCP IMDS (placeholder). Future impl:
 *   GET http://metadata.google.internal/computeMetadata/v1/instance/machine-type
 *     Headers: Metadata-Flavor: Google
 *   Response like "projects/<id>/machineTypes/n2-standard-8" → take
 *   trailing component.
 */
static int gcp_query_instance_type(char *out, size_t out_sz)
{
	(void)out;
	(void)out_sz;
	return -1;
}

/* ------------------------------------------------------------------------- *
 * /sys/class/net fallback. Often empty on cloud (ENA, gVNIC, hv_netvsc)
 * but works on baremetal. Parse /proc/net/route for default interface.
 * ------------------------------------------------------------------------- */

static int sysfs_nic_mbps(void)
{
	FILE *f;
	char line[256];
	char iface[32] = "";

	f = fopen("/proc/net/route", "r");
	if (!f)
		return -1;
	/* Skip header. */
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char if_name[32];
		unsigned dest;
		if (sscanf(line, "%31s %x", if_name, &dest) == 2 && dest == 0) {
			snprintf(iface, sizeof(iface), "%s", if_name);
			break;
		}
	}
	fclose(f);

	/* Common fallbacks if parsing failed. */
	if (!iface[0]) {
		const char *candidates[] = {
			"eth0", "ens5", "ens3", "enp0s3", "enp1s0", NULL
		};
		int i;
		for (i = 0; candidates[i]; i++) {
			char path[128];
			FILE *sf;
			snprintf(path, sizeof(path),
				 "/sys/class/net/%s/speed", candidates[i]);
			sf = fopen(path, "r");
			if (sf) {
				int speed = -1;
				if (fscanf(sf, "%d", &speed) == 1) {
					fclose(sf);
					if (speed > 100)
						return speed;
				} else {
					fclose(sf);
				}
			}
		}
		return -1;
	}

	{
		char path[128];
		FILE *sf;
		int speed = -1;
		snprintf(path, sizeof(path),
			 "/sys/class/net/%s/speed", iface);
		sf = fopen(path, "r");
		if (!sf)
			return -1;
		if (fscanf(sf, "%d", &speed) != 1) {
			fclose(sf);
			return -1;
		}
		fclose(sf);
		if (speed <= 100)
			return -1;
		return speed;
	}
}

/* ------------------------------------------------------------------------- *
 * Orchestration. Called via pthread_once; stores result in g_detected_mbps.
 * ------------------------------------------------------------------------- */

static int try_env_direct(void)
{
	const char *s = getenv("CRIU_NIC_MBPS");
	if (!s || !*s)
		return -1;
	{
		char *end;
		long v = strtol(s, &end, 10);
		if (*end == '\0' && v > 0 && v < 1000000) {
			pr_info("NIC from CRIU_NIC_MBPS env: %ld Mbps\n", v);
			return (int)v;
		}
	}
	return -1;
}

static int try_env_type(void)
{
	struct { const char *env; const char *provider; } rows[] = {
		{ "AWS_INSTANCE_TYPE", "aws" },
		{ "AZURE_VM_SIZE",     "azure" },
		{ "GCP_MACHINE_TYPE",  "gcp" },
		{ NULL, NULL },
	};
	int i;
	for (i = 0; rows[i].env; i++) {
		const char *v = getenv(rows[i].env);
		if (v && *v) {
			int m = nic_lookup_mbps(rows[i].provider, v);
			if (m > 0) {
				pr_info("NIC from %s=%s: %d Mbps (%s)\n",
					rows[i].env, v, m, rows[i].provider);
				return m;
			}
			pr_warn("%s=%s not in table; ignoring\n",
				rows[i].env, v);
		}
	}
	return -1;
}

static int try_imds(void)
{
	char itype[64] = "";
	int m;

	if (aws_query_instance_type(itype, sizeof(itype)) == 0) {
		m = nic_lookup_mbps("aws", itype);
		if (m > 0) {
			pr_info("NIC from AWS IMDSv2: %s → %d Mbps\n",
				itype, m);
			return m;
		}
		pr_warn("AWS IMDSv2 returned %s; not in NIC table\n", itype);
	}
	if (azure_query_instance_type(itype, sizeof(itype)) == 0) {
		m = nic_lookup_mbps("azure", itype);
		if (m > 0) {
			pr_info("NIC from Azure IMDS: %s → %d Mbps\n",
				itype, m);
			return m;
		}
	}
	if (gcp_query_instance_type(itype, sizeof(itype)) == 0) {
		m = nic_lookup_mbps("gcp", itype);
		if (m > 0) {
			pr_info("NIC from GCP metadata: %s → %d Mbps\n",
				itype, m);
			return m;
		}
	}
	return -1;
}

static void detect_nic_once(void)
{
	int m;

	m = try_env_direct();
	if (m > 0) {
		g_detected_mbps = m;
		return;
	}
	m = try_env_type();
	if (m > 0) {
		g_detected_mbps = m;
		return;
	}
	m = try_imds();
	if (m > 0) {
		g_detected_mbps = m;
		return;
	}
	m = sysfs_nic_mbps();
	if (m > 0) {
		pr_info("NIC from /sys/class/net: %d Mbps\n", m);
		g_detected_mbps = m;
		return;
	}
	pr_info("NIC detection failed; caller will use static default\n");
	g_detected_mbps = -1;
}

int auto_nic_mbps(void)
{
	pthread_once(&g_detect_once, detect_nic_once);
	return g_detected_mbps;
}

int auto_pool_workers(int nic_mbps, int ncpu, int max_cap, int per_conn_mbps)
{
	int workers;

	if (per_conn_mbps <= 0)
		per_conn_mbps = 300;  /* safe middle ground */

	if (nic_mbps <= 0)
		return 8;  /* static default when detection failed */

	/*
	 * Need roughly nic_mbps / per_conn_mbps connections to saturate,
	 * plus ~50% headroom for asymmetric per-slot throughput dropoff
	 * observed in our EC2 measurements (w=8 ≈ 280 Mbps/slot, w=16
	 * ≈ 180 Mbps/slot due to libcurl O(N) polling overhead).
	 */
	workers = nic_mbps / per_conn_mbps + nic_mbps / (2 * per_conn_mbps);

	if (workers < 4)
		workers = 4;
	if (ncpu > 1 && workers > ncpu - 1)
		workers = ncpu - 1;
	if (max_cap > 0 && workers > max_cap)
		workers = max_cap;
	if (workers < 1)
		workers = 1;

	return workers;
}
