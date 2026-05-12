#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include "common/config.h"
#include "common/compiler.h"
#include "log.h"
#include "cr_options.h"
#include "object-storage.h"
#include "obstor_prefetch.h"
#include "servicefd.h"
#include "xmalloc.h"

/*
 * =================================================================================
 * Data Structures
 * =================================================================================
 */

/* Structure to hold data during libcurl transfer */
struct MemoryStruct {
	char *memory;
	size_t size;     /* current size of the downloaded data */
	size_t capacity; /* capacity of the buffer */
};

/* Structure to hold process-specific curl handle */
struct curl_handle_entry {
	pid_t pid;
	CURL *handle;
	time_t last_used;
	int request_count;
	struct curl_handle_entry *next;
};

/* Structure to hold thread-specific curl handle */
struct curl_thread_handle {
	pthread_t thread_id;
	CURL *handle;
	struct curl_slist *resolve_list;  /* CURLOPT_RESOLVE entry pinning host->ip */
	time_t last_used;
	int request_count;
	struct curl_thread_handle *next;
};

/* Structure to hold both data and error buffers + CDN observability fields. */
struct FetchContext {
	struct MemoryStruct *data_chunk;
	struct MemoryStruct *error_chunk;
	int got_error;
	/*
	 * Captured response headers for CDN visibility.  Populated by
	 * header_callback, consumed by the caller after curl_easy_perform
	 * completes.  Empty string means the header was absent.
	 */
	char x_cache[64];
	char x_amz_cf_pop[32];
	/*
	 * Content-Range total length parsed from "Content-Range: bytes
	 * a-b/<total>". Used by tail-fetch (negative range) callers to
	 * recover the object size from the same response, eliminating a
	 * separate HEAD round-trip. 0 if the header was absent.
	 */
	unsigned long content_range_total;
};

/*
 * =================================================================================
 * Global Variables
 * =================================================================================
 */

/* Process-local handle storage */
static struct curl_handle_entry *g_curl_handles = NULL;

/* Thread-local storage key and list */
static pthread_key_t g_curl_thread_key;
static pthread_once_t g_curl_thread_key_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_thread_handles_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct curl_thread_handle *g_thread_handles = NULL;

/* Initialization flags */
static int g_curl_initialized_in_this_process = 0;
static int g_is_lazy_pages_context = 0;

/*
 * Global S3 edge-IP pool — resolved once on first thread-local handle
 * creation and reused across every restore worker thread. Each worker
 * is pinned to a different IP via CURLOPT_RESOLVE so prefetch reads
 * spread across multiple S3 frontend partitions instead of collapsing
 * onto whichever IP the glibc resolver picked first. Without this,
 * prefetch workers each call getaddrinfo independently but glibc's
 * default ordering is deterministic, so all of them end up using the
 * same IP and hitting a single per-edge rate cap.
 */
#define MAX_RESOLVED_IPS 16
static pthread_mutex_t g_s3_ips_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_s3_ips[MAX_RESOLVED_IPS][64];
static int g_s3_n_ips = 0;
static char g_s3_host[512] = "";
static int g_s3_port = 443;
static int g_s3_next_slot = 0;

/* AWS S3 Express One Zone Session Credentials */
static char g_session_access_key[256];
static char g_session_secret_key[256];
static char g_session_token[2048];
static time_t g_session_expiration = 0;

/*
 * =================================================================================
 * Forward Declarations
 * =================================================================================
 */

static int _object_storage_create_express_session(void);
static int ensure_valid_session(void);
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
static int _parse_xml_tag(const char *xml, const char *tag, char *buffer, size_t buffer_len);

/*
 * =================================================================================
 * AWS Signature V4 Implementation
 * =================================================================================
 */

/* Compute SHA256 and return as lowercase hex string */
__attribute__((used))
/*
 * Compute the value of x-amz-content-sha256 for a request body. When
 * opts.sign_payload is off (the default), fill `output` with the literal
 * "UNSIGNED-PAYLOAD" string — SigV4 spec permits this and S3 accepts it,
 * trading the per-request body scan for TLS-only in-transit integrity.
 * aws-cli v2 (CRT) and most AWS SDKs default to UNSIGNED-PAYLOAD for
 * the same performance reason. output buffer must be at least 65 bytes
 * either way (64 hex chars + NUL vs 16-char literal + NUL).
 */
static void _payload_hash(const void *data, size_t len, char *output);

static void _sha256_hex(const char *str, size_t len, char *output)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	int i;

	md = EVP_sha256();
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, str, len);
	EVP_DigestFinal_ex(mdctx, hash, &md_len);
	EVP_MD_CTX_free(mdctx);

	for (i = 0; i < md_len; i++) {
		sprintf(output + (i * 2), "%02x", hash[i]);
	}
	output[md_len * 2] = '\0';
}

static void _payload_hash(const void *data, size_t len, char *output)
{
	if (opts.sign_payload) {
		_sha256_hex((const char *)data, len, output);
	} else {
		/* SigV4 permits the literal string "UNSIGNED-PAYLOAD" in both
		 * the canonical x-amz-content-sha256 header and the canonical
		 * request hash input. See AWS SigV4 docs section "Unsigned
		 * payload option". */
		memcpy(output, "UNSIGNED-PAYLOAD", 17);  /* includes NUL */
	}
}

/* Compute HMAC-SHA256 and return raw bytes */
__attribute__((used))
static unsigned char *_hmac_sha256(const void *key, int key_len, const unsigned char *data, size_t data_len,
				   unsigned int *out_len)
{
	unsigned char *result = malloc(EVP_MAX_MD_SIZE);
	if (!result) {
		pr_err("HMAC result malloc failed\n");
		return NULL;
	}
	if (HMAC(EVP_sha256(), key, key_len, data, data_len, result, out_len) == NULL) {
		free(result);
		return NULL;
	}
	return result;
}

/* Derive SigV4 signing key from AWS secret key */
__attribute__((used))
static unsigned char *_get_signature_key(const char *secret_key, const char *date_stamp, const char *region,
					 const char *service, unsigned int *out_len)
{
	char k_secret[64];
	unsigned int len;
	unsigned char *k_date, *k_region, *k_service, *k_signing;

	snprintf(k_secret, sizeof(k_secret), "AWS4%s", secret_key);

	k_date = _hmac_sha256(k_secret, strlen(k_secret), (unsigned char *)date_stamp, strlen(date_stamp), &len);
	k_region = _hmac_sha256(k_date, len, (unsigned char *)region, strlen(region), &len);
	k_service = _hmac_sha256(k_region, len, (unsigned char *)service, strlen(service), &len);
	k_signing = _hmac_sha256(k_service, len, (unsigned char *)"aws4_request", strlen("aws4_request"), out_len);

	/* Free intermediate keys */
	if (k_date)
		free(k_date);
	if (k_region)
		free(k_region);
	if (k_service)
		free(k_service);

	return k_signing;
}

/* Strip scheme (http://, https://) from URL, return pointer to hostname portion */
static const char *_strip_scheme(const char *url)
{
	if (strncmp(url, "https://", 8) == 0)
		return url + 8;
	if (strncmp(url, "http://", 7) == 0)
		return url + 7;
	return url;
}

/*
 * Build SigV4 authentication headers for an S3 request.
 *
 * Parameters:
 *   access_key    - AWS access key ID (or session access key for Express)
 *   secret_key    - AWS secret access key (or session secret key for Express)
 *   session_token - Session token (NULL for standard S3/MinIO)
 *   region        - AWS region (e.g., "us-east-1")
 *   method        - HTTP method ("GET", "PUT", "POST", "DELETE")
 *   host          - Host header value, scheme-free (e.g., "bucket.s3.amazonaws.com")
 *   canonical_uri - URI path (e.g., "/object/key")
 *   query_string  - Canonical query string (NULL or "" for none)
 *   content_sha256 - SHA256 hex of request body (use EMPTY_PAYLOAD_HASH for no body)
 *   range_value   - Range header value (NULL if not applicable)
 *   content_length - Content-Length value (-1 if not applicable)
 *   headers       - Output: curl_slist with Authorization, X-Amz-Date, etc.
 *
 * Returns 0 on success, -1 on failure.
 */
#define EMPTY_PAYLOAD_HASH "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

static int _build_sigv4_headers(const char *access_key, const char *secret_key,
				const char *session_token, const char *region,
				const char *method, const char *host,
				const char *canonical_uri, const char *query_string,
				const char *content_sha256, const char *range_value,
				long content_length, struct curl_slist **headers)
{
	char amz_date[17];
	char date_stamp[9];
	char canonical_headers[4096];
	char signed_headers[256];
	char canonical_request[8192];
	char canonical_request_hash[65];
	char string_to_sign[512];
	char credential_scope[128];
	char signature_hex[65];
	char auth_header[1024];
	char x_amz_date_header[64];
	char x_amz_content_sha256_header[100];
	time_t now;
	struct tm *tm_gmt;
	const char *service = "s3";
	const char *qs = (query_string && query_string[0]) ? query_string : "";
	unsigned char *signing_key;
	unsigned int signing_key_len;
	unsigned char *signature_raw;
	unsigned int signature_raw_len;
	int i;
	int pos;

	now = time(NULL);
	tm_gmt = gmtime(&now);
	strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", tm_gmt);
	strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", tm_gmt);

	/*
	 * Build signed headers and canonical headers.
	 * Headers MUST be sorted alphabetically by name.
	 * Conditionally include: content-length, range, x-amz-s3session-token.
	 */
	pos = 0;
	signed_headers[0] = '\0';
	canonical_headers[0] = '\0';

	/*
	 * Note: content-length is NOT included in signed headers.
	 * curl sets Content-Length automatically. Including it in the
	 * signature causes SignatureDoesNotMatch on AWS S3 because
	 * curl may format the value differently than our signed version.
	 */

	/* host (always) */
	pos += snprintf(canonical_headers + pos, sizeof(canonical_headers) - pos,
			"host:%s\n", host);
	strncat(signed_headers, "host;", sizeof(signed_headers) - strlen(signed_headers) - 1);

	/* range (only for GET with range) */
	if (range_value) {
		pos += snprintf(canonical_headers + pos, sizeof(canonical_headers) - pos,
				"range:%s\n", range_value);
		strncat(signed_headers, "range;", sizeof(signed_headers) - strlen(signed_headers) - 1);
	}

	/* x-amz-content-sha256 (always) */
	pos += snprintf(canonical_headers + pos, sizeof(canonical_headers) - pos,
			"x-amz-content-sha256:%s\n", content_sha256);
	strncat(signed_headers, "x-amz-content-sha256;", sizeof(signed_headers) - strlen(signed_headers) - 1);

	/* x-amz-date (always) */
	pos += snprintf(canonical_headers + pos, sizeof(canonical_headers) - pos,
			"x-amz-date:%s\n", amz_date);
	strncat(signed_headers, "x-amz-date;", sizeof(signed_headers) - strlen(signed_headers) - 1);

	/* x-amz-s3session-token (Express One Zone only) */
	if (session_token) {
		pos += snprintf(canonical_headers + pos, sizeof(canonical_headers) - pos,
				"x-amz-s3session-token:%s\n", session_token);
		strncat(signed_headers, "x-amz-s3session-token;", sizeof(signed_headers) - strlen(signed_headers) - 1);
	}

	/* Remove trailing semicolon from signed_headers */
	{
		size_t sh_len = strlen(signed_headers);
		if (sh_len > 0 && signed_headers[sh_len - 1] == ';')
			signed_headers[sh_len - 1] = '\0';
	}

	/* Build canonical request */
	snprintf(canonical_request, sizeof(canonical_request), "%s\n%s\n%s\n%s\n%s\n%s",
		 method, canonical_uri, qs,
		 canonical_headers, signed_headers, content_sha256);

	/* Hash canonical request */
	_sha256_hex(canonical_request, strlen(canonical_request), canonical_request_hash);

	pr_debug("SigV4 canonical_request:\n---\n%s\n---\nhash: %s\n",
		 canonical_request, canonical_request_hash);

	/* Build credential scope and string to sign */
	snprintf(credential_scope, sizeof(credential_scope), "%s/%s/%s/aws4_request",
		 date_stamp, region, service);
	snprintf(string_to_sign, sizeof(string_to_sign), "AWS4-HMAC-SHA256\n%s\n%s\n%s",
		 amz_date, credential_scope, canonical_request_hash);

	/* Calculate signature */
	signing_key = _get_signature_key(secret_key, date_stamp, region, service, &signing_key_len);
	signature_raw = _hmac_sha256(signing_key, signing_key_len,
				     (unsigned char *)string_to_sign,
				     strlen(string_to_sign), &signature_raw_len);
	if (signing_key)
		free(signing_key);

	if (!signature_raw) {
		pr_err("Failed to create SigV4 signature\n");
		return -1;
	}

	for (i = 0; i < (int)signature_raw_len; i++)
		sprintf(signature_hex + i * 2, "%02x", signature_raw[i]);
	signature_hex[signature_raw_len * 2] = '\0';
	free(signature_raw);

	/* Build Authorization header */
	snprintf(auth_header, sizeof(auth_header),
		 "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		 access_key, credential_scope, signed_headers, signature_hex);

	/* Append headers to curl_slist */
	snprintf(x_amz_date_header, sizeof(x_amz_date_header), "X-Amz-Date: %s", amz_date);
	*headers = curl_slist_append(*headers, x_amz_date_header);

	snprintf(x_amz_content_sha256_header, sizeof(x_amz_content_sha256_header),
		 "X-Amz-Content-Sha256: %s", content_sha256);
	*headers = curl_slist_append(*headers, x_amz_content_sha256_header);

	/* Content-Length is set by curl automatically via CURLOPT_INFILESIZE_LARGE */

	if (session_token) {
		char token_header[2100];
		snprintf(token_header, sizeof(token_header),
			 "x-amz-s3session-token: %s", session_token);
		*headers = curl_slist_append(*headers, token_header);
	}

	*headers = curl_slist_append(*headers, auth_header);

	/*
	 * Strip libcurl's default "Expect: 100-continue" header. For bodies
	 * over 1 KB libcurl sends Expect: 100-continue and waits a full RTT
	 * for the 100 Continue response before sending the body — wasted
	 * latency on every part upload. Region-local S3 RTT is ~1-2 ms but
	 * with 100+ parts per dump this adds up. AWS CRT and aws-cli both
	 * disable this for the same reason. Empty Expect: tells curl to
	 * remove its auto-added header.
	 */
	*headers = curl_slist_append(*headers, "Expect:");

	return 0;
}

/*
 * Build authentication headers for object storage requests.
 * Single entry point for all auth methods — dispatches to provider-specific implementations.
 *
 * Parameters:
 *   method        - HTTP method ("GET", "PUT", "POST", "DELETE")
 *   host          - Host header value, scheme-free
 *   canonical_uri - URI path
 *   query_string  - Canonical query string (NULL or "" for none)
 *   content_sha256 - SHA256 hex of body (EMPTY_PAYLOAD_HASH for no body)
 *   range_value   - Range header value (NULL if not applicable)
 *   content_length - Content-Length (-1 if not applicable)
 *   headers       - Output: curl_slist
 */
static int _build_auth_headers(const char *method, const char *host,
			       const char *canonical_uri, const char *query_string,
			       const char *content_sha256, const char *range_value,
			       long content_length, struct curl_slist **headers)
{
	if (opts.express_one_zone && opts.aws_access_key && opts.aws_secret_key) {
		pr_debug("Auth: SigV4 with Express One Zone session credentials\n");
		return _build_sigv4_headers(g_session_access_key, g_session_secret_key,
					    g_session_token, opts.aws_region,
					    method, host, canonical_uri, query_string,
					    content_sha256, range_value,
					    content_length, headers);
	}

	if (opts.aws_access_key && opts.aws_secret_key) {
		pr_debug("Auth: SigV4 with standard credentials\n");
		return _build_sigv4_headers(opts.aws_access_key, opts.aws_secret_key,
					    NULL, opts.aws_region,
					    method, host, canonical_uri, query_string,
					    content_sha256, range_value,
					    content_length, headers);
	}

	/* No credentials — anonymous access */
	return 0;
}

/*
 * =================================================================================
 * Utility Functions
 * =================================================================================
 */

/* Get current thread ID using syscall */
static pid_t get_thread_id(void)
{
	return (pid_t)syscall(SYS_gettid);
}

/* Check if current thread is the main thread */
static int is_main_thread(void)
{
	return get_thread_id() == getpid();
}

/* Simple XML parser to extract text content from a tag */
static int _parse_xml_tag(const char *xml, const char *tag, char *buffer, size_t buffer_len)
{
	char start_tag[64];
	char end_tag[64];
	const char *start;
	const char *end;
	size_t len;

	snprintf(start_tag, sizeof(start_tag), "<%s>", tag);
	snprintf(end_tag, sizeof(end_tag), "</%s>", tag);

	start = strstr(xml, start_tag);
	if (!start) {
		/* Try again without namespace prefix */
		const char *tag_name_only = strchr(tag, ':');
		if (tag_name_only) {
			return _parse_xml_tag(xml, tag_name_only + 1, buffer, buffer_len);
		}
		return -1;
	}
	start += strlen(start_tag);

	end = strstr(start, end_tag);
	if (!end)
		return -1;

	len = end - start;
	if (len >= buffer_len) {
		pr_err("XML tag '%s' content is too large for buffer\n", tag);
		return -1;
	}

	memcpy(buffer, start, len);
	buffer[len] = '\0';
	return 0;
}

/*
 * =================================================================================
 * CURL Callback Functions
 * =================================================================================
 */

/* Callback for libcurl to write received data */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;
	size_t new_size = mem->size + realsize;

	/* Dynamic allocation for CreateSession responses */
	if (mem->capacity == 0) {
		char *ptr = realloc(mem->memory, new_size + 1);
		if (!ptr) {
			pr_err("Object Storage: Failed to allocate memory for response\n");
			return 0;
		}
		mem->memory = ptr;
		memcpy(&(mem->memory[mem->size]), contents, realsize);
		mem->size = new_size;
		mem->memory[mem->size] = '\0';
		return realsize;
	}

	/* Fixed buffer for range requests */
	if (new_size > mem->capacity) {
		pr_err("Object Storage: Received data exceeds buffer capacity (%zu > %zu)\n", new_size,
		       mem->capacity);
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size = new_size;

	return realsize;
}

/* Callback for libcurl to write error response data */
static size_t write_error_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;
	char *ptr;

	/* Always use dynamic allocation for error responses */
	ptr = realloc(mem->memory, mem->size + realsize + 1);
	if (!ptr) {
		pr_err("Failed to allocate memory for error response\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = '\0';

	return realsize;
}

/* Header callback to detect HTTP errors early */
/*
 * Case-insensitive prefix match for HTTP header names.  Returns pointer to
 * the byte after the matched prefix on success, NULL on miss.  Used so we
 * don't bring in strcasecmp for libcurl's case-bag headers.
 */
static const char *_hdr_match(const char *buf, size_t buflen, const char *needle)
{
	size_t nlen = strlen(needle);
	size_t i;
	if (buflen < nlen)
		return NULL;
	for (i = 0; i < nlen; i++) {
		char a = buf[i];
		char b = needle[i];
		if (a >= 'A' && a <= 'Z')
			a += 32;
		if (b >= 'A' && b <= 'Z')
			b += 32;
		if (a != b)
			return NULL;
	}
	return buf + nlen;
}

/*
 * Copy a header value into dst, trimming leading whitespace and stripping
 * trailing CRLF.  Always NUL-terminates dst.
 */
static void _copy_hdr_value(const char *src, size_t src_len, char *dst, size_t dst_size)
{
	size_t i = 0;
	size_t j = 0;
	while (i < src_len && (src[i] == ' ' || src[i] == '\t'))
		i++;
	while (i < src_len && j + 1 < dst_size) {
		char c = src[i];
		if (c == '\r' || c == '\n')
			break;
		dst[j++] = c;
		i++;
	}
	dst[j] = '\0';
}

static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
	struct FetchContext *ctx = (struct FetchContext *)userdata;
	size_t total_size = size * nitems;
	const char *value;

	/* Check if this is the status line */
	if (strncmp(buffer, "HTTP/", 5) == 0) {
		int status_code = 0;
		if (sscanf(buffer, "HTTP/%*d.%*d %d", &status_code) == 1) {
			if (status_code >= 400) {
				ctx->got_error = 1;
				pr_debug("Detected error status code: %d\n", status_code);
			}
		}
		return total_size;
	}

	/*
	 * Capture CDN observability headers.  CloudFront uses "X-Cache" with
	 * values like "Hit from cloudfront" / "Miss from cloudfront", and
	 * "X-Amz-Cf-Pop" for the serving edge POP id (e.g. "CDG52-P1").
	 */
	value = _hdr_match(buffer, total_size, "X-Cache:");
	if (value) {
		_copy_hdr_value(value, total_size - (size_t)(value - buffer),
				ctx->x_cache, sizeof(ctx->x_cache));
		return total_size;
	}
	value = _hdr_match(buffer, total_size, "X-Amz-Cf-Pop:");
	if (value) {
		_copy_hdr_value(value, total_size - (size_t)(value - buffer),
				ctx->x_amz_cf_pop, sizeof(ctx->x_amz_cf_pop));
		return total_size;
	}

	/*
	 * Content-Range: bytes <start>-<end>/<total>. Used by tail-fetch
	 * callers to learn the object's total size without a separate HEAD.
	 */
	value = _hdr_match(buffer, total_size, "Content-Range:");
	if (value) {
		const char *slash;
		size_t hdr_remaining = total_size - (size_t)(value - buffer);
		size_t i;
		for (i = 0, slash = NULL; i < hdr_remaining; i++) {
			if (value[i] == '/') {
				slash = value + i + 1;
				break;
			}
			if (value[i] == '\r' || value[i] == '\n')
				break;
		}
		if (slash) {
			unsigned long total_len = 0;
			while (slash < value + hdr_remaining &&
			       *slash >= '0' && *slash <= '9') {
				total_len = total_len * 10 + (*slash - '0');
				slash++;
			}
			ctx->content_range_total = total_len;
		}
		return total_size;
	}

	return total_size;
}

/* Write callback router that directs to appropriate buffer */
static size_t write_router_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	struct FetchContext *ctx = (struct FetchContext *)userp;

	if (ctx->got_error) {
		return write_error_callback(contents, size, nmemb, ctx->error_chunk);
	} else {
		return write_callback(contents, size, nmemb, ctx->data_chunk);
	}
}

/*
 * =================================================================================
 * CURL Handle Management - Process-Local
 * =================================================================================
 */

/* Set fixed curl options that don't change between requests */
/*
 * Custom socket open callback for libcurl.
 * Moves the socket fd out of the user fd range using the
 * centralized relocate_internal_fd() policy.
 */
static curl_socket_t curl_opensocket_cb(void *clientp,
					curlsocktype purpose,
					struct curl_sockaddr *address)
{
	curl_socket_t s;

	(void)clientp;
	(void)purpose;

	s = socket(address->family, address->socktype, address->protocol);
	if (s == CURL_SOCKET_BAD)
		return CURL_SOCKET_BAD;

	return relocate_internal_fd(s);
}

/* Forward declaration — implementation sits in the upload_pool section below. */
static int _upload_sockopt_cb(void *clientp, curl_socket_t sockfd,
			      curlsocktype purpose);
static CURLcode _upload_ssl_ctx_cb(CURL *curl, void *sslctx, void *parm);

/* Shared URL-construction result, defined here (before first use) and
 * populated by _construct_object_url below. */
struct object_url_info {
	char url[2048];
	char auth_host[512];
	char canonical_uri[2048];
	char full_object_path[1024];
};
static int _construct_object_url(const char *object_key, struct object_url_info *info);

static void set_fixed_curl_options(CURL *handle)
{
	curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);

	/* TCP keepalive settings */
	curl_easy_setopt(handle, CURLOPT_TCP_KEEPALIVE, 1L);
	curl_easy_setopt(handle, CURLOPT_TCP_KEEPIDLE, 120L);
	curl_easy_setopt(handle, CURLOPT_TCP_KEEPINTVL, 60L);

	/* Connection caching/reuse settings */
	curl_easy_setopt(handle, CURLOPT_FORBID_REUSE, 0L);
	curl_easy_setopt(handle, CURLOPT_FRESH_CONNECT, 0L);

	/* Critical: Avoid using stdin (fd 0) */
	curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);

	/* SSL verification */
	curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);

	/*
	 * Larger download read buffer: default 16 KB means 512 read
	 * callbacks per 8 MB Range GET. 512 KB drops to 16 callbacks and
	 * lets the kernel TCP receive buffer fill with fewer userspace
	 * hops. Complements SO_RCVBUF tuning below.
	 */
	curl_easy_setopt(handle, CURLOPT_BUFFERSIZE, 512L * 1024L);

	/* TCP_NODELAY: disable Nagle for small request bursts. */
	curl_easy_setopt(handle, CURLOPT_TCP_NODELAY, 1L);

	/*
	 * Bigger SO_RCVBUF (2 MB) so BDP between EC2 and S3 is fully
	 * utilized by Range GETs. Matches the upload_pool SOCKOPT
	 * callback — shared between upload (emphasizes SO_SNDBUF) and
	 * download (emphasizes SO_RCVBUF) since both are raised.
	 */
	curl_easy_setopt(handle, CURLOPT_SOCKOPTFUNCTION, _upload_sockopt_cb);
	curl_easy_setopt(handle, CURLOPT_SOCKOPTDATA, NULL);

	/*
	 * Enable Kernel TLS — kernel offloads AES-GCM record enc/dec.
	 * Useful on restore Range GET path too since decryption would
	 * otherwise run on the per-worker thread. Falls back to userspace
	 * OpenSSL if the kernel refuses the TLS ULP attach.
	 */
	curl_easy_setopt(handle, CURLOPT_SSL_CTX_FUNCTION, _upload_ssl_ctx_cb);

	/* Move curl sockets to high fd range to avoid conflicts with restore */
	curl_easy_setopt(handle, CURLOPT_OPENSOCKETFUNCTION, curl_opensocket_cb);
}

/* Get curl handle for current process (create if not exists) */
static CURL *get_curl_handle_for_current_process(void)
{
	pid_t current_pid = getpid();
	struct curl_handle_entry *entry = g_curl_handles;
	CURL *new_handle;

	/* Search for existing handle for this PID */
	while (entry) {
		if (entry->pid == current_pid) {
			pr_debug("Reusing existing curl handle for PID %d (handle: %p, requests: %d)\n", current_pid,
				 entry->handle, entry->request_count);
			return entry->handle;
		}
		entry = entry->next;
	}

	/* No handle found, create a new one */
	pr_info("Creating new curl handle for PID %d\n", current_pid);
	new_handle = curl_easy_init();
	if (!new_handle) {
		pr_err("Failed to initialize curl handle for PID %d\n", current_pid);
		return NULL;
	}

	/* Set fixed options once during handle creation */
	set_fixed_curl_options(new_handle);

	/* Create new entry */
	entry = malloc(sizeof(struct curl_handle_entry));
	if (!entry) {
		curl_easy_cleanup(new_handle);
		pr_err("Failed to allocate memory for curl handle entry (PID %d)\n", current_pid);
		return NULL;
	}

	/* Initialize entry */
	entry->pid = current_pid;
	entry->handle = new_handle;
	entry->last_used = time(NULL);
	entry->request_count = 0;

	/* Add to global list */
	entry->next = g_curl_handles;
	g_curl_handles = entry;

	return new_handle;
}

/* Update usage statistics for the current process's handle */
static void update_handle_stats(void)
{
	pid_t current_pid = getpid();
	struct curl_handle_entry *entry = g_curl_handles;

	while (entry) {
		if (entry->pid == current_pid) {
			entry->last_used = time(NULL);
			entry->request_count++;
			pr_debug("Updated curl handle stats for PID %d (requests: %d)\n", current_pid,
				 entry->request_count);
			break;
		}
		entry = entry->next;
	}
}

/* Clean up the curl handle for a specific process */
static void cleanup_curl_handle_for_process(pid_t pid)
{
	struct curl_handle_entry **pp = &g_curl_handles;
	struct curl_handle_entry *entry;

	while (*pp) {
		entry = *pp;
		if (entry->pid == pid) {
			*pp = entry->next;
			pr_info("Cleaning up curl handle for PID %d (handle: %p, requests: %d)\n", pid,
				entry->handle, entry->request_count);
			curl_easy_cleanup(entry->handle);
			free(entry);
			return;
		}
		pp = &entry->next;
	}
}

/* Process exit handler (called via atexit) */
static void cleanup_current_process_curl_handle(void)
{
	cleanup_curl_handle_for_process(getpid());
}

/* Clean up all curl handles and resources */
static void cleanup_all_curl_resources(void)
{
	struct curl_handle_entry *entry = g_curl_handles;
	struct curl_handle_entry *next;

	/* Clean up all handles in the list */
	while (entry) {
		next = entry->next;
		pr_info("Cleaning up curl handle for PID %d (handle: %p, requests: %d)\n", entry->pid,
			entry->handle, entry->request_count);
		curl_easy_cleanup(entry->handle);
		free(entry);
		entry = next;
	}

	g_curl_handles = NULL;

	/* Only clean up global resources if we initialized them in this process */
	if (g_curl_initialized_in_this_process) {
		curl_global_cleanup();
		pr_info("Object Storage client global resources cleaned up (PID: %d)\n", getpid());
		g_curl_initialized_in_this_process = 0;
	}
}

/*
 * =================================================================================
 * CURL Handle Management - Thread-Local
 * =================================================================================
 */

/* Thread-local storage destructor for CURL handles */
static void curl_thread_handle_destructor(void *handle)
{
	CURL *curl_handle = (CURL *)handle;
	struct curl_thread_handle *entry, **pp;
	pthread_t thread_id = pthread_self();

	if (curl_handle) {
		struct curl_slist *resolve_list = NULL;
		/* Remove from global thread handle list */
		pthread_mutex_lock(&g_thread_handles_mutex);
		pp = &g_thread_handles;
		while (*pp) {
			entry = *pp;
			if (pthread_equal(entry->thread_id, thread_id)) {
				*pp = entry->next;
				resolve_list = entry->resolve_list;
				pr_debug("Thread %lu: Cleaning up thread-local CURL handle (requests: %d)\n",
					 (unsigned long)thread_id, entry->request_count);
				free(entry);
				break;
			}
			pp = &entry->next;
		}
		pthread_mutex_unlock(&g_thread_handles_mutex);

		curl_easy_cleanup(curl_handle);
		if (resolve_list)
			curl_slist_free_all(resolve_list);
	}
}

/* Initialize thread-local storage key */
static void init_curl_thread_key(void)
{
	pthread_key_create(&g_curl_thread_key, curl_thread_handle_destructor);
}

/*
 * Resolve the S3 host once per process and populate g_s3_ips[]. Safe to
 * call repeatedly; no-op after the first successful resolution. Uses
 * the currently configured endpoint URL + bucket to derive the auth host
 * the same way real PUT/GET requests do.
 */
static void _resolve_s3_edge_ips_once(void)
{
	struct object_url_info tmp;
	struct addrinfo hints, *res = NULL, *ai;
	char port_str[8];
	char ipbuf[64];
	int port = 443;
	int rc, i, distinct = 0;

	pthread_mutex_lock(&g_s3_ips_mutex);
	if (g_s3_n_ips > 0) {
		pthread_mutex_unlock(&g_s3_ips_mutex);
		return;
	}
	pthread_mutex_unlock(&g_s3_ips_mutex);

	/* Re-construct URL info to get auth_host + scheme. Key choice is
	 * arbitrary: the auth host is the same for every key in a session. */
	if (_construct_object_url("probe", &tmp) != 0)
		return;
	if (strncmp(tmp.url, "http://", 7) == 0)
		port = 80;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(port_str, sizeof(port_str), "%d", port);

	rc = getaddrinfo(tmp.auth_host, port_str, &hints, &res);
	if (rc != 0 || !res) {
		pr_warn("restore IP pool: getaddrinfo(%s) failed: %s\n",
			tmp.auth_host, gai_strerror(rc));
		return;
	}

	pthread_mutex_lock(&g_s3_ips_mutex);
	if (g_s3_n_ips == 0) {
		for (ai = res; ai && distinct < MAX_RESOLVED_IPS; ai = ai->ai_next) {
			const struct sockaddr_in *sin = (const struct sockaddr_in *)ai->ai_addr;
			if (!inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf)))
				continue;
			for (i = 0; i < distinct; i++) {
				if (strcmp(g_s3_ips[i], ipbuf) == 0)
					break;
			}
			if (i < distinct)
				continue;
			snprintf(g_s3_ips[distinct], sizeof(g_s3_ips[distinct]),
				 "%s", ipbuf);
			distinct++;
		}
		if (distinct > 0) {
			snprintf(g_s3_host, sizeof(g_s3_host), "%s", tmp.auth_host);
			g_s3_port = port;
			g_s3_n_ips = distinct;
			pr_info("restore IP pool: resolved %d distinct IPs for %s\n",
				distinct, tmp.auth_host);
		}
	}
	pthread_mutex_unlock(&g_s3_ips_mutex);
	freeaddrinfo(res);
}

/*
 * Attach a CURLOPT_RESOLVE entry pinning this handle to one of the
 * resolved S3 edge IPs (round-robin across calls). Returns the
 * curl_slist (caller frees on handle teardown) or NULL if no pool
 * available / host unknown. Not fatal to ignore — without the pin,
 * libcurl uses its own DNS cache and perf degrades to single-edge.
 */
static struct curl_slist *_pin_handle_to_s3_edge(CURL *handle)
{
	struct curl_slist *list = NULL;
	char entry[640];
	const char *chosen_ip = NULL;

	_resolve_s3_edge_ips_once();

	pthread_mutex_lock(&g_s3_ips_mutex);
	if (g_s3_n_ips > 0 && g_s3_host[0]) {
		int slot = g_s3_next_slot++ % g_s3_n_ips;
		chosen_ip = g_s3_ips[slot];
		snprintf(entry, sizeof(entry), "%s:%d:%s",
			 g_s3_host, g_s3_port, chosen_ip);
	}
	pthread_mutex_unlock(&g_s3_ips_mutex);

	if (chosen_ip) {
		list = curl_slist_append(NULL, entry);
		if (list)
			curl_easy_setopt(handle, CURLOPT_RESOLVE, list);
	}
	return list;
}

/* Get or create thread-local CURL handle */
static CURL *get_thread_curl_handle(void)
{
	CURL *handle;
	struct curl_thread_handle *entry;
	pthread_t thread_id = pthread_self();

	/* Ensure thread key is initialized */
	pthread_once(&g_curl_thread_key_once, init_curl_thread_key);

	/* Check if we already have a handle for this thread */
	handle = (CURL *)pthread_getspecific(g_curl_thread_key);
	if (handle) {
		/* Update statistics */
		pthread_mutex_lock(&g_thread_handles_mutex);
		entry = g_thread_handles;
		while (entry) {
			if (pthread_equal(entry->thread_id, thread_id)) {
				entry->last_used = time(NULL);
				entry->request_count++;
				break;
			}
			entry = entry->next;
		}
		pthread_mutex_unlock(&g_thread_handles_mutex);
		return handle;
	}

	/* Create new handle for this thread */
	handle = curl_easy_init();
	if (!handle) {
		pr_err("Thread %lu: Failed to initialize CURL handle\n", (unsigned long)thread_id);
		return NULL;
	}

	/* Set fixed options for the handle */
	set_fixed_curl_options(handle);

	/*
	 * Pin this thread's handle to one of the resolved S3 edge IPs so
	 * concurrent workers spread across S3 partitions. Without this,
	 * every worker resolves the same host via glibc getaddrinfo in
	 * the same order and ends up on the same IP.
	 */
	{
		struct curl_slist *resolve_list = _pin_handle_to_s3_edge(handle);

		/* Store in thread-local storage */
		pthread_setspecific(g_curl_thread_key, handle);

		/* Add to global thread handle list for tracking */
		entry = malloc(sizeof(struct curl_thread_handle));
		if (entry) {
			entry->thread_id = thread_id;
			entry->handle = handle;
			entry->resolve_list = resolve_list;
			entry->last_used = time(NULL);
			entry->request_count = 0;

			pthread_mutex_lock(&g_thread_handles_mutex);
			entry->next = g_thread_handles;
			g_thread_handles = entry;
			pthread_mutex_unlock(&g_thread_handles_mutex);

			pr_info("Thread TID=%d (pthread_id=%lu): Created new thread-local CURL handle\n",
				get_thread_id(), (unsigned long)thread_id);
		} else if (resolve_list) {
			/* Couldn't track entry; free slist ourselves now. */
			curl_slist_free_all(resolve_list);
		}
	}

	return handle;
}

/*
 * =================================================================================
 * Lazy Pages Context Management
 * =================================================================================
 */

/* Re-initialize curl for lazy-pages context */
static int reinitialize_curl_for_lazy_pages(void)
{
	CURLcode res;

	/* Clean up all existing curl resources first */
	cleanup_all_curl_resources();

	/* Re-initialize curl */
	res = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (res != CURLE_OK) {
		pr_err("curl_global_init() failed during lazy-pages reinitialization: %s\n",
		       curl_easy_strerror(res));
		return -1;
	}

	g_curl_initialized_in_this_process = 1;
	g_is_lazy_pages_context = 1;

	pr_info("Object Storage client reinitialized for lazy-pages context (PID: %d)\n", getpid());
	return 0;
}

/* Check if we're in a lazy-pages context and need to reinitialize curl */
static int check_and_reinitialize_for_lazy_pages(void)
{
	pid_t current_pid = getpid();
	struct curl_handle_entry *entry = g_curl_handles;
	int found = 0;

	/* Check if we already have a handle for this process */
	while (entry) {
		if (entry->pid == current_pid) {
			found = 1;
			break;
		}
		entry = entry->next;
	}

	/* If this is the first request in this process and we're not in a known lazy-pages context */
	if (!found && !g_is_lazy_pages_context) {
		pr_info("Detected possible lazy-pages context in PID %d, reinitializing curl\n", current_pid);
		return reinitialize_curl_for_lazy_pages();
	}

	return 0;
}

/*
 * =================================================================================
 * AWS S3 Express One Zone Session Management
 * =================================================================================
 */

/* Create a session for Express One Zone using the CreateSession API */
static int _object_storage_create_express_session(void)
{
	CURL *curl;
	CURLcode res;
	struct MemoryStruct chunk;
	char session_url[1024];
	long http_code = 0;
	struct curl_slist *headers = NULL;
	char amz_date[17];
	char date_stamp[9];
	time_t now;
	struct tm *tm_gmt;
	const char *method = "GET";
	const char *service = "s3";
	const char *payload = "";
	size_t payload_len;
	char payload_hash[65];
	char canonical_uri[] = "/";
	char canonical_querystring[] = "session=";
	char canonical_headers[4096];
	char signed_headers[] = "host;x-amz-content-sha256;x-amz-create-session-mode;x-amz-date";
	char canonical_request[8192];
	char canonical_request_hash[65];
	char string_to_sign[512];
	char credential_scope[128];
	unsigned char *signing_key;
	unsigned int signing_key_len;
	unsigned char *signature_raw;
	unsigned int signature_raw_len;
	char signature_hex[65];
	char auth_header[512];
	char x_amz_date_header[64];
	char x_amz_content_sha256_header[100];
	int i;

	const char *endpoint_host;

	OBJSTOR_SESSION_CREATE_LOG();

	if (!opts.aws_access_key || !opts.aws_secret_key || !opts.aws_region) {
		pr_err("Missing AWS credentials or region for Express One Zone session\n");
		return -1;
	}

	/* Strip optional protocol prefix so concatenation produces a well-formed URL.
	 * Without this we end up with "https://bucket.https://endpoint/?session". */
	endpoint_host = opts.object_storage_endpoint_url;
	if (endpoint_host && strncmp(endpoint_host, "https://", 8) == 0)
		endpoint_host += 8;
	else if (endpoint_host && strncmp(endpoint_host, "http://", 7) == 0)
		endpoint_host += 7;

	payload_len = strlen(payload);
	now = time(NULL);
	tm_gmt = gmtime(&now);
	strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", tm_gmt);
	strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", tm_gmt);

	snprintf(session_url, sizeof(session_url), "https://%s.%s/?session", opts.object_storage_bucket,
		 endpoint_host);
	pr_info("Session URL: %s\n", session_url);

	_sha256_hex(payload, payload_len, payload_hash);

	snprintf(canonical_headers, sizeof(canonical_headers),
		 "host:%s.%s\n"
		 "x-amz-content-sha256:%s\n"
		 "x-amz-create-session-mode:ReadWrite\n"
		 "x-amz-date:%s\n",
		 opts.object_storage_bucket, endpoint_host, payload_hash, amz_date);

	snprintf(canonical_request, sizeof(canonical_request), "%s\n%s\n%s\n%s\n%s\n%s", method, canonical_uri,
		 canonical_querystring, canonical_headers, signed_headers, payload_hash);

	_sha256_hex(canonical_request, strlen(canonical_request), canonical_request_hash);

	snprintf(credential_scope, sizeof(credential_scope), "%s/%s/%s/aws4_request", date_stamp, opts.aws_region,
		 service);

	snprintf(string_to_sign, sizeof(string_to_sign), "AWS4-HMAC-SHA256\n%s\n%s\n%s", amz_date, credential_scope,
		 canonical_request_hash);

	signing_key = _get_signature_key(opts.aws_secret_key, date_stamp, opts.aws_region, service, &signing_key_len);
	signature_raw = _hmac_sha256(signing_key, signing_key_len, (unsigned char *)string_to_sign,
				     strlen(string_to_sign), &signature_raw_len);
	if (signing_key)
		free(signing_key);

	if (signature_raw) {
		for (i = 0; i < signature_raw_len; i++) {
			sprintf(signature_hex + i * 2, "%02x", signature_raw[i]);
		}
		signature_hex[signature_raw_len * 2] = '\0';
		free(signature_raw);
	} else {
		pr_err("Failed to create signature\n");
		return -1;
	}

	snprintf(auth_header, sizeof(auth_header),
		 "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		 opts.aws_access_key, credential_scope, signed_headers, signature_hex);

	chunk.memory = malloc(1);
	chunk.size = 0;
	chunk.capacity = 0; /* 0 indicates dynamic allocation mode */

	curl = curl_easy_init();
	if (!curl) {
		pr_err("Failed to initialize curl for session creation\n");
		free(chunk.memory);
		return -1;
	}

	headers = curl_slist_append(headers, "x-amz-create-session-mode: ReadWrite");
	snprintf(x_amz_date_header, sizeof(x_amz_date_header), "x-amz-date: %s", amz_date);
	headers = curl_slist_append(headers, x_amz_date_header);
	snprintf(x_amz_content_sha256_header, sizeof(x_amz_content_sha256_header), "x-amz-content-sha256: %s",
		 payload_hash);
	headers = curl_slist_append(headers, x_amz_content_sha256_header);
	headers = curl_slist_append(headers, auth_header);

	curl_easy_setopt(curl, CURLOPT_URL, session_url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0L);

	res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	if (res != CURLE_OK || http_code >= 400) {
		OBJSTOR_SESSION_ERROR_LOG(http_code);
		pr_err("CreateSession request failed: %s (HTTP code: %ld)\n", curl_easy_strerror(res), http_code);
		pr_err("--- Server Error Response ---\n");
		if (chunk.size > 0)
			pr_err("%.*s\n", (int)chunk.size, chunk.memory);
		pr_err("---------------------------\n");
		curl_easy_cleanup(curl);
		free(chunk.memory);
		curl_slist_free_all(headers);
		return -1;
	}

	pr_debug("CreateSession response: %s\n", chunk.memory);

	if (_parse_xml_tag(chunk.memory, "AccessKeyId", g_session_access_key, sizeof(g_session_access_key)) != 0 ||
	    _parse_xml_tag(chunk.memory, "SecretAccessKey", g_session_secret_key, sizeof(g_session_secret_key)) !=
		    0 ||
	    _parse_xml_tag(chunk.memory, "SessionToken", g_session_token, sizeof(g_session_token)) != 0) {
		pr_err("Failed to parse session credentials from XML response\n");
		curl_easy_cleanup(curl);
		free(chunk.memory);
		curl_slist_free_all(headers);
		return -1;
	}

	pr_info("Successfully parsed session credentials:\n");

	/* Set session expiration to 4 minutes from now */
	g_session_expiration = time(NULL) + (4 * 60);

	OBJSTOR_SESSION_CREATED_LOG(g_session_expiration);

	curl_easy_cleanup(curl);
	free(chunk.memory);
	curl_slist_free_all(headers);

	return 0;
}

/* Ensure we have a valid (non-expired) Express One Zone session */
static int ensure_valid_session(void)
{
	if (!opts.express_one_zone)
		return 0;

	if (g_session_expiration == 0 || time(NULL) >= g_session_expiration) {
		pr_info("Express One Zone session is expired or not created. Creating a new one.\n");
		return _object_storage_create_express_session();
	}

	return 0;
}

/*
 * =================================================================================
 * Public API Implementation
 * =================================================================================
 */

int object_storage_reinit_after_fork(void)
{
	/* Wraps the static reinitialize_curl_for_lazy_pages so external code
	 * can force a single-threaded curl re-init before spawning workers. */
	return reinitialize_curl_for_lazy_pages();
}

int object_storage_init(void)
{
	CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (res != CURLE_OK) {
		pr_err("curl_global_init() failed: %s\n", curl_easy_strerror(res));
		return -1;
	}

	/* Mark that we initialized curl in this process */
	g_curl_initialized_in_this_process = 1;

	/* Initialize handle storage */
	g_curl_handles = NULL;

	/* Register cleanup handler for this process */
	if (atexit(cleanup_current_process_curl_handle) != 0) {
		pr_warn("Failed to register curl handle cleanup handler\n");
	}

	pr_info("Object Storage client initialized (libcurl, PID: %d)\n", getpid());

	if (opts.express_one_zone) {
		pr_info("Express One Zone mode enabled\n");

		if (!opts.aws_access_key || !opts.aws_secret_key || !opts.aws_region) {
			pr_err("Express One Zone requires --aws-access-key, --aws-secret-key, and --aws-region\n");
			return -1;
		}

		if (ensure_valid_session() != 0) {
			pr_err("Failed to create initial Express One Zone session\n");
			return -1;
		}
	}

	if (!opts.express_one_zone && opts.aws_access_key && opts.aws_secret_key) {
		if (!opts.aws_region) {
			pr_err("SigV4 authentication requires --aws-region\n");
			return -1;
		}
		pr_info("Standard S3 mode with SigV4 authentication%s\n",
			opts.object_storage_path_style ? " (path-style)" : "");
	}

	return 0;
}

void object_storage_cleanup(void)
{
	cleanup_all_curl_resources();
	pr_info("Object Storage client cleaned up (libcurl, PID: %d)\n", getpid());
}

/*
 * =================================================================================
 * URL Construction Helper
 * =================================================================================
 *
 * Constructs S3 URL, auth host, and canonical URI from object key and options.
 * Shared by fetch_range, put_object, and multipart operations.
 * (struct object_url_info is forward-declared near the top of the file.)
 */
static int _construct_object_url(const char *object_key, struct object_url_info *info)
{
	char normalized_prefix[512];
	const char *endpoint_url;
	const char *hostname;

	memset(info, 0, sizeof(*info));

	/* Normalize the object prefix */
	if (opts.object_storage_object_prefix) {
		const char *original_prefix = opts.object_storage_object_prefix;
		size_t prefix_len = strlen(original_prefix);
		if (prefix_len == 1 && original_prefix[0] == '/') {
			normalized_prefix[0] = '\0';
		} else if (prefix_len > 0) {
			const char *start = original_prefix;
			size_t copy_len = prefix_len;
			if (original_prefix[0] == '/') {
				start++;
				copy_len--;
			}
			snprintf(normalized_prefix, sizeof(normalized_prefix), "%.*s", (int)copy_len, start);
			if (copy_len > 0 && normalized_prefix[copy_len - 1] != '/') {
				size_t current_len = strlen(normalized_prefix);
				if (current_len < sizeof(normalized_prefix) - 1) {
					normalized_prefix[current_len] = '/';
					normalized_prefix[current_len + 1] = '\0';
				}
			}
		} else {
			normalized_prefix[0] = '\0';
		}
	} else {
		normalized_prefix[0] = '\0';
	}

	/* Handle endpoint URL and extract hostname */
	endpoint_url = opts.object_storage_endpoint_url;
	hostname = _strip_scheme(endpoint_url);

	/*
	 * Build full object path. Callers pass `object_key` in one of two
	 * forms:
	 *   1. bare filename (e.g., "inventory.img") — needs normalized_prefix
	 *      prepended to become a full S3 key.
	 *   2. already-prefixed path (e.g., "memcached-4gb/pages-1.img" in
	 *      the normal case, or "pdtest/pd1/pages-1.img" when
	 *      maybe_read_page_object_storage serves a parent page_read with
	 *      its own per-page_read prefix).
	 *
	 * The previous strncmp() check only detected case (2) when the key
	 * started with THE CURRENT opts prefix — so parent-chain keys (which
	 * use the PARENT's prefix, not the current) were incorrectly
	 * re-prefixed, producing "pdtest/pd_dump/pdtest/pd1/pages-1.img".
	 *
	 * Simpler rule: any key containing '/' is already absolute and must
	 * not be re-prefixed. Bare filenames never contain '/'.
	 */
	if (strchr(object_key, '/') != NULL) {
		snprintf(info->full_object_path, sizeof(info->full_object_path), "%s", object_key);
	} else {
		snprintf(info->full_object_path, sizeof(info->full_object_path), "%s%s", normalized_prefix, object_key);
	}

	/* Construct URL */
	if (opts.express_one_zone) {
		snprintf(info->url, sizeof(info->url), "https://%s.%s/%s",
			 opts.object_storage_bucket, hostname, info->full_object_path);
	} else if (opts.object_storage_bucket && opts.object_storage_bucket[0] != '\0') {
		if (opts.object_storage_path_style) {
			if (hostname != endpoint_url) {
				snprintf(info->url, sizeof(info->url), "%.*s%s/%s/%s",
					 (int)(hostname - endpoint_url), endpoint_url,
					 hostname, opts.object_storage_bucket, info->full_object_path);
			} else {
				snprintf(info->url, sizeof(info->url), "https://%s/%s/%s",
					 hostname, opts.object_storage_bucket, info->full_object_path);
			}
		} else {
			if (hostname != endpoint_url) {
				snprintf(info->url, sizeof(info->url), "%.*s%s.%s/%s",
					 (int)(hostname - endpoint_url), endpoint_url,
					 opts.object_storage_bucket, hostname, info->full_object_path);
			} else {
				snprintf(info->url, sizeof(info->url), "https://%s.%s/%s",
					 opts.object_storage_bucket, hostname, info->full_object_path);
			}
		}
	} else {
		if (hostname != endpoint_url) {
			snprintf(info->url, sizeof(info->url), "%s/%s", endpoint_url, info->full_object_path);
		} else {
			snprintf(info->url, sizeof(info->url), "https://%s/%s", hostname, info->full_object_path);
		}
	}

	/* Construct auth host */
	if (opts.express_one_zone) {
		snprintf(info->auth_host, sizeof(info->auth_host), "%s.%s",
			 opts.object_storage_bucket, hostname);
	} else if (opts.object_storage_path_style ||
		   !opts.object_storage_bucket || !opts.object_storage_bucket[0]) {
		snprintf(info->auth_host, sizeof(info->auth_host), "%s", hostname);
	} else {
		snprintf(info->auth_host, sizeof(info->auth_host), "%s.%s",
			 opts.object_storage_bucket, hostname);
	}
	/* Strip trailing slash from auth_host */
	{
		size_t hlen = strlen(info->auth_host);
		if (hlen > 0 && info->auth_host[hlen - 1] == '/')
			info->auth_host[hlen - 1] = '\0';
	}

	/* Construct canonical URI */
	if (!opts.express_one_zone && opts.object_storage_path_style &&
	    opts.object_storage_bucket && opts.object_storage_bucket[0]) {
		snprintf(info->canonical_uri, sizeof(info->canonical_uri), "/%s/%s",
			 opts.object_storage_bucket, info->full_object_path);
	} else {
		snprintf(info->canonical_uri, sizeof(info->canonical_uri), "/%s", info->full_object_path);
	}

	return 0;
}

/*
 * Get curl handle appropriate for current thread context.
 * Returns NULL on failure.
 */
static CURL *_get_curl_handle(void)
{
	CURL *handle;

	if (!is_main_thread()) {
		handle = get_thread_curl_handle();
		if (!handle)
			pr_err("Failed to get thread-local curl handle\n");
		return handle;
	}

	handle = get_curl_handle_for_current_process();
	if (!handle) {
		pr_warn("Failed to get process curl handle, using one-time handle\n");
		handle = curl_easy_init();
		if (handle)
			set_fixed_curl_options(handle);
		return handle;
	}

	curl_easy_reset(handle);
	set_fixed_curl_options(handle);
	return handle;
}

/*
 * =================================================================================
 * PUT Object — Simple upload for small files (metadata, pagemap, etc.)
 * =================================================================================
 */

/* Read callback for curl PUT upload */
struct UploadContext {
	const char *data;
	unsigned long size;
	unsigned long offset;
};

static size_t _upload_read_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct UploadContext *ctx = (struct UploadContext *)userdata;
	size_t remaining = ctx->size - ctx->offset;
	size_t to_copy = size * nmemb;
	if (to_copy > remaining)
		to_copy = remaining;
	memcpy(ptr, ctx->data + ctx->offset, to_copy);
	ctx->offset += to_copy;
	return to_copy;
}

/* Forward declaration for the metadata-bundle accumulator (defined further
 * down with the manifest helpers). Declared here because object_storage_put_object
 * mirrors small successful PUTs into the bundle. */
static int _bundle_accum_add(const char *key, const void *data, unsigned long length);

int object_storage_put_object(const char *object_key, const void *data, unsigned long length)
{
	struct object_url_info url_info;
	struct UploadContext upload_ctx;
	struct MemoryStruct response;
	CURL *curl_handle;
	CURLcode res;
	long http_code = 0;
	struct curl_slist *headers = NULL;
	char content_sha256[65];

	if (!object_key || !data) {
		pr_err("put_object: NULL object_key or data\n");
		return -1;
	}

	/* Ensure valid session for Express One Zone */
	if (opts.express_one_zone) {
		if (ensure_valid_session() != 0)
			return -1;
	}

	/* Construct URL */
	if (_construct_object_url(object_key, &url_info) != 0)
		return -1;

	/* Compute body hash (or UNSIGNED-PAYLOAD marker). */
	_payload_hash(data, length, content_sha256);

	/* Get curl handle */
	curl_handle = _get_curl_handle();
	if (!curl_handle)
		return -1;

	/* Setup upload context */
	upload_ctx.data = (const char *)data;
	upload_ctx.size = length;
	upload_ctx.offset = 0;

	/* Setup response buffer */
	response.memory = malloc(1);
	response.size = 0;
	response.capacity = 0;

	/* Configure curl for PUT */
	curl_easy_setopt(curl_handle, CURLOPT_URL, url_info.url);
	curl_easy_setopt(curl_handle, CURLOPT_UPLOAD, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_READFUNCTION, _upload_read_callback);
	curl_easy_setopt(curl_handle, CURLOPT_READDATA, &upload_ctx);
	curl_easy_setopt(curl_handle, CURLOPT_INFILESIZE_LARGE, (curl_off_t)length);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);

	/* Build auth headers */
	if (_build_auth_headers("PUT", url_info.auth_host, url_info.canonical_uri, NULL,
			       content_sha256, NULL, (long)length, &headers) != 0) {
		free(response.memory);
		return -1;
	}
	if (headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

	pr_info("PUT %s (%lu bytes)\n", url_info.url, length);

	/* Execute */
	res = curl_easy_perform(curl_handle);
	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

	if (headers)
		curl_slist_free_all(headers);

	if (res != CURLE_OK) {
		pr_err("PUT failed: %s\n", curl_easy_strerror(res));
		free(response.memory);
		return -1;
	}

	if (http_code < 200 || http_code >= 300) {
		pr_err("PUT failed with HTTP %ld: %.*s\n", http_code,
		       (int)response.size, response.memory);
		free(response.memory);
		return -1;
	}

	pr_info("PUT %s succeeded (HTTP %ld)\n", object_key, http_code);
	free(response.memory);

	/*
	 * Mirror small successful PUTs into the metadata bundle accumulator
	 * so a single bundle GET on restore replaces N parallel small GETs.
	 * Cap each entry at 1 MB (the bundle stays small enough to fit in
	 * a single response) and skip the bundle/manifest objects themselves.
	 * Failures here are non-fatal — the dump is still valid and the
	 * restore can fall through to per-key fetches.
	 */
	{
		const char *base = strrchr(object_key, '/');
		base = base ? base + 1 : object_key;
		if (length > 0 && length <= (1UL << 20) &&
		    strcmp(base, "manifest.txt") != 0 &&
		    strcmp(base, "metadata.tar") != 0)
			(void)_bundle_accum_add(object_key, data, length);
	}

	return 0;
}

/*
 * =================================================================================
 * Async PUT pool — for back-to-back small uploads (image files, etc.)
 *
 * Many CRIU image files (core-*, fs-*, ids-*, mm-*, fdinfo-*, ...) get
 * written and uploaded back-to-back at the end of dump. Synchronously
 * PUTting each one cross-region serializes ~30 × ~150 ms RTTs, costing
 * ~5 s of wall time. The async pool collapses that to roughly
 * ceil(N / workers) × RTT by overlapping uploads.
 * =================================================================================
 */
#define ASYNC_PUT_WORKERS	4

struct put_work_item {
	char *key;
	void *data;	/* owned by the queue; worker frees after PUT */
	unsigned long length;
	struct put_work_item *next;
};

static struct put_work_item *g_put_q_head;
static struct put_work_item *g_put_q_tail;
static pthread_mutex_t g_put_q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_put_q_avail = PTHREAD_COND_INITIALIZER;
static pthread_cond_t g_put_q_drain = PTHREAD_COND_INITIALIZER;
static pthread_t g_put_workers[ASYNC_PUT_WORKERS];
static bool g_put_workers_started = false;
static bool g_put_shutdown = false;
static int g_put_inflight;

static void *_put_worker_thread(void *arg)
{
	(void)arg;
	for (;;) {
		struct put_work_item *item;

		pthread_mutex_lock(&g_put_q_lock);
		while (!g_put_q_head && !g_put_shutdown)
			pthread_cond_wait(&g_put_q_avail, &g_put_q_lock);
		if (!g_put_q_head && g_put_shutdown) {
			pthread_mutex_unlock(&g_put_q_lock);
			break;
		}
		item = g_put_q_head;
		g_put_q_head = item->next;
		if (!g_put_q_head)
			g_put_q_tail = NULL;
		pthread_mutex_unlock(&g_put_q_lock);

		(void)object_storage_put_object(item->key, item->data, item->length);
		free(item->key);
		free(item->data);
		free(item);

		pthread_mutex_lock(&g_put_q_lock);
		g_put_inflight--;
		if (g_put_inflight == 0)
			pthread_cond_broadcast(&g_put_q_drain);
		pthread_mutex_unlock(&g_put_q_lock);
	}
	return NULL;
}

int object_storage_put_object_async(const char *object_key, void *data,
				    unsigned long length)
{
	struct put_work_item *item;

	if (!object_key || !data || length == 0)
		return -1;

	pthread_mutex_lock(&g_put_q_lock);
	if (!g_put_workers_started) {
		int i;
		g_put_shutdown = false;
		for (i = 0; i < ASYNC_PUT_WORKERS; i++) {
			if (pthread_create(&g_put_workers[i], NULL,
					   _put_worker_thread, NULL) != 0) {
				pr_warn("async-put: spawn worker[%d] failed\n", i);
				/* Continue with whatever workers we got. */
				break;
			}
		}
		g_put_workers_started = true;
	}
	pthread_mutex_unlock(&g_put_q_lock);

	item = malloc(sizeof(*item));
	if (!item)
		return -1;
	item->key = strdup(object_key);
	if (!item->key) {
		free(item);
		return -1;
	}
	item->data = data;
	item->length = length;
	item->next = NULL;

	pthread_mutex_lock(&g_put_q_lock);
	if (g_put_q_tail)
		g_put_q_tail->next = item;
	else
		g_put_q_head = item;
	g_put_q_tail = item;
	g_put_inflight++;
	pthread_cond_signal(&g_put_q_avail);
	pthread_mutex_unlock(&g_put_q_lock);

	return 0;
}

void object_storage_drain_uploads(void)
{
	pthread_mutex_lock(&g_put_q_lock);
	while (g_put_inflight > 0)
		pthread_cond_wait(&g_put_q_drain, &g_put_q_lock);
	pthread_mutex_unlock(&g_put_q_lock);
}

/*
 * =================================================================================
 * Multipart Upload — for large files (pages-*.img, typically > 5MB)
 * =================================================================================
 */

int object_storage_multipart_init(const char *object_key, char *upload_id, size_t id_len)
{
	struct object_url_info url_info;
	struct MemoryStruct response;
	CURL *curl_handle;
	CURLcode res;
	long http_code = 0;
	struct curl_slist *headers = NULL;
	char full_url[2200];

	if (opts.express_one_zone) {
		if (ensure_valid_session() != 0)
			return -1;
	}

	if (_construct_object_url(object_key, &url_info) != 0)
		return -1;

	/* Append ?uploads to URL */
	snprintf(full_url, sizeof(full_url), "%s?uploads", url_info.url);

	curl_handle = _get_curl_handle();
	if (!curl_handle)
		return -1;

	response.memory = malloc(1);
	response.size = 0;
	response.capacity = 0;

	curl_easy_setopt(curl_handle, CURLOPT_URL, full_url);
	curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);

	/* SigV4: POST with empty body, query_string = "uploads=" */
	if (_build_auth_headers("POST", url_info.auth_host, url_info.canonical_uri,
			       "uploads=", EMPTY_PAYLOAD_HASH, NULL, 0, &headers) != 0) {
		free(response.memory);
		return -1;
	}
	if (headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

	res = curl_easy_perform(curl_handle);
	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

	if (headers)
		curl_slist_free_all(headers);

	if (res != CURLE_OK || http_code < 200 || http_code >= 300) {
		pr_err("Multipart init failed: curl=%s http=%ld body=%.*s\n",
		       curl_easy_strerror(res), http_code, (int)response.size, response.memory);
		free(response.memory);
		return -1;
	}

	/* Parse UploadId from XML response */
	if (_parse_xml_tag(response.memory, "UploadId", upload_id, id_len) != 0) {
		pr_err("Failed to parse UploadId from response: %.*s\n",
		       (int)response.size, response.memory);
		free(response.memory);
		return -1;
	}

	pr_info("Multipart upload initiated: %s uploadId=%s\n", object_key, upload_id);
	free(response.memory);
	return 0;
}

int object_storage_multipart_upload_part(const char *object_key, const char *upload_id,
					 int part_num, const void *data, unsigned long length,
					 char *etag, size_t etag_len)
{
	struct object_url_info url_info;
	struct UploadContext upload_ctx;
	struct MemoryStruct response;
	struct MemoryStruct header_buf;
	CURL *curl_handle;
	CURLcode res;
	long http_code = 0;
	struct curl_slist *headers = NULL;
	char full_url[2400];
	char query_string[512];
	char content_sha256[65];
	char *etag_hdr;

	if (opts.express_one_zone) {
		if (ensure_valid_session() != 0)
			return -1;
	}

	if (_construct_object_url(object_key, &url_info) != 0)
		return -1;

	snprintf(full_url, sizeof(full_url), "%s?partNumber=%d&uploadId=%s",
		 url_info.url, part_num, upload_id);
	/* Query string must be sorted alphabetically for SigV4 */
	snprintf(query_string, sizeof(query_string), "partNumber=%d&uploadId=%s",
		 part_num, upload_id);

	_payload_hash(data, length, content_sha256);

	curl_handle = _get_curl_handle();
	if (!curl_handle)
		return -1;

	upload_ctx.data = (const char *)data;
	upload_ctx.size = length;
	upload_ctx.offset = 0;

	response.memory = malloc(1);
	response.size = 0;
	response.capacity = 0;

	curl_easy_setopt(curl_handle, CURLOPT_URL, full_url);
	curl_easy_setopt(curl_handle, CURLOPT_UPLOAD, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_READFUNCTION, _upload_read_callback);
	curl_easy_setopt(curl_handle, CURLOPT_READDATA, &upload_ctx);
	curl_easy_setopt(curl_handle, CURLOPT_INFILESIZE_LARGE, (curl_off_t)length);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);

	/* We need ETag from response headers */
	header_buf.memory = malloc(1);
	header_buf.size = 0;
	header_buf.capacity = 0;
	curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, &header_buf);

	if (_build_auth_headers("PUT", url_info.auth_host, url_info.canonical_uri,
			       query_string, content_sha256, NULL, (long)length, &headers) != 0) {
		free(response.memory);
		free(header_buf.memory);
		return -1;
	}
	if (headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

	res = curl_easy_perform(curl_handle);
	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

	if (headers)
		curl_slist_free_all(headers);

	if (res != CURLE_OK || http_code < 200 || http_code >= 300) {
		pr_err("Upload part %d failed: curl=%s http=%ld\n",
		       part_num, curl_easy_strerror(res), http_code);
		free(response.memory);
		free(header_buf.memory);
		return -1;
	}

	/* Extract ETag from response headers */
	etag_hdr = strcasestr(header_buf.memory, "ETag:");
	if (etag_hdr) {
		size_t ei;
		etag_hdr += 5;
		while (*etag_hdr == ' ' || *etag_hdr == '\t')
			etag_hdr++;
		for (ei = 0; etag_hdr[ei] && etag_hdr[ei] != '\r' && etag_hdr[ei] != '\n' && ei < etag_len - 1; ei++)
			etag[ei] = etag_hdr[ei];
		etag[ei] = '\0';
	} else {
		pr_err("No ETag in upload part response headers\n");
		free(response.memory);
		free(header_buf.memory);
		return -1;
	}

	pr_debug("Uploaded part %d (%lu bytes), ETag=%s\n", part_num, length, etag);
	free(response.memory);
	free(header_buf.memory);
	return 0;
}

/* ============================================================
 * Parallel multipart upload pool (CURLM single-thread N in-flight)
 *
 * The serial object_storage_multipart_upload_part() above does one
 * synchronous PUT per part (~45 MB/s on m5.8xlarge at 8 MB parts). This
 * pool keeps N handles in flight via a single CURLM, reaching aws-s3-cp-
 * class throughput (~400 MB/s) without introducing any pthreads (which
 * previously destabilised the parasite RPC socket). The dump thread calls
 * upload_pool_submit() per part, which blocks only when max_in_flight is
 * hit; otherwise it returns immediately and the dump continues while the
 * PUT runs in the background via curl_multi.
 *
 * Memory: N × (8 MB part buffer + curl handle + headers) ≈ 33 MB for
 * N=4. No full-dump buffering — streaming is preserved.
 * ============================================================
 */

#include "../include/upload_pool.h"

/*
 * Scatter-gather read context for upload_pool. A slot's body can be
 * either one contiguous heap buffer (legacy `data`/`len` fields + the
 * shared struct UploadContext) or a vector of heap-owned chunks that
 * libcurl reads through without the pool having to memcpy them into a
 * single buffer. The compressed dump path uses the vector form so the
 * per-frame compressed output produced by the compress workers is fed
 * directly into libcurl — no intermediate part_buf memcpy.
 *
 * struct upload_sg_chunk is defined in upload_pool.h so callers can
 * build the chunk array directly; the pool takes ownership of both
 * the array and each chunk's heap data pointer.
 */

struct upload_sg_ctx {
	const struct upload_sg_chunk *chunks;
	int n_chunks;
	int cur_chunk;
	size_t cur_off;    /* offset inside chunks[cur_chunk] */
	size_t total_len;  /* sum of chunk lens */
	size_t total_read; /* bytes already fed to libcurl */
};

struct upload_pool_slot {
	CURL *handle;
	int part_num;               /* 1-based */
	void *data;                 /* contiguous body — owned by pool (xfree on reset) */
	size_t len;                 /* contiguous body length */
	struct upload_sg_chunk *sg_chunks;  /* scatter-gather body (owned); NULL if using contiguous */
	int sg_n_chunks;
	struct UploadContext ctx;        /* used when sg_chunks == NULL */
	struct upload_sg_ctx sg_ctx;     /* used when sg_chunks != NULL */
	struct MemoryStruct response;
	struct MemoryStruct header;
	struct curl_slist *headers;
	struct curl_slist *resolve_list; /* CURLOPT_RESOLVE entry pinning host->ip */
	int in_flight;              /* 1 = added to multi, 0 = free */
	char *full_url;             /* heap-allocated per request */
};

static size_t _upload_sg_read_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct upload_sg_ctx *ctx = (struct upload_sg_ctx *)userdata;
	size_t want = size * nmemb;
	size_t written = 0;

	while (want > 0 && ctx->cur_chunk < ctx->n_chunks) {
		const struct upload_sg_chunk *c = &ctx->chunks[ctx->cur_chunk];
		size_t remaining = c->len - ctx->cur_off;
		size_t n = want < remaining ? want : remaining;
		if (n == 0) {
			ctx->cur_chunk++;
			ctx->cur_off = 0;
			continue;
		}
		memcpy(ptr + written, (const char *)c->data + ctx->cur_off, n);
		ctx->cur_off += n;
		ctx->total_read += n;
		written += n;
		want -= n;
		if (ctx->cur_off >= c->len) {
			ctx->cur_chunk++;
			ctx->cur_off = 0;
		}
	}
	return written;
}

struct upload_pool {
	CURLM *multi;
	/*
	 * Event-driven pumping (libcurl socket_action model).
	 * - epfd: epoll fd we register libcurl's managed sockets against.
	 * - curl_timeout_ms: last timeout requested by libcurl's TIMERFUNCTION
	 *   callback; -1 = no active timer, 0 = fire immediately.
	 * - still_running: #handles libcurl reports as not-yet-finished (stored
	 *   here because socket_action() sets it via out-param).
	 *
	 * Replaces the earlier curl_multi_perform + curl_multi_poll loop which
	 * is O(N) per iteration. Evented scales to hundreds of concurrent
	 * PUTs with O(1) per-event cost, matching CRT's architecture.
	 */
	int epfd;
	long curl_timeout_ms;
	int still_running;

	char *key;                  /* strdup'd */
	char *upload_id;            /* strdup'd */
	int max_slots;
	struct upload_pool_slot *slots;

	/*
	 * Pre-resolved S3 edge IPs. S3 DNS returns ~8 different A records
	 * per lookup and rotates them; libcurl's per-handle DNS cache would
	 * otherwise pin every slot to whichever IP won the first resolve.
	 * We spread slots across discovered IPs to engage multiple S3 front-
	 * end partitions and raise aggregate throughput beyond per-edge
	 * bandwidth limits. Empty if resolution failed; slots then fall
	 * back to libcurl's default DNS path.
	 */
	char *host;                 /* e.g. bucket.s3.us-west-2.amazonaws.com */
	int port;                   /* 443 or 80 */
	char (*ips)[64];            /* each slot's pinned IP, len=max_slots */
	int n_ips;                  /* number of distinct IPs discovered */

	/* Ordered ETag array indexed by part_num-1. Grown as parts land. */
	char **etags;
	int etags_cap;
	int n_parts;                /* max part_num seen */
	int failed_part_num;        /* 0 = no failure */
};

/*
 * (a) TCP buffer tuning. libcurl defaults SO_SNDBUF to ~208 KB on Linux,
 * which caps throughput over long-haul TCP BDPs. Bump to 4 MB so we can
 * keep the pipe full across higher RTT (AZ↔S3 is ~1-2 ms, PUT with 8 MB
 * parts needs >1 MB window to saturate). Also bump SO_RCVBUF (less
 * important for PUT but helps headers).
 */
static int _upload_sockopt_cb(void *clientp, curl_socket_t sockfd,
			      curlsocktype purpose)
{
	int sndbuf = 4 * 1024 * 1024;
	int on = 1;
	(void)clientp;
	(void)purpose;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	/*
	 * SO_RCVBUF previously forced to 2 MB which capped per-stream
	 * cross-region throughput at 2MB/RTT (~15 MB/s @ 134ms RTT, but
	 * actually observed 0.68 MB/s due to compounding effects).
	 * Removed: kernel auto-tunes up to net.ipv4.tcp_rmem max
	 * (default 6 MB on stock Linux, far better at long RTTs).
	 *
	 * TCP_QUICKACK: disable Linux's delayed-ACK (~40 ms). Faster ACKs
	 * let the sender's cwnd ramp up sooner, which materially helps the
	 * long-RTT case where each missed ACK opportunity costs an RTT of
	 * window growth.
	 */
	setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &on, sizeof(on));
	return CURL_SOCKOPT_OK;
}

/*
 * Kernel TLS (kTLS) enablement via OpenSSL's SSL_OP_ENABLE_KTLS.
 *
 * Once the TLS handshake finishes, OpenSSL asks the kernel to attach
 * the TLS_ULP to the socket and offloads record encryption/decryption
 * there. For large-object multipart PUT (our workload) this eliminates
 * per-record AES-GCM + HMAC work in the userspace OpenSSL thread, which
 * is otherwise serialized across all concurrent slots sharing the
 * event-driven main thread.
 *
 * Requirements (all met on modern cloud hosts):
 *   - OpenSSL 3.0+ built with kTLS support
 *   - Linux kernel 4.17+ (we use 6.x)
 *   - TLS ULP kernel module available (/lib/modules/.../net/tls/tls.ko)
 *   - Cipher suite with kernel kTLS support (AES-GCM-*, ChaCha20-Poly1305)
 *
 * Falls back gracefully: if the kernel refuses the ULP attach, OpenSSL
 * keeps doing record processing in userspace — no runtime error, just
 * no speedup. Safe to enable unconditionally.
 */
static CURLcode _upload_ssl_ctx_cb(CURL *curl, void *sslctx, void *parm)
{
	(void)curl;
	(void)sslctx;
	(void)parm;
	/*
	 * SSL_OP_ENABLE_KTLS was set here previously to offload AES record
	 * encryption to the kernel. Investigated under prefetch-worker-perf:
	 * with kTLS attached, libcurl never reused the connection across
	 * sequential curl_easy_perform calls on the same easy handle (every
	 * fetch reopened TCP+TLS, observed reused=NO 100% on cross-region
	 * HTTPS while a kTLS-disabled standalone test on the same instance
	 * reused 4/5). Disabling kTLS to recover keep-alive; revisit if
	 * upload-side throughput regresses.
	 */
	return CURLE_OK;
}

/*
 * (b) Resolve the S3 endpoint host to a list of edge IPs so each slot
 * can be pinned to a different IP via CURLOPT_RESOLVE. This defeats
 * libcurl's connection reuse collapsing all slots onto the first-
 * resolved IP. S3 applies per-prefix-per-IP rate shaping, so spreading
 * across IPs lets us exceed the single-edge bandwidth cap.
 *
 * Returns 0 on success. On failure pool->n_ips stays 0 and slots fall
 * back to default DNS (correctness preserved, perf loss only).
 */
static int _pool_resolve_ips(struct upload_pool *p, const char *host, int port)
{
	struct addrinfo hints, *res = NULL, *ai;
	char port_str[8];
	char ipbuf[64];
	int rc, i, n;
	int distinct;

	p->n_ips = 0;
	if (!host || !host[0])
		return -1;

	p->host = xstrdup(host);
	p->port = port;
	p->ips = xzalloc(p->max_slots * sizeof(*p->ips));
	if (!p->host || !p->ips)
		return -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(port_str, sizeof(port_str), "%d", port);

	rc = getaddrinfo(host, port_str, &hints, &res);
	if (rc != 0 || !res) {
		pr_warn("upload_pool: getaddrinfo(%s) failed: %s\n",
			host, gai_strerror(rc));
		return -1;
	}

	/* Collect up to max_slots distinct IPv4 IPs. */
	distinct = 0;
	for (ai = res; ai && distinct < p->max_slots; ai = ai->ai_next) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)ai->ai_addr;
		if (!inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf)))
			continue;
		/* Dedup against already-collected IPs */
		for (i = 0; i < distinct; i++) {
			if (strcmp(p->ips[i], ipbuf) == 0)
				break;
		}
		if (i < distinct)
			continue;
		snprintf(p->ips[distinct], sizeof(p->ips[distinct]), "%s", ipbuf);
		distinct++;
	}
	freeaddrinfo(res);

	if (distinct == 0) {
		pr_warn("upload_pool: no IPs resolved for %s\n", host);
		return -1;
	}

	/*
	 * If we got fewer distinct IPs than slots (common — S3 typically
	 * returns 8), cycle through them. Each slot still stays pinned to
	 * one IP but multiple slots may share it; with 8 IPs and 8 slots
	 * this is 1:1 already.
	 */
	n = distinct;
	for (i = distinct; i < p->max_slots; i++) {
		char tmp[64];
		memcpy(tmp, p->ips[i % n], sizeof(tmp));
		memcpy(p->ips[i], tmp, sizeof(tmp));
	}
	p->n_ips = distinct;
	pr_info("upload_pool: resolved %d distinct IPs for %s (slots=%d)\n",
		distinct, host, p->max_slots);
	return 0;
}

/* Grow etag array to at least `need` entries (values init to NULL). */
static int _etags_reserve(struct upload_pool *p, int need)
{
	char **nt;
	int cap;
	if (need <= p->etags_cap)
		return 0;
	cap = p->etags_cap ? p->etags_cap : 32;
	while (cap < need)
		cap *= 2;
	nt = xrealloc(p->etags, cap * sizeof(*nt));
	if (!nt)
		return -1;
	memset(nt + p->etags_cap, 0, (cap - p->etags_cap) * sizeof(*nt));
	p->etags = nt;
	p->etags_cap = cap;
	return 0;
}

/* Extract "ETag: ..." value into out. Returns 0 on success. */
static int _parse_etag_header(const char *hdr_buf, char *out, size_t out_len)
{
	const char *p = strcasestr(hdr_buf, "ETag:");
	size_t i;
	if (!p)
		return -1;
	p += 5;
	while (*p == ' ' || *p == '\t')
		p++;
	for (i = 0; p[i] && p[i] != '\r' && p[i] != '\n' && i < out_len - 1; i++)
		out[i] = p[i];
	out[i] = '\0';
	return 0;
}

/* Release slot resources (headers, buffers, data, url). Does not touch
 * the curl handle itself (reused across calls). */
static void _slot_reset(struct upload_pool_slot *s)
{
	if (s->resolve_list) {
		curl_slist_free_all(s->resolve_list);
		s->resolve_list = NULL;
	}
	if (s->headers) {
		curl_slist_free_all(s->headers);
		s->headers = NULL;
	}
	free(s->response.memory); s->response.memory = NULL;
	s->response.size = 0; s->response.capacity = 0;
	free(s->header.memory); s->header.memory = NULL;
	s->header.size = 0; s->header.capacity = 0;
	free(s->full_url); s->full_url = NULL;
	if (s->data) {
		free(s->data);
		s->data = NULL;
	}
	s->len = 0;
	if (s->sg_chunks) {
		int i;
		for (i = 0; i < s->sg_n_chunks; i++) {
			if (s->sg_chunks[i].data)
				free(s->sg_chunks[i].data);
		}
		free(s->sg_chunks);
		s->sg_chunks = NULL;
		s->sg_n_chunks = 0;
	}
	s->part_num = 0;
	s->in_flight = 0;
}

/*
 * Common handle setup — either feed a contiguous `data` buffer (chunks==NULL)
 * or a scatter-gather list of chunks (chunks != NULL, total_len is the sum of
 * chunk lens). For the SG path the slot takes ownership of the chunks array
 * AND each chunk's `data` pointer (xfree()d via _slot_reset). For the
 * contiguous path, slot->data = data (xfree()d via _slot_reset).
 */
static int _slot_prepare_put_common(struct upload_pool *p,
				    struct upload_pool_slot *s,
				    int part_num,
				    void *data, size_t len,
				    struct upload_sg_chunk *chunks,
				    int n_chunks, size_t total_len)
{
	struct object_url_info url_info;
	char query_string[512];
	char content_sha256[65];
	char *url;
	size_t body_len;

	if (opts.express_one_zone) {
		if (ensure_valid_session() != 0)
			return -1;
	}
	if (_construct_object_url(p->key, &url_info) != 0)
		return -1;

	url = xmalloc(2400);
	if (!url)
		return -1;
	snprintf(url, 2400, "%s?partNumber=%d&uploadId=%s",
		 url_info.url, part_num, p->upload_id);
	snprintf(query_string, sizeof(query_string),
		 "partNumber=%d&uploadId=%s", part_num, p->upload_id);

	if (chunks) {
		/*
		 * UNSIGNED-PAYLOAD default makes SigV4 independent of body
		 * bytes; if opts.sign_payload is on, we'd need to SHA256
		 * across the entire chunk list (linear scan) to reconstruct
		 * the canonical hash. We emit a warning and fall back to
		 * UNSIGNED for this single request — callers doing scatter-
		 * gather are in the performance path and explicit sign is
		 * incompatible with the zero-memcpy goal.
		 */
		if (opts.sign_payload)
			pr_warn("sign-payload + scatter-gather: forcing UNSIGNED-PAYLOAD for part %d\n",
				part_num);
		memcpy(content_sha256, "UNSIGNED-PAYLOAD", 17);
		body_len = total_len;
	} else {
		_payload_hash(data, len, content_sha256);
		body_len = len;
	}

	s->part_num = part_num;
	if (chunks) {
		s->data = NULL;
		s->len = 0;
		s->sg_chunks = chunks;
		s->sg_n_chunks = n_chunks;
		s->sg_ctx.chunks = chunks;
		s->sg_ctx.n_chunks = n_chunks;
		s->sg_ctx.cur_chunk = 0;
		s->sg_ctx.cur_off = 0;
		s->sg_ctx.total_len = total_len;
		s->sg_ctx.total_read = 0;
	} else {
		s->data = data;
		s->len = len;
		s->sg_chunks = NULL;
		s->sg_n_chunks = 0;
		s->ctx.data = data;
		s->ctx.size = len;
		s->ctx.offset = 0;
	}

	s->response.memory = xmalloc(1);
	s->response.size = 0;
	s->response.capacity = 0;
	s->header.memory = xmalloc(1);
	s->header.size = 0;
	s->header.capacity = 0;
	s->full_url = url;

	if (!s->handle) {
		s->handle = curl_easy_init();
		if (!s->handle)
			goto fail;
	} else {
		curl_easy_reset(s->handle);
	}

	curl_easy_setopt(s->handle, CURLOPT_URL, s->full_url);
	curl_easy_setopt(s->handle, CURLOPT_UPLOAD, 1L);
	if (chunks) {
		curl_easy_setopt(s->handle, CURLOPT_READFUNCTION, _upload_sg_read_callback);
		curl_easy_setopt(s->handle, CURLOPT_READDATA, &s->sg_ctx);
	} else {
		curl_easy_setopt(s->handle, CURLOPT_READFUNCTION, _upload_read_callback);
		curl_easy_setopt(s->handle, CURLOPT_READDATA, &s->ctx);
	}
	curl_easy_setopt(s->handle, CURLOPT_INFILESIZE_LARGE, (curl_off_t)body_len);
	curl_easy_setopt(s->handle, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(s->handle, CURLOPT_WRITEDATA, &s->response);
	curl_easy_setopt(s->handle, CURLOPT_HEADERFUNCTION, write_callback);
	curl_easy_setopt(s->handle, CURLOPT_HEADERDATA, &s->header);
	curl_easy_setopt(s->handle, CURLOPT_TCP_KEEPALIVE, 1L);
	curl_easy_setopt(s->handle, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(s->handle, CURLOPT_PRIVATE, s);

	/*
	 * Larger upload read buffer: default 64 KB causes 128 read
	 * callbacks per 8 MB part. 1 MB drops this to 8 callbacks and
	 * lets libcurl pipe bigger chunks into the kernel socket buffer
	 * in one go. AWS CRT uses ~1 MB for the same reason.
	 */
	curl_easy_setopt(s->handle, CURLOPT_UPLOAD_BUFFERSIZE,
			 1024L * 1024L);

	/*
	 * TCP_NODELAY: disable Nagle. libcurl turns it on by default since
	 * 7.50 but being explicit guards against build-time defaults.
	 */
	curl_easy_setopt(s->handle, CURLOPT_TCP_NODELAY, 1L);

	/* (a) Bigger TCP buffers for long-haul EC2↔S3 BDP. */
	curl_easy_setopt(s->handle, CURLOPT_SOCKOPTFUNCTION, _upload_sockopt_cb);
	curl_easy_setopt(s->handle, CURLOPT_SOCKOPTDATA, NULL);

	/* Enable Kernel TLS for AES-GCM offload of record encryption. */
	curl_easy_setopt(s->handle, CURLOPT_SSL_CTX_FUNCTION,
			 _upload_ssl_ctx_cb);

	/*
	 * (b) Pin this slot to its assigned S3 edge IP so the pool spreads
	 * load across multiple edges. Without this, libcurl's per-handle
	 * DNS cache locks each handle to whichever IP it first resolved,
	 * typically the same one across all handles since glibc's resolver
	 * isn't guaranteed to rotate.
	 */
	if (p->n_ips > 0 && p->host) {
		int idx = (int)(s - p->slots);
		char resolve_entry[192];
		if (idx >= 0 && idx < p->max_slots && p->ips[idx][0]) {
			snprintf(resolve_entry, sizeof(resolve_entry),
				 "%s:%d:%s", p->host, p->port, p->ips[idx]);
			s->resolve_list = curl_slist_append(NULL, resolve_entry);
			if (s->resolve_list)
				curl_easy_setopt(s->handle, CURLOPT_RESOLVE,
						 s->resolve_list);
		}
	}

	if (_build_auth_headers("PUT", url_info.auth_host, url_info.canonical_uri,
				query_string, content_sha256, NULL,
				(long)body_len,
				&s->headers) != 0)
		goto fail;
	if (s->headers)
		curl_easy_setopt(s->handle, CURLOPT_HTTPHEADER, s->headers);

	return 0;
fail:
	_slot_reset(s);
	return -1;
}

/* Contiguous-body variant (legacy path). */
static int _slot_prepare_put(struct upload_pool *p, struct upload_pool_slot *s,
			     int part_num, void *data, size_t len)
{
	return _slot_prepare_put_common(p, s, part_num, data, len, NULL, 0, 0);
}

/* Scatter-gather body variant. Slot takes ownership of chunks + chunks[i].data. */
static int _slot_prepare_put_sg(struct upload_pool *p, struct upload_pool_slot *s,
				int part_num,
				struct upload_sg_chunk *chunks,
				int n_chunks, size_t total_len)
{
	return _slot_prepare_put_common(p, s, part_num, NULL, 0,
					chunks, n_chunks, total_len);
}

/* Process any completed transfers. Returns number of slots freed. */
static int _pool_drain_completions(struct upload_pool *p)
{
	int msgs_left = 0;
	int freed = 0;
	CURLMsg *msg;
	struct upload_pool_slot *s;
	long http_code;
	CURLcode res;
	char etag[256];

	while ((msg = curl_multi_info_read(p->multi, &msgs_left)) != NULL) {
		if (msg->msg != CURLMSG_DONE)
			continue;

		s = NULL;
		curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &s);
		if (!s) {
			pr_err("upload_pool: CURLINFO_PRIVATE unset on complete\n");
			continue;
		}

		http_code = 0;
		curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &http_code);
		res = msg->data.result;

		curl_multi_remove_handle(p->multi, msg->easy_handle);

		if (res != CURLE_OK || http_code < 200 || http_code >= 300) {
			pr_err("upload_pool: part %d failed curl=%s http=%ld\n",
			       s->part_num, curl_easy_strerror(res), http_code);
			p->failed_part_num = s->part_num;
		} else if (_parse_etag_header(s->header.memory, etag, sizeof(etag)) != 0) {
			pr_err("upload_pool: part %d missing ETag\n", s->part_num);
			p->failed_part_num = s->part_num;
		} else if (_etags_reserve(p, s->part_num) != 0) {
			p->failed_part_num = s->part_num;
		} else {
			free(p->etags[s->part_num - 1]);
			p->etags[s->part_num - 1] = xstrdup(etag);
			if (s->part_num > p->n_parts)
				p->n_parts = s->part_num;
		}

		_slot_reset(s);
		freed++;
	}
	return freed;
}

/* -------- Evented pumping (libcurl socket_action model) -------- */

/*
 * libcurl calls this whenever the set of sockets it cares about
 * changes. We mirror that into our epoll fd. sockp (the per-socket
 * user pointer settable via curl_multi_assign) is used as a tri-state
 * "tracked/untracked" marker so we know when to ADD vs MOD vs DEL.
 */
static int _pool_socket_cb(CURL *easy, curl_socket_t s, int what,
			   void *userp, void *sockp)
{
	struct upload_pool *p = userp;
	struct epoll_event ev;
	int op;
	(void)easy;

	memset(&ev, 0, sizeof(ev));
	ev.data.fd = s;

	if (what == CURL_POLL_REMOVE) {
		if (sockp) {
			epoll_ctl(p->epfd, EPOLL_CTL_DEL, s, NULL);
			curl_multi_assign(p->multi, s, NULL);
		}
		return 0;
	}

	if (what == CURL_POLL_IN)     ev.events = EPOLLIN;
	if (what == CURL_POLL_OUT)    ev.events = EPOLLOUT;
	if (what == CURL_POLL_INOUT)  ev.events = EPOLLIN | EPOLLOUT;

	op = sockp ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
	if (epoll_ctl(p->epfd, op, s, &ev) < 0 && errno == EEXIST)
		epoll_ctl(p->epfd, EPOLL_CTL_MOD, s, &ev);
	if (!sockp)
		curl_multi_assign(p->multi, s, p);  /* non-NULL = tracked */
	return 0;
}

static int _pool_timer_cb(CURLM *multi, long timeout_ms, void *userp)
{
	struct upload_pool *p = userp;
	(void)multi;
	p->curl_timeout_ms = timeout_ms;
	return 0;
}

/*
 * One epoll_wait pass + corresponding curl_multi_socket_action calls.
 * max_wait_ms is bounded below by curl's timer request and above by the
 * caller's patience. Returns the running-handle count (stored into
 * pool->still_running as well) or -1 on fatal epoll error.
 */
static int _pool_pump_events(struct upload_pool *p, int max_wait_ms)
{
	struct epoll_event events[64];
	int nevents;
	int i;
	long wait_ms;

	/*
	 * Pick the shorter of curl's requested timer and the caller's max.
	 * -1 in curl_timeout_ms means "no timer" → respect caller's cap.
	 * 0 means "fire now" → don't block.
	 */
	wait_ms = (p->curl_timeout_ms < 0) ? max_wait_ms
		: (p->curl_timeout_ms < max_wait_ms ? p->curl_timeout_ms
						    : max_wait_ms);
	if (wait_ms < 0)
		wait_ms = 0;

	nevents = epoll_wait(p->epfd, events, 64, (int)wait_ms);
	if (nevents < 0) {
		if (errno == EINTR)
			return p->still_running;
		pr_perror("upload_pool: epoll_wait");
		return -1;
	}

	if (nevents == 0) {
		/* Timer expired — let libcurl advance timer-driven state. */
		curl_multi_socket_action(p->multi, CURL_SOCKET_TIMEOUT, 0,
					 &p->still_running);
	} else {
		for (i = 0; i < nevents; i++) {
			int evmask = 0;
			if (events[i].events & EPOLLIN)
				evmask |= CURL_CSELECT_IN;
			if (events[i].events & EPOLLOUT)
				evmask |= CURL_CSELECT_OUT;
			if (events[i].events & (EPOLLERR | EPOLLHUP))
				evmask |= CURL_CSELECT_ERR;
			curl_multi_socket_action(p->multi, events[i].data.fd,
						 evmask, &p->still_running);
		}
	}

	_pool_drain_completions(p);
	return p->still_running;
}

/*
 * Pump events until at least one upload slot is free. Replaces the old
 * curl_multi_perform + curl_multi_poll loop with an evented variant
 * backed by epoll. O(1) per-event cost vs O(N) per iteration before.
 */
static int _pool_wait_any_slot(struct upload_pool *p)
{
	int found_free;
	int i;

	for (;;) {
		found_free = 0;
		for (i = 0; i < p->max_slots; i++) {
			if (!p->slots[i].in_flight) {
				found_free = 1;
				break;
			}
		}
		if (found_free)
			return 0;

		if (_pool_pump_events(p, 200) < 0)
			return -1;
		if (p->failed_part_num)
			return -1;
	}
}

struct upload_pool *upload_pool_create(const char *object_key,
				       const char *upload_id,
				       int max_in_flight)
{
	struct upload_pool *p;

	if (max_in_flight < 1)
		max_in_flight = 1;
	/*
	 * Evented backend supports up to ~255 connections (same as CRT's
	 * default cap). Raising our legacy cap from 32 to 256 now that
	 * curl_multi_perform's O(N) scan is replaced by epoll-driven
	 * socket_action (O(1) per ready fd).
	 */
	if (max_in_flight > 256)
		max_in_flight = 256;

	p = xzalloc(sizeof(*p));
	if (!p)
		return NULL;

	p->epfd = epoll_create1(EPOLL_CLOEXEC);
	if (p->epfd < 0) {
		pr_perror("upload_pool: epoll_create1");
		free(p);
		return NULL;
	}
	p->curl_timeout_ms = -1;
	p->still_running = 0;

	p->multi = curl_multi_init();
	if (!p->multi) {
		close(p->epfd);
		free(p);
		return NULL;
	}

	/* Register evented callbacks. Must happen before first add_handle. */
	curl_multi_setopt(p->multi, CURLMOPT_SOCKETFUNCTION, _pool_socket_cb);
	curl_multi_setopt(p->multi, CURLMOPT_SOCKETDATA, p);
	curl_multi_setopt(p->multi, CURLMOPT_TIMERFUNCTION, _pool_timer_cb);
	curl_multi_setopt(p->multi, CURLMOPT_TIMERDATA, p);

	p->key = xstrdup(object_key);
	p->upload_id = xstrdup(upload_id);
	p->max_slots = max_in_flight;
	p->slots = xzalloc(max_in_flight * sizeof(*p->slots));
	if (!p->key || !p->upload_id || !p->slots) {
		curl_multi_cleanup(p->multi);
		close(p->epfd);
		free(p->key);
		free(p->upload_id);
		free(p->slots);
		free(p);
		return NULL;
	}

	/*
	 * (b) Pre-resolve S3 endpoint IPs so slots can pin to different
	 * edges. Compute the auth_host the same way a per-request URL would
	 * (virtual-hosted vs path-style, express_one_zone). Failure is
	 * non-fatal; slots fall back to default DNS with only (a) gains.
	 */
	{
		struct object_url_info tmp;
		const char *scheme_end;
		int port = 443;
		/* Re-construct URL info for this key just to get auth_host + scheme. */
		if (_construct_object_url(object_key, &tmp) == 0) {
			/* Scheme: check full URL for http:// vs https:// */
			scheme_end = tmp.url;
			if (strncmp(scheme_end, "http://", 7) == 0)
				port = 80;
			else
				port = 443;
			(void)_pool_resolve_ips(p, tmp.auth_host, port);
		}
	}

	pr_info("upload_pool: created key=%s max_in_flight=%d\n",
		object_key, max_in_flight);
	return p;
}

int upload_pool_submit(struct upload_pool *pool, int part_num,
		       void *data, size_t len)
{
	struct upload_pool_slot *s = NULL;
	int i;

	if (!pool || !data || len == 0 || part_num < 1)
		return -1;
	if (pool->failed_part_num)
		return -1;

	/* Drive any pending completions non-blockingly before picking a slot. */
	if (_pool_pump_events(pool, 0) < 0)
		return -1;
	if (pool->failed_part_num)
		return -1;

	/* Find a free slot; if all busy, wait. */
	for (i = 0; i < pool->max_slots; i++) {
		if (!pool->slots[i].in_flight) {
			s = &pool->slots[i];
			break;
		}
	}
	if (!s) {
		if (_pool_wait_any_slot(pool) != 0)
			return -1;
		for (i = 0; i < pool->max_slots; i++) {
			if (!pool->slots[i].in_flight) {
				s = &pool->slots[i];
				break;
			}
		}
		if (!s)
			return -1;
	}

	if (_slot_prepare_put(pool, s, part_num, data, len) != 0)
		return -1;

	if (curl_multi_add_handle(pool->multi, s->handle) != CURLM_OK) {
		_slot_reset(s);
		return -1;
	}
	s->in_flight = 1;
	/* Kick the event loop so the new handle starts transferring ASAP. */
	curl_multi_socket_action(pool->multi, CURL_SOCKET_TIMEOUT, 0,
				 &pool->still_running);
	return 0;
}

int upload_pool_submit_sg(struct upload_pool *pool, int part_num,
			  struct upload_sg_chunk *chunks, int n_chunks,
			  size_t total_len)
{
	struct upload_pool_slot *s = NULL;
	int i;

	if (!pool || !chunks || n_chunks <= 0 || total_len == 0 || part_num < 1) {
		/* Free chunks on invalid args so caller's ownership-transfer
		 * semantics are honored unconditionally. */
		if (chunks) {
			for (i = 0; i < n_chunks; i++) {
				if (chunks[i].data)
					free(chunks[i].data);
			}
			free(chunks);
		}
		return -1;
	}
	if (pool->failed_part_num) {
		for (i = 0; i < n_chunks; i++) {
			if (chunks[i].data)
				free(chunks[i].data);
		}
		free(chunks);
		return -1;
	}

	if (_pool_pump_events(pool, 0) < 0 || pool->failed_part_num) {
		for (i = 0; i < n_chunks; i++) {
			if (chunks[i].data)
				free(chunks[i].data);
		}
		free(chunks);
		return -1;
	}

	for (i = 0; i < pool->max_slots; i++) {
		if (!pool->slots[i].in_flight) {
			s = &pool->slots[i];
			break;
		}
	}
	if (!s) {
		if (_pool_wait_any_slot(pool) != 0) {
			for (i = 0; i < n_chunks; i++) {
				if (chunks[i].data)
					free(chunks[i].data);
			}
			free(chunks);
			return -1;
		}
		for (i = 0; i < pool->max_slots; i++) {
			if (!pool->slots[i].in_flight) {
				s = &pool->slots[i];
				break;
			}
		}
		if (!s) {
			for (i = 0; i < n_chunks; i++) {
				if (chunks[i].data)
					free(chunks[i].data);
			}
			free(chunks);
			return -1;
		}
	}

	if (_slot_prepare_put_sg(pool, s, part_num, chunks, n_chunks,
				 total_len) != 0)
		return -1;  /* _slot_reset inside common path frees chunks */

	if (curl_multi_add_handle(pool->multi, s->handle) != CURLM_OK) {
		_slot_reset(s);
		return -1;
	}
	s->in_flight = 1;
	curl_multi_socket_action(pool->multi, CURL_SOCKET_TIMEOUT, 0,
				 &pool->still_running);
	return 0;
}

int upload_pool_wait(struct upload_pool *pool, int *failed_part_num)
{
	int i;

	if (!pool)
		return -1;

	/* Kick the event loop in case nothing is pumping (e.g., submit
	 * was followed immediately by wait with no intervening I/O). */
	curl_multi_socket_action(pool->multi, CURL_SOCKET_TIMEOUT, 0,
				 &pool->still_running);
	_pool_drain_completions(pool);

	while (pool->still_running > 0 && !pool->failed_part_num) {
		if (_pool_pump_events(pool, 500) < 0)
			break;
	}

	/* Defensive: ensure every slot cleaned. */
	for (i = 0; i < pool->max_slots; i++)
		if (pool->slots[i].in_flight)
			_slot_reset(&pool->slots[i]);

	if (pool->failed_part_num) {
		if (failed_part_num)
			*failed_part_num = pool->failed_part_num;
		return -1;
	}
	return 0;
}

int upload_pool_get_etags(struct upload_pool *pool,
			  const char ***etags_out, int *n_parts_out)
{
	if (!pool || !etags_out || !n_parts_out)
		return -1;
	*etags_out = (const char **)pool->etags;
	*n_parts_out = pool->n_parts;
	return 0;
}

void upload_pool_destroy(struct upload_pool *pool)
{
	int i;
	if (!pool)
		return;
	for (i = 0; i < pool->max_slots; i++) {
		if (pool->slots[i].handle)
			curl_easy_cleanup(pool->slots[i].handle);
		_slot_reset(&pool->slots[i]);
	}
	for (i = 0; i < pool->etags_cap; i++)
		free(pool->etags[i]);
	free(pool->etags);
	free(pool->slots);
	curl_multi_cleanup(pool->multi);
	if (pool->epfd >= 0)
		close(pool->epfd);
	free(pool->key);
	free(pool->upload_id);
	free(pool->host);
	free(pool->ips);
	free(pool);
}

int object_storage_multipart_complete(const char *object_key, const char *upload_id,
				      int n_parts, const char **etags)
{
	struct object_url_info url_info;
	struct UploadContext upload_ctx;
	struct MemoryStruct response;
	CURL *curl_handle;
	CURLcode res;
	long http_code = 0;
	struct curl_slist *headers = NULL;
	char full_url[2400];
	char query_string[512];
	char content_sha256[65];
	char *xml_body;
	size_t xml_len;
	size_t xml_pos;
	int i;

	if (opts.express_one_zone) {
		if (ensure_valid_session() != 0)
			return -1;
	}

	if (_construct_object_url(object_key, &url_info) != 0)
		return -1;

	snprintf(full_url, sizeof(full_url), "%s?uploadId=%s", url_info.url, upload_id);
	snprintf(query_string, sizeof(query_string), "uploadId=%s", upload_id);

	/* Build XML body: <CompleteMultipartUpload><Part>...</Part>...</> */
	xml_len = 128 + n_parts * 256;
	xml_body = malloc(xml_len);
	if (!xml_body)
		return -1;

	xml_pos = 0;
	xml_pos += snprintf(xml_body + xml_pos, xml_len - xml_pos,
			    "<CompleteMultipartUpload>");
	for (i = 0; i < n_parts; i++) {
		xml_pos += snprintf(xml_body + xml_pos, xml_len - xml_pos,
				    "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
				    i + 1, etags[i]);
	}
	xml_pos += snprintf(xml_body + xml_pos, xml_len - xml_pos,
			    "</CompleteMultipartUpload>");
	xml_len = xml_pos;

	_payload_hash(xml_body, xml_len, content_sha256);

	curl_handle = _get_curl_handle();
	if (!curl_handle) {
		free(xml_body);
		return -1;
	}

	upload_ctx.data = xml_body;
	upload_ctx.size = xml_len;
	upload_ctx.offset = 0;

	response.memory = malloc(1);
	response.size = 0;
	response.capacity = 0;

	curl_easy_setopt(curl_handle, CURLOPT_URL, full_url);
	curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_READFUNCTION, _upload_read_callback);
	curl_easy_setopt(curl_handle, CURLOPT_READDATA, &upload_ctx);
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)xml_len);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);

	if (_build_auth_headers("POST", url_info.auth_host, url_info.canonical_uri,
			       query_string, content_sha256, NULL, (long)xml_len, &headers) != 0) {
		free(xml_body);
		free(response.memory);
		return -1;
	}
	/* Content-Type for the completion XML */
	headers = curl_slist_append(headers, "Content-Type: application/xml");
	curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

	res = curl_easy_perform(curl_handle);
	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

	if (headers)
		curl_slist_free_all(headers);
	free(xml_body);

	if (res != CURLE_OK || http_code < 200 || http_code >= 300) {
		pr_err("Multipart complete failed: curl=%s http=%ld body=%.*s\n",
		       curl_easy_strerror(res), http_code, (int)response.size, response.memory);
		free(response.memory);
		return -1;
	}

	pr_info("Multipart upload completed: %s (%d parts)\n", object_key, n_parts);
	free(response.memory);
	return 0;
}

int object_storage_multipart_abort(const char *object_key, const char *upload_id)
{
	struct object_url_info url_info;
	struct MemoryStruct response;
	CURL *curl_handle;
	CURLcode res;
	long http_code = 0;
	struct curl_slist *headers = NULL;
	char full_url[2400];
	char query_string[512];

	if (opts.express_one_zone) {
		if (ensure_valid_session() != 0)
			return -1;
	}

	if (_construct_object_url(object_key, &url_info) != 0)
		return -1;

	snprintf(full_url, sizeof(full_url), "%s?uploadId=%s", url_info.url, upload_id);
	snprintf(query_string, sizeof(query_string), "uploadId=%s", upload_id);

	curl_handle = _get_curl_handle();
	if (!curl_handle)
		return -1;

	response.memory = malloc(1);
	response.size = 0;
	response.capacity = 0;

	curl_easy_setopt(curl_handle, CURLOPT_URL, full_url);
	curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "DELETE");
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);

	if (_build_auth_headers("DELETE", url_info.auth_host, url_info.canonical_uri,
			       query_string, EMPTY_PAYLOAD_HASH, NULL, -1, &headers) != 0) {
		free(response.memory);
		return -1;
	}
	if (headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

	res = curl_easy_perform(curl_handle);
	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

	if (headers)
		curl_slist_free_all(headers);
	free(response.memory);

	if (res != CURLE_OK) {
		pr_warn("Multipart abort failed: %s\n", curl_easy_strerror(res));
		return -1;
	}

	pr_info("Multipart upload aborted: %s\n", object_key);
	return 0;
}

/*
 * =================================================================================
 * GET Object — fetch entire file (for metadata files with unknown size)
 * =================================================================================
 */

static int do_get_object(const char *object_key, void **out_data, unsigned long *out_length, bool bypass_cache)
{
	struct object_url_info url_info;
	struct MemoryStruct chunk;
	CURL *curl_handle;
	CURLcode res;
	long http_code = 0;
	struct curl_slist *headers = NULL;
	const void *cache_data = NULL;
	size_t cache_len = 0;

	if (!object_key || !out_data || !out_length) {
		pr_err("get_object: NULL parameter\n");
		return -1;
	}

	*out_data = NULL;
	*out_length = 0;

	/*
	 * Short-circuit via the metadata prefetch cache. obstor_prefetch_init
	 * LISTed the active prefix (and its parent chain) and fetched every
	 * non-pages key in parallel, so the cache mirrors the set of objects
	 * that exist on S3 under this prefix. A miss on an authoritative cache
	 * means the object truly doesn't exist — no point burning a 134ms
	 * cross-region 404. Most visibly this kills the per-page_read GET of
	 * "parent-prefix" on full dumps (called from open_page_xfer,
	 * try_open_parent_at, get_parent_inventory).
	 *
	 * bypass_cache=true skips the authoritative-miss short-circuit for
	 * objects that may be uploaded after CRIU's manifest is sealed (e.g.
	 * hot-iovs.json appended by the workload runner post-dump). The
	 * cache-hit fast path is still consulted — if it's cached, we use it.
	 */
	if (obstor_prefetch_lookup(object_key, &cache_data, &cache_len) == 0) {
		void *copy = malloc(cache_len);
		if (!copy)
			return -1;
		memcpy(copy, cache_data, cache_len);
		*out_data = copy;
		*out_length = cache_len;
		pr_debug("GET %s: %lu bytes (prefetch cache hit)\n", object_key,
			 (unsigned long)cache_len);
		return 0;
	}
	if (!bypass_cache && obstor_prefetch_is_authoritative()) {
		pr_debug("GET %s: skipped (prefetch cache authoritative miss)\n",
			 object_key);
		return -ENOENT;
	}

	if (opts.express_one_zone) {
		if (ensure_valid_session() != 0)
			return -1;
	}

	if (_construct_object_url(object_key, &url_info) != 0)
		return -1;

	curl_handle = _get_curl_handle();
	if (!curl_handle)
		return -1;

	chunk.memory = malloc(1);
	chunk.size = 0;
	chunk.capacity = 0;

	curl_easy_setopt(curl_handle, CURLOPT_URL, url_info.url);
	curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &chunk);

	/* SigV4: GET without Range header */
	if (_build_auth_headers("GET", url_info.auth_host, url_info.canonical_uri,
			       NULL, EMPTY_PAYLOAD_HASH, NULL, -1, &headers) != 0) {
		free(chunk.memory);
		return -1;
	}
	if (headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

	pr_debug("GET %s (full object)\n", url_info.url);

	res = curl_easy_perform(curl_handle);
	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

	if (headers)
		curl_slist_free_all(headers);

	if (res != CURLE_OK) {
		pr_err("GET %s failed: %s\n", object_key, curl_easy_strerror(res));
		free(chunk.memory);
		return -1;
	}

	if (http_code == 404) {
		pr_debug("GET %s: not found (HTTP 404)\n", object_key);
		free(chunk.memory);
		return -ENOENT;
	}

	if (http_code < 200 || http_code >= 300) {
		pr_err("GET %s failed with HTTP %ld\n", object_key, http_code);
		free(chunk.memory);
		return -1;
	}

	pr_debug("GET %s: %lu bytes (HTTP %ld)\n", object_key, (unsigned long)chunk.size, http_code);
	*out_data = chunk.memory;
	*out_length = chunk.size;
	return 0;
}

int object_storage_get_object(const char *object_key, void **out_data, unsigned long *out_length)
{
	return do_get_object(object_key, out_data, out_length, false);
}

int object_storage_get_object_force(const char *object_key, void **out_data, unsigned long *out_length)
{
	return do_get_object(object_key, out_data, out_length, true);
}

/*
 * =================================================================================
 * Manifest helpers — replace post-dump LIST round-trip on restore.
 *
 * Format (manifest_v1, plain text, "\n" line endings):
 *   manifest_v1
 *   <key_relative_to_prefix>\t<size_bytes>
 *   ...
 * =================================================================================
 */
#define MANIFEST_FILE_NAME	"manifest.txt"
#define MANIFEST_HEADER		"manifest_v1\n"

/*
 * Metadata bundle — concatenation of every small PUT into a single
 * <prefix>/metadata.tar so the restore-side prefetch needs one GET, not
 * 30+. Format:
 *   "OBSTOR_BUNDLE_v1\n"
 *   per entry:  "<key>\t<size>\n" then <size> bytes of raw body.
 */
#define BUNDLE_FILE_NAME	"metadata.tar"
#define BUNDLE_HEADER		"OBSTOR_BUNDLE_v1\n"
#define BUNDLE_MAX_TOTAL_BYTES	(64UL << 20)	/* fail-safe cap */
#define BUNDLE_MAX_ENTRY_BYTES	(1UL << 20)	/* skip files >= 1 MB */

struct bundle_entry {
	char *key;
	void *data;
	unsigned long length;
	struct bundle_entry *next;
};

static struct bundle_entry *g_bundle_head;
static unsigned long g_bundle_total_bytes;
static pthread_mutex_t g_bundle_lock = PTHREAD_MUTEX_INITIALIZER;

static int _bundle_accum_add(const char *key, const void *data, unsigned long length)
{
	struct bundle_entry *e;

	if (!key || !data || length == 0)
		return 0;
	if (length > BUNDLE_MAX_ENTRY_BYTES)
		return 0;

	pthread_mutex_lock(&g_bundle_lock);
	if (g_bundle_total_bytes + length > BUNDLE_MAX_TOTAL_BYTES) {
		pthread_mutex_unlock(&g_bundle_lock);
		pr_debug("bundle: skipping '%s' (%lu B), would exceed %lu MB cap\n",
			 key, length, BUNDLE_MAX_TOTAL_BYTES >> 20);
		return 0;
	}
	pthread_mutex_unlock(&g_bundle_lock);

	e = malloc(sizeof(*e));
	if (!e)
		return -1;
	e->key = strdup(key);
	if (!e->key) {
		free(e);
		return -1;
	}
	e->data = malloc(length);
	if (!e->data) {
		free(e->key);
		free(e);
		return -1;
	}
	memcpy(e->data, data, length);
	e->length = length;

	pthread_mutex_lock(&g_bundle_lock);
	e->next = g_bundle_head;
	g_bundle_head = e;
	g_bundle_total_bytes += length;
	pthread_mutex_unlock(&g_bundle_lock);

	return 0;
}

int object_storage_write_manifest(void)
{
	char **keys = NULL;
	unsigned long *sizes = NULL;
	size_t nkeys = 0, i;
	const char *prefix;
	char *buf = NULL;
	size_t cap = 0, used = 0;
	int rc = -1;

	if (!opts.enable_object_storage)
		return 0;

	prefix = opts.object_storage_object_prefix ? opts.object_storage_object_prefix : "";

	/*
	 * One LIST at end-of-dump to enumerate everything we just uploaded.
	 * Acceptable cost on the dump side — dump latency is not gated on
	 * round trips the way restore latency is, and avoiding a tracker for
	 * "files I uploaded" keeps the change local to this helper.
	 */
	if (object_storage_list_objects(prefix, &keys, &sizes, &nkeys) != 0) {
		pr_warn("manifest: LIST '%s' failed; skipping manifest\n", prefix);
		return -1;
	}

	cap = 1024 + nkeys * 192;
	buf = malloc(cap);
	if (!buf)
		goto out;

	used = snprintf(buf, cap, "%s", MANIFEST_HEADER);

	for (i = 0; i < nkeys; i++) {
		const char *full_key = keys[i];
		const char *rel = full_key;
		size_t prefix_len = strlen(prefix);
		size_t base_name_len;
		int n;

		/* Normalize: store key relative to the prefix to keep manifest
		 * portable across moves of the prefix root. */
		if (prefix_len > 0 && strncmp(full_key, prefix, prefix_len) == 0) {
			rel = full_key + prefix_len;
			while (*rel == '/')
				rel++;
		}
		base_name_len = strlen(rel);
		if (base_name_len == 0)
			continue;
		/* Self-skip: never list the manifest in itself. */
		if (strcmp(rel, MANIFEST_FILE_NAME) == 0)
			continue;

		if (used + base_name_len + 32 >= cap) {
			size_t new_cap = cap * 2 + base_name_len + 256;
			char *bigger = realloc(buf, new_cap);
			if (!bigger)
				goto out;
			buf = bigger;
			cap = new_cap;
		}
		n = snprintf(buf + used, cap - used, "%s\t%lu\n", rel, sizes[i]);
		if (n <= 0)
			goto out;
		used += (size_t)n;
	}

	if (object_storage_put_object(MANIFEST_FILE_NAME, buf, used) != 0) {
		pr_warn("manifest: PUT '%s/%s' failed\n", prefix, MANIFEST_FILE_NAME);
		goto out;
	}

	pr_info("manifest: wrote '%s/%s' (%zu bytes, %zu entries)\n",
		prefix, MANIFEST_FILE_NAME, used, nkeys);
	rc = 0;

out:
	free(buf);
	for (i = 0; i < nkeys; i++)
		xfree(keys[i]);
	free(keys);
	free(sizes);
	return rc;
}

int object_storage_read_manifest(const char *key_prefix, char ***out_keys,
				 unsigned long **out_sizes, size_t *out_n)
{
	void *raw = NULL;
	unsigned long raw_len = 0;
	char *cur, *end;
	char **keys = NULL;
	unsigned long *sizes = NULL;
	size_t cap = 0, n = 0;
	const char *prefix;
	char normalized[512];
	int rc;

	if (!out_keys || !out_sizes || !out_n)
		return -1;
	*out_keys = NULL;
	*out_sizes = NULL;
	*out_n = 0;

	prefix = key_prefix ? key_prefix : "";
	/* Reuse the prefetch's prefix normalization helper indirectly by
	 * constructing the same "<normalized_prefix><relative_key>" form
	 * that object_storage_list_objects emits. */
	{
		size_t plen = strlen(prefix);
		if (plen == 0) {
			normalized[0] = '\0';
		} else {
			const char *start = prefix;
			size_t copy_len = plen;
			if (start[0] == '/') {
				start++;
				copy_len--;
			}
			snprintf(normalized, sizeof(normalized), "%.*s",
				 (int)copy_len, start);
			plen = strlen(normalized);
			if (plen > 0 && normalized[plen - 1] != '/' &&
			    plen + 1 < sizeof(normalized)) {
				normalized[plen] = '/';
				normalized[plen + 1] = '\0';
			}
		}
	}

	rc = object_storage_get_object(MANIFEST_FILE_NAME, &raw, &raw_len);
	if (rc == -ENOENT)
		return -ENOENT;
	if (rc != 0 || !raw || raw_len == 0) {
		free(raw);
		return -1;
	}

	cur = (char *)raw;
	end = cur + raw_len;

	{
		size_t hlen = strlen(MANIFEST_HEADER);
		if ((size_t)raw_len < hlen ||
		    memcmp(cur, MANIFEST_HEADER, hlen) != 0) {
			pr_err("manifest: bad header (expected '%s')\n",
			       MANIFEST_HEADER);
			free(raw);
			return -1;
		}
		cur += hlen;
	}

	while (cur < end) {
		char *line_end = memchr(cur, '\n', (size_t)(end - cur));
		size_t line_len = line_end ? (size_t)(line_end - cur) : (size_t)(end - cur);
		char *tab;
		char rel[512];
		unsigned long size_val = 0;
		char full[1024];

		if (line_len == 0) {
			cur = line_end ? line_end + 1 : end;
			continue;
		}
		tab = memchr(cur, '\t', line_len);
		if (!tab) {
			pr_warn("manifest: malformed line (no tab), skipping\n");
			cur = line_end ? line_end + 1 : end;
			continue;
		}
		{
			size_t name_len = (size_t)(tab - cur);
			if (name_len >= sizeof(rel))
				name_len = sizeof(rel) - 1;
			memcpy(rel, cur, name_len);
			rel[name_len] = '\0';
		}
		{
			char *size_start = tab + 1;
			while (size_start < cur + line_len &&
			       *size_start >= '0' && *size_start <= '9') {
				size_val = size_val * 10 + (unsigned long)(*size_start - '0');
				size_start++;
			}
		}
		cur = line_end ? line_end + 1 : end;

		if (rel[0] == '\0')
			continue;

		snprintf(full, sizeof(full), "%s%s", normalized, rel);

		if (n == cap) {
			size_t new_cap = cap ? cap * 2 : 32;
			char **nk = realloc(keys, new_cap * sizeof(*nk));
			unsigned long *ns = realloc(sizes, new_cap * sizeof(*ns));
			if (!nk || !ns) {
				free(nk ? nk : keys);
				free(ns ? ns : sizes);
				free(raw);
				return -1;
			}
			keys = nk;
			sizes = ns;
			cap = new_cap;
		}
		keys[n] = xstrdup(full);
		if (!keys[n]) {
			free(raw);
			goto err;
		}
		sizes[n] = size_val;
		n++;
	}

	free(raw);

	*out_keys = keys;
	*out_sizes = sizes;
	*out_n = n;
	pr_info("manifest: parsed %zu entries from %s/%s\n",
		n, prefix, MANIFEST_FILE_NAME);
	return 0;

err:
	{
		size_t i;
		for (i = 0; i < n; i++)
			xfree(keys[i]);
	}
	free(keys);
	free(sizes);
	return -1;
}

int object_storage_write_metadata_bundle(void)
{
	struct bundle_entry *e;
	char *buf = NULL;
	size_t cap = 0, used = 0;
	const char *prefix;
	size_t n_entries = 0;
	int rc = -1;

	if (!opts.enable_object_storage)
		return 0;

	pthread_mutex_lock(&g_bundle_lock);
	if (!g_bundle_head) {
		pthread_mutex_unlock(&g_bundle_lock);
		pr_info("bundle: nothing accumulated, skipping metadata.tar\n");
		return 0;
	}

	cap = g_bundle_total_bytes + 1024 + 256 * 64; /* body + header + per-entry line */
	buf = malloc(cap);
	if (!buf) {
		pthread_mutex_unlock(&g_bundle_lock);
		return -1;
	}
	used = snprintf(buf, cap, "%s", BUNDLE_HEADER);

	for (e = g_bundle_head; e; e = e->next) {
		size_t key_len = strlen(e->key);
		size_t need = key_len + 32 + e->length;

		if (used + need > cap) {
			size_t new_cap = (used + need) * 2;
			char *bigger = realloc(buf, new_cap);
			if (!bigger) {
				free(buf);
				pthread_mutex_unlock(&g_bundle_lock);
				return -1;
			}
			buf = bigger;
			cap = new_cap;
		}

		used += (size_t)snprintf(buf + used, cap - used, "%s\t%lu\n",
					 e->key, e->length);
		memcpy(buf + used, e->data, e->length);
		used += e->length;
		n_entries++;
	}
	pthread_mutex_unlock(&g_bundle_lock);

	prefix = opts.object_storage_object_prefix ? opts.object_storage_object_prefix : "";

	if (object_storage_put_object(BUNDLE_FILE_NAME, buf, used) != 0) {
		pr_warn("bundle: PUT '%s/%s' failed\n", prefix, BUNDLE_FILE_NAME);
		goto out;
	}

	pr_info("bundle: wrote '%s/%s' (%zu bytes, %zu entries)\n",
		prefix, BUNDLE_FILE_NAME, used, n_entries);
	rc = 0;

out:
	free(buf);
	/* Free accumulator regardless — we've either uploaded or given up. */
	pthread_mutex_lock(&g_bundle_lock);
	while (g_bundle_head) {
		struct bundle_entry *next = g_bundle_head->next;
		free(g_bundle_head->key);
		free(g_bundle_head->data);
		free(g_bundle_head);
		g_bundle_head = next;
	}
	g_bundle_total_bytes = 0;
	pthread_mutex_unlock(&g_bundle_lock);
	return rc;
}

int object_storage_read_metadata_bundle(struct objstor_bundle_entry **out_entries,
					size_t *out_n)
{
	void *raw = NULL;
	unsigned long raw_len = 0;
	const char *cur, *end;
	struct objstor_bundle_entry *entries = NULL;
	size_t cap = 0, n = 0;
	int rc;
	size_t hlen;

	if (!out_entries || !out_n)
		return -1;
	*out_entries = NULL;
	*out_n = 0;

	rc = object_storage_get_object(BUNDLE_FILE_NAME, &raw, &raw_len);
	if (rc == -ENOENT)
		return -ENOENT;
	if (rc != 0 || !raw || raw_len == 0) {
		free(raw);
		return -1;
	}

	hlen = strlen(BUNDLE_HEADER);
	if (raw_len < hlen || memcmp(raw, BUNDLE_HEADER, hlen) != 0) {
		pr_err("bundle: bad header\n");
		free(raw);
		return -1;
	}
	cur = (const char *)raw + hlen;
	end = (const char *)raw + raw_len;

	while (cur < end) {
		const char *line_end = memchr(cur, '\n', (size_t)(end - cur));
		const char *tab;
		size_t line_len;
		size_t key_len;
		unsigned long sz = 0;
		const char *p;

		if (!line_end) {
			pr_err("bundle: truncated header at end\n");
			goto err;
		}
		line_len = (size_t)(line_end - cur);
		tab = memchr(cur, '\t', line_len);
		if (!tab) {
			pr_err("bundle: malformed entry header (no tab)\n");
			goto err;
		}
		key_len = (size_t)(tab - cur);

		for (p = tab + 1; p < line_end; p++) {
			if (*p < '0' || *p > '9') {
				pr_err("bundle: malformed size in entry\n");
				goto err;
			}
			sz = sz * 10 + (unsigned long)(*p - '0');
		}

		if ((size_t)(end - (line_end + 1)) < sz) {
			pr_err("bundle: truncated body (needed %lu, have %zu)\n",
			       sz, (size_t)(end - (line_end + 1)));
			goto err;
		}

		if (n == cap) {
			size_t new_cap = cap ? cap * 2 : 32;
			struct objstor_bundle_entry *bigger;
			bigger = realloc(entries, new_cap * sizeof(*bigger));
			if (!bigger)
				goto err;
			entries = bigger;
			cap = new_cap;
		}
		entries[n].key = malloc(key_len + 1);
		entries[n].data = sz > 0 ? malloc(sz) : NULL;
		if (!entries[n].key || (sz > 0 && !entries[n].data)) {
			free(entries[n].key);
			free(entries[n].data);
			goto err;
		}
		memcpy(entries[n].key, cur, key_len);
		entries[n].key[key_len] = '\0';
		if (sz > 0)
			memcpy(entries[n].data, line_end + 1, sz);
		entries[n].length = sz;
		n++;

		cur = line_end + 1 + sz;
	}

	free(raw);
	*out_entries = entries;
	*out_n = n;
	pr_info("bundle: parsed %zu entries from %s\n", n, BUNDLE_FILE_NAME);
	return 0;

err:
	free(raw);
	{
		size_t i;
		for (i = 0; i < n; i++) {
			free(entries[i].key);
			free(entries[i].data);
		}
		free(entries);
	}
	return -1;
}

/*
 * =================================================================================
 * HEAD Object — fetch only the Content-Length, no body.
 *
 * Replaces the geometric Range-GET probe that restore-side compression
 * detection used to discover the compressed pages-*.img length. One
 * round-trip instead of O(log N). S3 and MinIO both answer HEAD cheaply.
 * =================================================================================
 */
int object_storage_head_object(const char *object_key, unsigned long *out_length)
{
	struct object_url_info url_info;
	CURL *curl_handle;
	CURLcode res;
	long http_code = 0;
	curl_off_t content_length = -1;
	struct curl_slist *headers = NULL;
	unsigned long cached_size = 0;

	if (!object_key || !out_length) {
		pr_err("head_object: NULL parameter\n");
		return -1;
	}

	*out_length = 0;

	/*
	 * Short-circuit via the prefetch size cache. obstor_prefetch_init
	 * pulled <Size> out of the LIST response for every key in the active
	 * prefix (including pages-*.img we don't download), so we can answer
	 * HEAD directly without a cross-region round-trip. Authoritative miss
	 * still returns -ENOENT so existence semantics match the real HEAD.
	 */
	if (obstor_prefetch_lookup_size(object_key, &cached_size) == 0) {
		*out_length = cached_size;
		pr_debug("HEAD %s: %lu bytes (prefetch size cache hit)\n",
			 object_key, cached_size);
		return 0;
	}
	if (obstor_prefetch_is_authoritative()) {
		pr_debug("HEAD %s: skipped (prefetch cache authoritative miss)\n",
			 object_key);
		return -ENOENT;
	}

	if (opts.express_one_zone) {
		if (ensure_valid_session() != 0)
			return -1;
	}

	if (_construct_object_url(object_key, &url_info) != 0)
		return -1;

	curl_handle = _get_curl_handle();
	if (!curl_handle)
		return -1;

	curl_easy_setopt(curl_handle, CURLOPT_URL, url_info.url);
	curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 1L);
	/* No write callback — HEAD doesn't return a body. Range/GET handlers
	 * still leaked into reused handles elsewhere, so clear them. */
	curl_easy_setopt(curl_handle, CURLOPT_RANGE, NULL);

	if (_build_auth_headers("HEAD", url_info.auth_host, url_info.canonical_uri,
				NULL, EMPTY_PAYLOAD_HASH, NULL, -1, &headers) != 0)
		return -1;
	if (headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

	res = curl_easy_perform(curl_handle);
	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
	curl_easy_getinfo(curl_handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &content_length);

	/* Reset transient options so the reused handle doesn't stay NOBODY. */
	curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 0L);

	if (headers)
		curl_slist_free_all(headers);

	if (res != CURLE_OK) {
		pr_err("HEAD %s failed: %s\n", object_key, curl_easy_strerror(res));
		return -1;
	}
	if (http_code == 404)
		return -ENOENT;
	if (http_code < 200 || http_code >= 300) {
		pr_err("HEAD %s failed with HTTP %ld\n", object_key, http_code);
		return -1;
	}
	if (content_length < 0) {
		pr_err("HEAD %s: server returned no Content-Length\n", object_key);
		return -1;
	}
	*out_length = (unsigned long)content_length;
	pr_debug("HEAD %s: %lu bytes (HTTP %ld)\n", object_key, *out_length, http_code);
	return 0;
}

/*
 * =================================================================================
 * Fetch Object Tail — single RTT replacement for the legacy
 *   HEAD + 3 small Range GETs that compressed-image init used to do.
 *
 * Issues a "Range: bytes=-<max_tail>" request which both delivers the
 * trailing bytes and returns Content-Range: bytes a-b/<total>, so the
 * caller learns the object size from the same response. For objects
 * smaller than max_tail, S3 returns the entire object and the caller
 * sees got == total_size.
 * =================================================================================
 */
int object_storage_fetch_tail(const char *object_key, unsigned long max_tail,
			      void *buffer, unsigned long *out_got,
			      unsigned long *out_total_size, const char *source)
{
	struct object_url_info url_info;
	CURL *curl_handle;
	CURLcode res;
	long http_code = 0;
	struct MemoryStruct chunk;
	struct MemoryStruct error_response;
	struct FetchContext fetch_ctx;
	struct curl_slist *headers = NULL;
	char range_header[32];
	char range_header_value[64];
	struct timespec t_start, t_end;
	double dur_ms;

	if (!object_key || !buffer || max_tail == 0 ||
	    !out_got || !out_total_size) {
		pr_err("fetch_tail: NULL parameter\n");
		return -1;
	}
	*out_got = 0;
	*out_total_size = 0;

	if (opts.express_one_zone) {
		if (ensure_valid_session() != 0)
			return -1;
	}

	if (_construct_object_url(object_key, &url_info) != 0)
		return -1;

	curl_handle = _get_curl_handle();
	if (!curl_handle)
		return -1;

	chunk.memory = buffer;
	chunk.size = 0;
	chunk.capacity = max_tail;
	error_response.memory = malloc(1);
	error_response.size = 0;
	error_response.capacity = 0;

	fetch_ctx.data_chunk = &chunk;
	fetch_ctx.error_chunk = &error_response;
	fetch_ctx.got_error = 0;
	fetch_ctx.x_cache[0] = '\0';
	fetch_ctx.x_amz_cf_pop[0] = '\0';
	fetch_ctx.content_range_total = 0;

	/*
	 * libcurl's CURLOPT_RANGE takes "first-last" or "-N" (suffix)
	 * forms. We use the suffix form to mean "last N bytes". The value
	 * sent on the wire becomes "Range: bytes=-N", which SigV4 must
	 * sign verbatim.
	 */
	snprintf(range_header, sizeof(range_header), "-%lu", max_tail);
	snprintf(range_header_value, sizeof(range_header_value),
		 "bytes=-%lu", max_tail);

	curl_easy_setopt(curl_handle, CURLOPT_URL, url_info.url);
	curl_easy_setopt(curl_handle, CURLOPT_RANGE, range_header);
	curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 0L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_router_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&fetch_ctx);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *)&fetch_ctx);

	if (_build_auth_headers("GET", url_info.auth_host,
				url_info.canonical_uri, NULL,
				EMPTY_PAYLOAD_HASH, range_header_value,
				-1, &headers) != 0) {
		free(error_response.memory);
		return -1;
	}
	if (headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

	clock_gettime(CLOCK_MONOTONIC, &t_start);
	OBJSTOR_FETCH_START_LOG(object_key, 0, max_tail, source);
	res = curl_easy_perform(curl_handle);
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	dur_ms = (t_end.tv_sec - t_start.tv_sec) * 1000.0 +
		 (t_end.tv_nsec - t_start.tv_nsec) / 1000000.0;

	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

	OBJSTOR_FETCH_DONE_LOG(object_key, 0, chunk.size, dur_ms,
			       fetch_ctx.x_cache, fetch_ctx.x_amz_cf_pop, source);

	if (headers)
		curl_slist_free_all(headers);
	curl_easy_setopt(curl_handle, CURLOPT_RANGE, NULL);

	if (res != CURLE_OK) {
		pr_err("fetch_tail %s: curl error %s\n",
		       object_key, curl_easy_strerror(res));
		free(error_response.memory);
		return -1;
	}
	if (http_code == 404) {
		free(error_response.memory);
		return -ENOENT;
	}
	/* 206 Partial Content for ranged tail; 200 OK for full small object. */
	if (http_code != 200 && http_code != 206) {
		pr_err("fetch_tail %s: HTTP %ld\n", object_key, http_code);
		free(error_response.memory);
		return -1;
	}

	*out_got = chunk.size;

	/*
	 * Recover total object size: prefer Content-Range (range/full
	 * responses); if absent (HTTP 200 small-object case), the body
	 * IS the entire object so total == got.
	 */
	if (fetch_ctx.content_range_total > 0)
		*out_total_size = fetch_ctx.content_range_total;
	else if (http_code == 200)
		*out_total_size = chunk.size;
	else {
		pr_err("fetch_tail %s: HTTP 206 without parsable Content-Range\n",
		       object_key);
		free(error_response.memory);
		return -1;
	}

	free(error_response.memory);
	return 0;
}

/*
 * =================================================================================
 * List Objects V2 — enumerates keys under a prefix for bulk metadata prefetch.
 * Used by obstor_prefetch to discover all metadata files before opening any
 * image so that per-image opens become in-memory cache hits instead of one
 * serial S3 GET per file.
 * =================================================================================
 */

/*
 * Percent-encode a string for SigV4 canonical query string.
 * RFC 3986 unreserved: A-Z a-z 0-9 - _ . ~
 * Everything else must be %XX (uppercase hex).
 */
static int _sigv4_uri_encode(const char *src, char *dst, size_t dst_cap)
{
	size_t si, di = 0;
	const char *hex = "0123456789ABCDEF";

	for (si = 0; src[si]; si++) {
		unsigned char c = (unsigned char)src[si];
		int unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
				 (c >= '0' && c <= '9') || c == '-' || c == '_' ||
				 c == '.' || c == '~';
		if (unreserved) {
			if (di + 1 >= dst_cap)
				return -1;
			dst[di++] = (char)c;
		} else {
			if (di + 3 >= dst_cap)
				return -1;
			dst[di++] = '%';
			dst[di++] = hex[(c >> 4) & 0xF];
			dst[di++] = hex[c & 0xF];
		}
	}
	if (di >= dst_cap)
		return -1;
	dst[di] = '\0';
	return 0;
}

/*
 * Minimal XML tag extractor. Finds the content of <tag>...</tag> starting
 * from *cursor; on success advances *cursor past the closing tag and returns
 * the content in a caller-provided buffer. Returns 0 on found, -1 on absent.
 * Not a general-purpose parser — only used for the tiny subset of fields
 * ListObjectsV2 returns (<Key>, <IsTruncated>, <NextContinuationToken>).
 */
static int _xml_extract_next(const char **cursor, const char *end, const char *tag, char *out, size_t out_cap)
{
	char open_tag[64], close_tag[64];
	const char *p, *q;
	size_t n;

	snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
	snprintf(close_tag, sizeof(close_tag), "</%s>", tag);

	p = strstr(*cursor, open_tag);
	if (!p || p >= end)
		return -1;
	p += strlen(open_tag);
	q = strstr(p, close_tag);
	if (!q || q >= end)
		return -1;

	n = (size_t)(q - p);
	if (n >= out_cap)
		n = out_cap - 1;
	memcpy(out, p, n);
	out[n] = '\0';
	*cursor = q + strlen(close_tag);
	return 0;
}

/*
 * Issue one ListObjectsV2 HTTP call. Appends extracted keys to *out_keys
 * (which may be NULL initially and is grown via realloc). Sets *continuation
 * to the NextContinuationToken on truncation (caller must free), NULL otherwise.
 *
 * Returns 0 on success, -1 on failure.
 */
static int _list_objects_v2_once(const char *key_prefix, const char *continuation_in,
				 char ***io_keys, unsigned long **io_sizes,
				 size_t *io_n, size_t *io_cap,
				 char **continuation_out)
{
	struct object_url_info url_info_unused;
	char encoded_prefix[1024];
	char encoded_token[1024];
	char query_canonical[4096];
	char query_url[4096];
	char url[8192];
	char host[512];
	CURL *curl_handle;
	struct MemoryStruct chunk;
	struct curl_slist *headers = NULL;
	CURLcode res;
	long http_code = 0;
	const char *endpoint_url, *hostname;
	const char *cursor, *end_p;
	char truncated_buf[16];
	int ret = -1;

	(void)url_info_unused;

	*continuation_out = NULL;

	if (_sigv4_uri_encode(key_prefix ? key_prefix : "", encoded_prefix, sizeof(encoded_prefix)) != 0) {
		pr_err("list_objects: prefix encode overflow\n");
		return -1;
	}

	if (continuation_in) {
		if (_sigv4_uri_encode(continuation_in, encoded_token, sizeof(encoded_token)) != 0) {
			pr_err("list_objects: continuation-token encode overflow\n");
			return -1;
		}
	} else {
		encoded_token[0] = '\0';
	}

	/*
	 * SigV4 canonical query string: keys sorted alphabetically.
	 * Keys used: continuation-token, list-type, max-keys, prefix
	 */
	if (continuation_in)
		snprintf(query_canonical, sizeof(query_canonical),
			 "continuation-token=%s&list-type=2&max-keys=1000&prefix=%s",
			 encoded_token, encoded_prefix);
	else
		snprintf(query_canonical, sizeof(query_canonical),
			 "list-type=2&max-keys=1000&prefix=%s",
			 encoded_prefix);

	/* URL query string is identical to canonical here (no duplicate keys). */
	snprintf(query_url, sizeof(query_url), "%s", query_canonical);

	endpoint_url = opts.object_storage_endpoint_url;
	hostname = _strip_scheme(endpoint_url);

	/* LIST target is the bucket itself, so auth host = bucket-virtual-host. */
	if (opts.object_storage_path_style || !opts.object_storage_bucket || !opts.object_storage_bucket[0]) {
		snprintf(host, sizeof(host), "%s", hostname);
		if (hostname != endpoint_url)
			snprintf(url, sizeof(url), "%.*s%s/%s?%s",
				 (int)(hostname - endpoint_url), endpoint_url, hostname,
				 opts.object_storage_bucket ? opts.object_storage_bucket : "", query_url);
		else
			snprintf(url, sizeof(url), "https://%s/%s?%s",
				 hostname, opts.object_storage_bucket ? opts.object_storage_bucket : "", query_url);
	} else {
		snprintf(host, sizeof(host), "%s.%s", opts.object_storage_bucket, hostname);
		if (hostname != endpoint_url)
			snprintf(url, sizeof(url), "%.*s%s.%s/?%s",
				 (int)(hostname - endpoint_url), endpoint_url,
				 opts.object_storage_bucket, hostname, query_url);
		else
			snprintf(url, sizeof(url), "https://%s.%s/?%s",
				 opts.object_storage_bucket, hostname, query_url);
	}
	/* Strip trailing slash in host if any */
	{
		size_t hlen = strlen(host);
		if (hlen > 0 && host[hlen - 1] == '/')
			host[hlen - 1] = '\0';
	}

	curl_handle = _get_curl_handle();
	if (!curl_handle)
		return -1;

	chunk.memory = malloc(1);
	chunk.size = 0;
	chunk.capacity = 0;

	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &chunk);

	/* SigV4 canonical URI for LIST: path-style = "/<bucket>", vhost = "/" */
	{
		char canonical_uri[1024];
		if (opts.object_storage_path_style && opts.object_storage_bucket && opts.object_storage_bucket[0])
			snprintf(canonical_uri, sizeof(canonical_uri), "/%s", opts.object_storage_bucket);
		else
			snprintf(canonical_uri, sizeof(canonical_uri), "/");

		if (_build_auth_headers("GET", host, canonical_uri, query_canonical,
					EMPTY_PAYLOAD_HASH, NULL, -1, &headers) != 0) {
			free(chunk.memory);
			return -1;
		}
	}

	if (headers)
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

	pr_debug("LIST %s\n", url);

	res = curl_easy_perform(curl_handle);
	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

	if (headers)
		curl_slist_free_all(headers);

	if (res != CURLE_OK) {
		pr_err("LIST failed: %s\n", curl_easy_strerror(res));
		goto out;
	}
	if (http_code < 200 || http_code >= 300) {
		pr_err("LIST HTTP %ld: %.*s\n", http_code, (int)chunk.size, chunk.memory ? (char *)chunk.memory : "");
		goto out;
	}

	/*
	 * Parse XML by walking <Contents>...</Contents> blocks, extracting
	 * <Key> and <Size> from each. Doing this per-block (rather than
	 * separate sequential walks for Key and Size) keeps the pairing
	 * unambiguous if S3 ever changes the relative order.
	 */
	cursor = (const char *)chunk.memory;
	end_p = cursor + chunk.size;
	for (;;) {
		const char *contents_open;
		const char *contents_close;
		const char *kp, *kq;
		const char *sp, *sq;
		char key_buf[2048];
		char size_buf[64];
		unsigned long size_val = 0;
		size_t key_len, size_len;

		contents_open = strstr(cursor, "<Contents>");
		if (!contents_open || contents_open >= end_p)
			break;
		contents_close = strstr(contents_open, "</Contents>");
		if (!contents_close || contents_close >= end_p)
			break;

		kp = strstr(contents_open, "<Key>");
		if (!kp || kp >= contents_close) {
			cursor = contents_close + strlen("</Contents>");
			continue;
		}
		kp += strlen("<Key>");
		kq = strstr(kp, "</Key>");
		if (!kq || kq >= contents_close) {
			cursor = contents_close + strlen("</Contents>");
			continue;
		}
		key_len = (size_t)(kq - kp);
		if (key_len >= sizeof(key_buf))
			key_len = sizeof(key_buf) - 1;
		memcpy(key_buf, kp, key_len);
		key_buf[key_len] = '\0';

		sp = strstr(contents_open, "<Size>");
		if (sp && sp < contents_close) {
			sp += strlen("<Size>");
			sq = strstr(sp, "</Size>");
			if (sq && sq < contents_close) {
				size_len = (size_t)(sq - sp);
				if (size_len < sizeof(size_buf)) {
					memcpy(size_buf, sp, size_len);
					size_buf[size_len] = '\0';
					size_val = strtoul(size_buf, NULL, 10);
				}
			}
		}

		if (*io_n == *io_cap) {
			size_t new_cap = *io_cap ? (*io_cap) * 2 : 128;
			char **nk = realloc(*io_keys, new_cap * sizeof(char *));
			unsigned long *ns;

			if (!nk) {
				pr_err("list_objects: realloc keys failed\n");
				goto out;
			}
			*io_keys = nk;
			ns = realloc(*io_sizes, new_cap * sizeof(unsigned long));
			if (!ns) {
				pr_err("list_objects: realloc sizes failed\n");
				goto out;
			}
			*io_sizes = ns;
			*io_cap = new_cap;
		}
		(*io_keys)[*io_n] = xstrdup(key_buf);
		(*io_sizes)[*io_n] = size_val;
		(*io_n)++;

		cursor = contents_close + strlen("</Contents>");
	}

	{
		const char *p = (const char *)chunk.memory;
		char token_buf[1024];
		if (_xml_extract_next(&p, end_p, "IsTruncated", truncated_buf, sizeof(truncated_buf)) == 0 &&
		    strcmp(truncated_buf, "true") == 0) {
			p = (const char *)chunk.memory;
			if (_xml_extract_next(&p, end_p, "NextContinuationToken", token_buf, sizeof(token_buf)) == 0)
				*continuation_out = xstrdup(token_buf);
		}
	}

	ret = 0;
out:
	free(chunk.memory);
	return ret;
}

/*
 * Enumerate all object keys under the given prefix, also returning their
 * sizes (via the LIST <Size> field). On success: *out_keys is a parallel
 * array of xstrdup'd key strings, *out_sizes is a realloc'd array of byte
 * sizes, *out_n is the count. Caller must xfree each key, the keys array,
 * and free() the sizes array. Pass out_sizes=NULL if sizes aren't needed.
 */
int object_storage_list_objects(const char *key_prefix, char ***out_keys,
				unsigned long **out_sizes, size_t *out_n)
{
	char **keys = NULL;
	unsigned long *sizes = NULL;
	size_t n = 0, cap = 0;
	char *continuation = NULL;
	int rounds = 0;

	if (!out_keys || !out_n)
		return -1;
	*out_keys = NULL;
	if (out_sizes)
		*out_sizes = NULL;
	*out_n = 0;

	do {
		char *next = NULL;
		if (_list_objects_v2_once(key_prefix, continuation, &keys, &sizes,
					  &n, &cap, &next) != 0) {
			if (continuation)
				xfree(continuation);
			goto err;
		}
		if (continuation)
			xfree(continuation);
		continuation = next;
		rounds++;
		if (rounds > 64) {
			pr_err("list_objects: too many pagination rounds (>64), aborting\n");
			goto err;
		}
	} while (continuation);

	*out_keys = keys;
	if (out_sizes)
		*out_sizes = sizes;
	else if (sizes)
		free(sizes);
	*out_n = n;
	pr_info("LIST prefix='%s': %zu keys (%d page(s))\n", key_prefix ? key_prefix : "", n, rounds);
	return 0;

err:
	if (sizes)
		free(sizes);
	if (keys) {
		size_t i;
		for (i = 0; i < n; i++)
			xfree(keys[i]);
		free(keys);
	}
	return -1;
}

/*
 * =================================================================================
 * Fetch Range (existing)
 * =================================================================================
 */

/*
 * Like object_storage_fetch_range, but returns the number of bytes actually
 * received (which can be less than `length` when the range ends past EOF)
 * and does not treat a short read as an error. Intended for probing file
 * tails (seek-table detection) and for decompressor-driven reads that
 * naturally clamp at EOF.
 */
int object_storage_fetch_range_short(const char *object_key, unsigned long offset,
				     unsigned long length, void *buffer,
				     unsigned long *out_got, const char *source);

/*
 * Multipart-parallel download path for prefetch worker fetches.
 *
 * Each worker thread keeps a small pool of curl easy handles bound to a
 * single CURLM. On each large (>= MULTIPART_DL_THRESHOLD) Range GET, the
 * helper splits [offset, offset+length) into N_PARTS sub-ranges, drives
 * them concurrently through curl_multi_perform, and writes directly into
 * adjacent slices of the caller's buffer.
 *
 * Design rationale:
 *   - AWS S3 caps single-connection throughput around ~2-5 MB/s for
 *     long-running cross-region ranges (per-connection cwnd stays small).
 *   - aws s3 cp's default multipart_chunksize=8MB × 10 parallel streams
 *     achieves ~100 MB/s per file. We mirror that pattern inside one
 *     prefetch worker.
 *   - Each sub-handle pins to a different S3 edge IP via CURLOPT_RESOLVE
 *     so concurrent sub-streams ride independent TCP paths.
 *   - The pool is per-pthread (TLS) — workers never share handles.
 *   - For lengths below the threshold, falls through to the single-handle
 *     path so small fetches do not pay multipart setup overhead.
 */
#define MULTIPART_DL_THRESHOLD  (8UL * 1024 * 1024)  /* under this, single-handle */
#define MULTIPART_DL_PART_SIZE  (8UL * 1024 * 1024)  /* 8 MB per sub-stream — matches aws s3 cp default and CRT's g_default_part_size_fallback */
#define MULTIPART_DL_MAX_PARTS  4                    /* sub-handles per worker; with 30 prefetch workers this caps total concurrent connections at 120 (vs 480 with 16 sub-handles), restoring connection reuse and per-stream throughput observed in standalone libcurl tests */

/*
 * Per-sub-handle persistent worker thread state.
 *
 * Each sub-handle owns one long-lived pthread for the lifetime of the
 * pool. The thread is the ONLY user of pool->easy[idx] and thus respects
 * libcurl's documented constraint that an easy handle stays in a single
 * thread context. This is essential for HTTPS keep-alive: TLS session
 * resumption and per-connection state are owned by the thread that did
 * the original handshake, and previous "ephemeral pthread per fetch"
 * implementations observed 0 % connection reuse on cross-region HTTPS
 * (every fetch re-did full TLS handshake, ~5.4 s per sub-stream).
 */
struct sub_thread_state {
	struct thread_dl_pool *pool;   /* back-reference */
	int idx;                       /* which sub-handle this thread drives */
	pthread_t tid;
	pthread_mutex_t lock;
	pthread_cond_t  work_avail;    /* dispatcher signals worker */
	pthread_cond_t  work_done;     /* worker signals dispatcher */

	bool has_work;
	bool done;
	bool shutdown;

	/* per-fetch arguments — written by dispatcher, read by worker */
	const char *url;
	const char *auth_host;
	const char *auth_canonical_uri;
	unsigned long part_off;
	unsigned long part_len;
	void *buffer_slice;
	int rc;
};

struct thread_dl_pool {
	CURL *easy[MULTIPART_DL_MAX_PARTS];
	struct curl_slist *headers[MULTIPART_DL_MAX_PARTS];   /* freed/rebuilt per fetch */
	struct curl_slist *resolve[MULTIPART_DL_MAX_PARTS];   /* set once at init */
	struct MemoryStruct chunks[MULTIPART_DL_MAX_PARTS];   /* per-fetch state */
	char range_hdr[MULTIPART_DL_MAX_PARTS][64];
	struct sub_thread_state subs[MULTIPART_DL_MAX_PARTS];
	/*
	 * Shared connection cache across all sub-handles in this pool.
	 * Mimics aws-c-http connection_manager semantics: any easy handle
	 * can vend a cached connection regardless of which handle initially
	 * established it. This is the key bit AWS recommends in
	 *   docs.aws.amazon.com/AmazonS3/latest/userguide/optimizing-performance-design-patterns.html
	 *   "use a pool of HTTP connections and re-use each connection for
	 *   a series of requests"
	 * Without share, libcurl's per-handle cache means only the same
	 * handle can reuse — and under cond-var dispatch, idle gaps cause
	 * the cached connection to be considered stale.
	 */
	CURLSH *share;
	pthread_mutex_t share_locks[CURL_LOCK_DATA_LAST];
	bool initialized;
};

static void _share_lock_cb(CURL *handle, curl_lock_data data,
			   curl_lock_access access, void *userptr)
{
	struct thread_dl_pool *pool = (struct thread_dl_pool *)userptr;
	(void)handle;
	(void)access;
	if (data >= 0 && data < (curl_lock_data)CURL_LOCK_DATA_LAST)
		pthread_mutex_lock(&pool->share_locks[data]);
}

static void _share_unlock_cb(CURL *handle, curl_lock_data data, void *userptr)
{
	struct thread_dl_pool *pool = (struct thread_dl_pool *)userptr;
	(void)handle;
	if (data >= 0 && data < (curl_lock_data)CURL_LOCK_DATA_LAST)
		pthread_mutex_unlock(&pool->share_locks[data]);
}

/* Forward decl: pool init creates pthreads pointing at this function. */
static void *sub_worker_thread_fn(void *vargp);

/*
 * libcurl debug callback. Prints every TEXT line (info/header/conn) that
 * libcurl would normally write to stderr in verbose mode. We intercept
 * to route through pr_info so it lands in criu-lazy-pages.log alongside
 * our own timing instrumentation, and we tag every line with the pid and
 * a "subdbg:" prefix for grep-ability.
 */
static int _curl_debug_cb(CURL *handle, curl_infotype type,
			  char *data, size_t size, void *userptr)
{
	const char *tag;
	char buf[1024];
	size_t n;
	(void)handle;
	(void)userptr;

	switch (type) {
	case CURLINFO_TEXT:        tag = "INFO"; break;
	case CURLINFO_HEADER_OUT:  tag = "HDR>"; break;
	case CURLINFO_HEADER_IN:   tag = "HDR<"; break;
	case CURLINFO_DATA_OUT:    return 0;  /* skip body bytes */
	case CURLINFO_DATA_IN:     return 0;
	case CURLINFO_SSL_DATA_OUT: return 0;
	case CURLINFO_SSL_DATA_IN:  return 0;
	default:                   tag = "????"; break;
	}

	n = size > sizeof(buf) - 1 ? sizeof(buf) - 1 : size;
	memcpy(buf, data, n);
	buf[n] = '\0';
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
		buf[--n] = '\0';
	}
	if (n > 0)
		pr_info("subdbg: %s %s\n", tag, buf);
	return 0;
}


int object_storage_fetch_range(const char *object_key, unsigned long offset, unsigned long length, void *buffer,
			       const char *source)
{
	unsigned long got = 0;
	int rc = object_storage_fetch_range_short(object_key, offset, length,
						  buffer, &got, source);
	if (rc != 0)
		return rc;
	if (got != length) {
		pr_warn("Object Storage fetch: short read (Expected %lu, Got %lu) — "
			"likely past EOF, keeping handle warm\n", length, got);
		return -1;
	}
	return 0;
}

/* ===========================================================
 * Multipart-parallel download: per-thread pool implementation
 * =========================================================== */
static pthread_key_t g_dl_pool_key;
static pthread_once_t g_dl_pool_key_once = PTHREAD_ONCE_INIT;

static void dl_pool_destructor(void *p)
{
	struct thread_dl_pool *pool = (struct thread_dl_pool *)p;
	int i;
	if (!pool)
		return;
	if (pool->initialized) {
		/* Signal shutdown to all sub-threads, then join. */
		for (i = 0; i < MULTIPART_DL_MAX_PARTS; i++) {
			struct sub_thread_state *s = &pool->subs[i];
			pthread_mutex_lock(&s->lock);
			s->shutdown = true;
			pthread_cond_signal(&s->work_avail);
			pthread_mutex_unlock(&s->lock);
		}
		for (i = 0; i < MULTIPART_DL_MAX_PARTS; i++) {
			pthread_join(pool->subs[i].tid, NULL);
			pthread_mutex_destroy(&pool->subs[i].lock);
			pthread_cond_destroy(&pool->subs[i].work_avail);
			pthread_cond_destroy(&pool->subs[i].work_done);
		}
	}
	for (i = 0; i < MULTIPART_DL_MAX_PARTS; i++) {
		if (pool->headers[i])
			curl_slist_free_all(pool->headers[i]);
		if (pool->resolve[i])
			curl_slist_free_all(pool->resolve[i]);
		if (pool->easy[i])
			curl_easy_cleanup(pool->easy[i]);
	}
	if (pool->share)
		curl_share_cleanup(pool->share);
	for (i = 0; i < CURL_LOCK_DATA_LAST; i++)
		pthread_mutex_destroy(&pool->share_locks[i]);
	free(pool);
}

static void init_dl_pool_key(void)
{
	pthread_key_create(&g_dl_pool_key, dl_pool_destructor);
}

static struct thread_dl_pool *get_thread_dl_pool(void)
{
	struct thread_dl_pool *pool;
	int i;

	pthread_once(&g_dl_pool_key_once, init_dl_pool_key);
	pool = (struct thread_dl_pool *)pthread_getspecific(g_dl_pool_key);
	if (pool && pool->initialized)
		return pool;
	if (!pool) {
		pool = (struct thread_dl_pool *)calloc(1, sizeof(*pool));
		if (!pool) {
			pr_err("dl_pool: calloc failed\n");
			return NULL;
		}
		pthread_setspecific(g_dl_pool_key, pool);
	}
	/* Init share handle + per-data mutexes. Must succeed before easy
	 * handles are bound to it. */
	for (i = 0; i < CURL_LOCK_DATA_LAST; i++)
		pthread_mutex_init(&pool->share_locks[i], NULL);
	pool->share = curl_share_init();
	if (!pool->share) {
		pr_err("dl_pool: curl_share_init failed\n");
		dl_pool_destructor(pool);
		pthread_setspecific(g_dl_pool_key, NULL);
		return NULL;
	}
	curl_share_setopt(pool->share, CURLSHOPT_LOCKFUNC, _share_lock_cb);
	curl_share_setopt(pool->share, CURLSHOPT_UNLOCKFUNC, _share_unlock_cb);
	curl_share_setopt(pool->share, CURLSHOPT_USERDATA, pool);
	curl_share_setopt(pool->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
	curl_share_setopt(pool->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
	curl_share_setopt(pool->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);

	for (i = 0; i < MULTIPART_DL_MAX_PARTS; i++) {
		pool->easy[i] = curl_easy_init();
		if (!pool->easy[i]) {
			pr_err("dl_pool: curl_easy_init[%d] failed\n", i);
			dl_pool_destructor(pool);
			pthread_setspecific(g_dl_pool_key, NULL);
			return NULL;
		}
		set_fixed_curl_options(pool->easy[i]);
		/* Bind to the shared connection / DNS / SSL-session cache so
		 * any sub-handle can vend a previously-cached connection. */
		curl_easy_setopt(pool->easy[i], CURLOPT_SHARE, pool->share);
		/*
		 * Enable libcurl verbose tracing on sub-handle 0 of every
		 * pool. This records "Re-using existing connection" /
		 * "Connection died" / SSL handshake / HTTP exchange details
		 * which let us see why reuse is or isn't happening. We limit
		 * to idx=0 to keep the log volume sane.
		 */
		if (i == 0) {
			curl_easy_setopt(pool->easy[i], CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(pool->easy[i], CURLOPT_DEBUGFUNCTION,
					 _curl_debug_cb);
		}
		/*
		 * Pin each sub-handle to one resolved endpoint IP (round-robin
		 * across the host's resolved IP list). 4 sub-handles -> 4
		 * different IPs. Two purposes:
		 *   1) Address diversity recommended by S3 perf doc: spread
		 *      concurrent requests across S3 partitions/edges so we
		 *      get more aggregate bandwidth than a single edge gives.
		 *   2) Bundle-key stability under shared connection cache: a
		 *      pinned handle only matches/reuses its own IP's idle
		 *      connection in the CURLSH bundle, so back-to-back
		 *      requests on one sub-handle stick to one socket.
		 * Generic IP-level mechanism via CURLOPT_RESOLVE — works for
		 * MinIO and any S3-compatible endpoint, no AWS-specific path.
		 */
		pool->resolve[i] = _pin_handle_to_s3_edge(pool->easy[i]);

		/* Initialize sub-thread state and spawn the persistent worker. */
		pool->subs[i].pool = pool;
		pool->subs[i].idx = i;
		pthread_mutex_init(&pool->subs[i].lock, NULL);
		pthread_cond_init(&pool->subs[i].work_avail, NULL);
		pthread_cond_init(&pool->subs[i].work_done, NULL);
		pool->subs[i].has_work = false;
		pool->subs[i].done = false;
		pool->subs[i].shutdown = false;
		if (pthread_create(&pool->subs[i].tid, NULL,
				   sub_worker_thread_fn, &pool->subs[i]) != 0) {
			pr_err("dl_pool: pthread_create[%d] failed\n", i);
			pthread_mutex_destroy(&pool->subs[i].lock);
			pthread_cond_destroy(&pool->subs[i].work_avail);
			pthread_cond_destroy(&pool->subs[i].work_done);
			dl_pool_destructor(pool);
			pthread_setspecific(g_dl_pool_key, NULL);
			return NULL;
		}
	}
	pool->initialized = true;
	return pool;
}

/*
 * Drive a single sub-fetch on the per-thread persistent easy handle.
 * Called only from the sub-thread that owns this handle — never from
 * the dispatcher or another worker. Reads work parameters from the
 * sub_thread_state struct that the dispatcher pre-populated.
 */
static void _do_sub_fetch(struct thread_dl_pool *pool, int idx,
			  struct sub_thread_state *s)
{
	CURL *e = pool->easy[idx];
	CURLcode res;
	long http_code = 0;
	char range_value[64];
	double t_connect = 0, t_appconnect = 0;
	double t_starttransfer = 0, t_total = 0;
	curl_off_t dl_size = 0;
	double body_ms, body_mbps = 0.0;

	pool->chunks[idx].memory = s->buffer_slice;
	pool->chunks[idx].size = 0;
	pool->chunks[idx].capacity = s->part_len;
	snprintf(pool->range_hdr[idx], sizeof(pool->range_hdr[idx]),
		 "%lu-%lu", s->part_off, s->part_off + s->part_len - 1);

	curl_easy_setopt(e, CURLOPT_URL, s->url);
	curl_easy_setopt(e, CURLOPT_RANGE, pool->range_hdr[idx]);
	curl_easy_setopt(e, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(e, CURLOPT_FAILONERROR, 0L);
	curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(e, CURLOPT_WRITEDATA, (void *)&pool->chunks[idx]);

	snprintf(range_value, sizeof(range_value), "bytes=%s",
		 pool->range_hdr[idx]);
	if (pool->headers[idx]) {
		curl_slist_free_all(pool->headers[idx]);
		pool->headers[idx] = NULL;
	}
	if (_build_auth_headers("GET", s->auth_host, s->auth_canonical_uri,
				NULL, EMPTY_PAYLOAD_HASH, range_value,
				-1, &pool->headers[idx]) != 0) {
		pr_err("sub_fetch[%d]: auth build failed\n", idx);
		s->rc = -1;
		return;
	}
	curl_easy_setopt(e, CURLOPT_HTTPHEADER, pool->headers[idx]);

	res = curl_easy_perform(e);
	curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &http_code);
	curl_easy_getinfo(e, CURLINFO_CONNECT_TIME, &t_connect);
	curl_easy_getinfo(e, CURLINFO_APPCONNECT_TIME, &t_appconnect);
	curl_easy_getinfo(e, CURLINFO_STARTTRANSFER_TIME, &t_starttransfer);
	curl_easy_getinfo(e, CURLINFO_TOTAL_TIME, &t_total);
	curl_easy_getinfo(e, CURLINFO_SIZE_DOWNLOAD_T, &dl_size);
	{
		long num_connects = -1;
		curl_off_t conn_id = -1;
		long local_port = -1;
		char *primary_ip = NULL;
		long primary_port = 0;
		curl_easy_getinfo(e, CURLINFO_NUM_CONNECTS, &num_connects);
		curl_easy_getinfo(e, CURLINFO_CONN_ID, &conn_id);
		curl_easy_getinfo(e, CURLINFO_LOCAL_PORT, &local_port);
		curl_easy_getinfo(e, CURLINFO_PRIMARY_IP, &primary_ip);
		curl_easy_getinfo(e, CURLINFO_PRIMARY_PORT, &primary_port);

		body_ms = (t_total - t_starttransfer) * 1000.0;
		if (body_ms > 0)
			body_mbps = ((double)dl_size / 1024.0 / 1024.0) / (body_ms / 1000.0);

		pr_info("multipart_sub_timing: idx=%d dl=%ld total_ms=%.1f "
			"connect_ms=%.1f appconnect_ms=%.1f starttransfer_ms=%.1f "
			"body_ms=%.1f body_mbps=%.2f reused=%s "
			"num_connects=%ld conn_id=%ld local_port=%ld "
			"peer=%s:%ld http=%ld\n",
			idx, (long)dl_size, t_total * 1000.0,
			t_connect * 1000.0, t_appconnect * 1000.0,
			t_starttransfer * 1000.0, body_ms, body_mbps,
			t_connect == 0.0 ? "yes" : "no",
			num_connects, (long)conn_id, local_port,
			primary_ip ? primary_ip : "?", primary_port, http_code);
	}

	if (res != CURLE_OK || http_code >= 400) {
		pr_err("sub_fetch[%d]: failed: %s (HTTP %ld)\n", idx,
		       curl_easy_strerror(res), http_code);
		s->rc = -1;
	} else {
		s->rc = 0;
	}
}

/*
 * Persistent sub-handle worker thread. Owns pool->easy[idx] for life.
 * Loops: wait on cond var → execute one sub-fetch → signal done → repeat.
 */
static void *sub_worker_thread_fn(void *vargp)
{
	struct sub_thread_state *s = (struct sub_thread_state *)vargp;
	struct thread_dl_pool *pool = s->pool;
	int idx = s->idx;

	for (;;) {
		pthread_mutex_lock(&s->lock);
		while (!s->has_work && !s->shutdown)
			pthread_cond_wait(&s->work_avail, &s->lock);
		if (s->shutdown) {
			pthread_mutex_unlock(&s->lock);
			break;
		}
		s->has_work = false;
		pthread_mutex_unlock(&s->lock);

		_do_sub_fetch(pool, idx, s);

		pthread_mutex_lock(&s->lock);
		s->done = true;
		pthread_cond_signal(&s->work_done);
		pthread_mutex_unlock(&s->lock);
	}
	return NULL;
}

/*
 * Multipart helper. Caller has already constructed `url` (including any
 * presigned query) and `auth_host` / `auth_canonical_uri` for SigV4.
 * Returns 0 on full success, -1 on any sub-fetch failure.
 *
 * Splits the range across the per-thread pool's persistent sub-handles
 * (one pthread per sub-handle for life of the worker). Dispatcher fills
 * each sub-thread's mailbox, signals work_avail, then waits work_done.
 * The persistent-thread design ensures each easy handle is touched by a
 * single thread context — required by libcurl for HTTPS keep-alive
 * (TLS session resumption breaks across thread contexts and we observed
 * 0 % connection reuse cross-region with ephemeral threads).
 */
static int _fetch_range_multipart(const char *url, const char *auth_host,
				  const char *auth_canonical_uri,
				  unsigned long offset, unsigned long length,
				  void *buffer, unsigned long *out_got)
{
	struct thread_dl_pool *pool = get_thread_dl_pool();
	int n = (int)((length + MULTIPART_DL_PART_SIZE - 1) / MULTIPART_DL_PART_SIZE);
	unsigned long part_size;
	int i;
	int n_failed = 0;
	int n_dispatched = 0;
	unsigned long got = 0;

	if (n < 1)
		n = 1;
	if (n > MULTIPART_DL_MAX_PARTS)
		n = MULTIPART_DL_MAX_PARTS;

	if (!pool)
		return -1;

	/* part_size: ceil(length/n). Final part absorbs the tail rounding. */
	part_size = (length + n - 1) / n;

	/* Dispatch: fill each mailbox + signal work_avail. */
	for (i = 0; i < n; i++) {
		unsigned long part_off = offset + (unsigned long)i * part_size;
		unsigned long part_len;
		struct sub_thread_state *s = &pool->subs[i];

		if (part_off >= offset + length)
			break;
		part_len = part_size;
		if (part_off + part_len > offset + length)
			part_len = offset + length - part_off;
		if (part_len == 0)
			break;

		pthread_mutex_lock(&s->lock);
		s->url = url;
		s->auth_host = auth_host;
		s->auth_canonical_uri = auth_canonical_uri;
		s->part_off = part_off;
		s->part_len = part_len;
		s->buffer_slice = (char *)buffer + (part_off - offset);
		s->rc = 0;
		s->done = false;
		s->has_work = true;
		pthread_cond_signal(&s->work_avail);
		pthread_mutex_unlock(&s->lock);
		n_dispatched++;
	}

	/* Wait: each dispatched sub-thread sets done=true and signals. */
	for (i = 0; i < n_dispatched; i++) {
		struct sub_thread_state *s = &pool->subs[i];
		pthread_mutex_lock(&s->lock);
		while (!s->done)
			pthread_cond_wait(&s->work_done, &s->lock);
		if (s->rc != 0)
			n_failed++;
		got += pool->chunks[i].size;
		pthread_mutex_unlock(&s->lock);
	}

	if (out_got)
		*out_got = got;

	return n_failed > 0 ? -1 : 0;
}

int object_storage_fetch_range_short(const char *object_key, unsigned long offset, unsigned long length, void *buffer,
				     unsigned long *out_got, const char *source)
{
	CURL *curl_handle;
	CURLcode res;
	long http_code = 0;
	struct MemoryStruct chunk;
	struct MemoryStruct error_response;
	char range_header[64];
	char url[1024];
	char normalized_prefix[256];
	char full_object_path[512];
	const char *endpoint_url;
	const char *hostname;
	CURL *retry_handle = NULL;
	struct curl_slist *headers = NULL;
	int ret = -1;
	struct FetchContext fetch_ctx;
	struct timespec fetch_start, fetch_end;
	double fetch_duration_ms;

	/* Ensure we have a valid session for Express One Zone */
	if (ensure_valid_session() != 0) {
		pr_err("Failed to ensure valid Express One Zone session\n");
		return -1;
	}

	/* Check if we need to reinitialize curl for lazy-pages context */
	if (check_and_reinitialize_for_lazy_pages() != 0) {
		pr_err("Failed to reinitialize curl for lazy-pages context\n");
	}

	/* Basic validation */
	if (!opts.object_storage_endpoint_url || !object_key || !buffer || length == 0) {
		pr_err("Object Storage fetch range: Invalid arguments provided.\n");
		return -1;
	}

	/* Prepare memory structure for received data */
	chunk.memory = buffer;
	chunk.size = 0;
	chunk.capacity = length;

	/* Initialize error response buffer */
	error_response.memory = malloc(1);
	error_response.size = 0;
	error_response.capacity = 0;

	/* Set up fetch context */
	fetch_ctx.data_chunk = &chunk;
	fetch_ctx.error_chunk = &error_response;
	fetch_ctx.got_error = 0;
	fetch_ctx.x_cache[0] = '\0';
	fetch_ctx.x_amz_cf_pop[0] = '\0';

	/* Normalize the object prefix */
	if (opts.object_storage_object_prefix) {
		const char *original_prefix = opts.object_storage_object_prefix;
		size_t prefix_len = strlen(original_prefix);
		if (prefix_len == 1 && original_prefix[0] == '/') {
			normalized_prefix[0] = '\0';
		} else if (prefix_len > 0) {
			const char *start = original_prefix;
			size_t copy_len = prefix_len;
			/* Remove leading '/' if present */
			if (original_prefix[0] == '/') {
				start++;
				copy_len--;
			}
			snprintf(normalized_prefix, sizeof(normalized_prefix), "%.*s", (int)copy_len, start);

			/* Ensure trailing '/' if not empty */
			if (copy_len > 0 && normalized_prefix[copy_len - 1] != '/') {
				size_t current_len = strlen(normalized_prefix);
				if (current_len < sizeof(normalized_prefix) - 1) {
					normalized_prefix[current_len] = '/';
					normalized_prefix[current_len + 1] = '\0';
				} else {
					pr_warn("Object prefix buffer too small to add trailing slash: %s\n",
						original_prefix);
				}
			}
		} else {
			normalized_prefix[0] = '\0';
		}
	} else {
		normalized_prefix[0] = '\0';
	}

	/* Handle endpoint URL and extract hostname (without scheme) */
	endpoint_url = opts.object_storage_endpoint_url;
	hostname = _strip_scheme(endpoint_url);

	/*
	 * Build full object path. See _construct_object_url for the full
	 * rationale. Any key containing '/' is already absolute (either the
	 * current opts prefix or a parent-chain prefix attached by
	 * maybe_read_page_object_storage via pr->object_storage_prefix).
	 * Only bare filenames need normalized_prefix prepended.
	 */
	if (strchr(object_key, '/') != NULL) {
		snprintf(full_object_path, sizeof(full_object_path), "%s", object_key);
		pr_debug("Object key is absolute, using as is: %s\n", full_object_path);
	} else {
		snprintf(full_object_path, sizeof(full_object_path), "%s%s", normalized_prefix, object_key);
		pr_debug("Prepended prefix to object key: %s\n", full_object_path);
	}

	/* Construct the final URL */
	if (opts.express_one_zone) {
		/* Express One Zone: always virtual-hosted style */
		snprintf(url, sizeof(url), "https://%s.%s/%s", opts.object_storage_bucket,
			 hostname, full_object_path);
	} else if (opts.object_storage_bucket && opts.object_storage_bucket[0] != '\0') {
		if (opts.object_storage_path_style) {
			/* Path-style: {scheme}{hostname}/{bucket}/{path} */
			if (hostname != endpoint_url) {
				snprintf(url, sizeof(url), "%.*s%s/%s/%s",
					 (int)(hostname - endpoint_url), endpoint_url,
					 hostname, opts.object_storage_bucket, full_object_path);
			} else {
				snprintf(url, sizeof(url), "https://%s/%s/%s",
					 hostname, opts.object_storage_bucket, full_object_path);
			}
		} else {
			/* Virtual-hosted-style: {scheme}{bucket}.{hostname}/{path} */
			if (hostname != endpoint_url) {
				snprintf(url, sizeof(url), "%.*s%s.%s/%s",
					 (int)(hostname - endpoint_url), endpoint_url,
					 opts.object_storage_bucket, hostname, full_object_path);
			} else {
				snprintf(url, sizeof(url), "https://%s.%s/%s",
					 opts.object_storage_bucket, hostname, full_object_path);
			}
		}
	} else {
		/* No bucket - use direct endpoint URL */
		if (hostname != endpoint_url) {
			snprintf(url, sizeof(url), "%s/%s", endpoint_url, full_object_path);
		} else {
			snprintf(url, sizeof(url), "https://%s/%s", hostname, full_object_path);
		}
	}

	/* Prepare the Range header */
	snprintf(range_header, sizeof(range_header), "%lu-%lu", offset, offset + length - 1);

	/* Get the appropriate curl handle based on thread context */
	if (!is_main_thread()) {
		/* We're in a worker thread, use thread-local handle */
		pr_debug("Thread %d: Using thread-local CURL handle\n", get_thread_id());
		curl_handle = get_thread_curl_handle();
		if (!curl_handle) {
			pr_err("Failed to get thread-local curl handle for thread %d\n", get_thread_id());
			free(error_response.memory);
			return -1;
		}
	} else {
		/* We're in the main thread/process, use process-local handle */
		pr_debug("Main thread (PID %d): Using process-local CURL handle\n", getpid());
		curl_handle = get_curl_handle_for_current_process();
		if (!curl_handle) {
			pr_err("Failed to get curl handle for PID %d, falling back to one-time handle\n", getpid());

			/* Fall back to a one-time handle */
			curl_handle = curl_easy_init();
			if (!curl_handle) {
				pr_err("Failed to initialize curl easy handle\n");
				free(error_response.memory);
				return -1;
			}

			set_fixed_curl_options(curl_handle);
		} else {
			/* Reset the handle for reuse */
			curl_easy_reset(curl_handle);
			set_fixed_curl_options(curl_handle);
		}
	}

	/* Set variable options for each request */
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_RANGE, range_header);
	curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 0L);

	/* Set up callbacks with context */
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_router_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&fetch_ctx);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *)&fetch_ctx);

	/* Build authentication headers via auth dispatcher */
	{
		char auth_host[512];
		char auth_canonical_uri[1024];
		char range_header_value[64];

		/* Construct auth host (must match URL) */
		if (opts.express_one_zone) {
			/* Express One Zone: always virtual-hosted */
			snprintf(auth_host, sizeof(auth_host), "%s.%s",
				 opts.object_storage_bucket, hostname);
		} else if (opts.object_storage_path_style ||
			   !opts.object_storage_bucket || !opts.object_storage_bucket[0]) {
			/* Path-style or no bucket: host = hostname only */
			snprintf(auth_host, sizeof(auth_host), "%s", hostname);
		} else {
			/* Virtual-hosted: host = bucket.hostname */
			snprintf(auth_host, sizeof(auth_host), "%s.%s",
				 opts.object_storage_bucket, hostname);
		}
		/* Strip trailing slash */
		{
			size_t hlen = strlen(auth_host);
			if (hlen > 0 && auth_host[hlen - 1] == '/')
				auth_host[hlen - 1] = '\0';
		}

		/* Construct canonical URI (must match URL path) */
		if (!opts.express_one_zone && opts.object_storage_path_style &&
		    opts.object_storage_bucket && opts.object_storage_bucket[0]) {
			snprintf(auth_canonical_uri, sizeof(auth_canonical_uri), "/%s/%s",
				 opts.object_storage_bucket, full_object_path);
		} else {
			snprintf(auth_canonical_uri, sizeof(auth_canonical_uri), "/%s", full_object_path);
		}

		snprintf(range_header_value, sizeof(range_header_value), "bytes=%lu-%lu",
			 offset, offset + length - 1);

		/*
		 * Multipart-parallel dispatch: for worker-thread fetches whose
		 * range exceeds the single-stream's per-connection ceiling,
		 * split into N concurrent sub-streams across distinct S3 edge
		 * IPs. Falls through to the existing single-handle path on
		 * any setup failure so callers always get a result.
		 */
		if (!is_main_thread() && length >= MULTIPART_DL_THRESHOLD) {
			unsigned long mp_got = 0;
			int mp_rc;

			clock_gettime(CLOCK_MONOTONIC, &fetch_start);
			OBJSTOR_FETCH_START_LOG(object_key, offset, length, source);

			mp_rc = _fetch_range_multipart(url, auth_host,
						       auth_canonical_uri,
						       offset, length, buffer,
						       &mp_got);

			clock_gettime(CLOCK_MONOTONIC, &fetch_end);
			fetch_duration_ms = (fetch_end.tv_sec - fetch_start.tv_sec) * 1000.0 +
					    (fetch_end.tv_nsec - fetch_start.tv_nsec) / 1000000.0;
			OBJSTOR_FETCH_DONE_LOG(object_key, offset, length,
					       fetch_duration_ms, "", "", source);
			pr_info("multipart_fetch: src=%s len=%lu got=%lu total_ms=%.1f "
				"throughput_mbps=%.2f rc=%d\n",
				source, length, mp_got, fetch_duration_ms,
				fetch_duration_ms > 0 ? ((double)mp_got / 1024.0 / 1024.0) /
							 (fetch_duration_ms / 1000.0)
						      : 0.0,
				mp_rc);

			if (mp_rc == 0) {
				if (out_got)
					*out_got = mp_got;
				free(error_response.memory);
				return 0;
			}
			/* On failure fall through to the single-handle path so
			 * the caller still has a chance via the legacy fetch. */
			pr_warn("multipart fetch failed (rc=%d), falling back to single-handle\n",
				mp_rc);
		}

		if (_build_auth_headers("GET", auth_host, auth_canonical_uri, NULL,
				       EMPTY_PAYLOAD_HASH, range_header_value, -1, &headers) != 0) {
			free(error_response.memory);
			return -1;
		}
		if (headers)
			curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
	}

	pr_debug("Fetching range %s from %s\n", range_header, url);

	/* Log fetch start for simulation and record start time */
	clock_gettime(CLOCK_MONOTONIC, &fetch_start);
	OBJSTOR_FETCH_START_LOG(object_key, offset, length, source);

	/* Perform the request */
	res = curl_easy_perform(curl_handle);

	/* Get HTTP status code */
	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

	if (res != CURLE_OK || http_code >= 400) {
		OBJSTOR_FETCH_ERROR_LOG(object_key, offset, length, (int)http_code, source);
		pr_err("curl_easy_perform() failed: %s (URL: %s, Range: %s, HTTP Code: %ld)\n",
		       curl_easy_strerror(res), url, range_header, http_code);

		/* If we got an HTTP error response, capture the error body */
		if (res == CURLE_OK && http_code >= 400) {
			if (error_response.size > 0) {
				pr_err("--- Server Error Response (HTTP %ld) ---\n", http_code);
				pr_err("%.*s\n", (int)error_response.size, error_response.memory);
				pr_err("---------------------------\n");
			}
		}

		/* If using a reused handle and got an error, try with a fresh handle */
		if (!is_main_thread()) {
			pr_err("Thread %d: curl_easy_perform failed, not retrying\n", get_thread_id());
			free(error_response.memory);
			return -1;
		} else if (curl_handle == get_curl_handle_for_current_process()) {
			pr_warn("Retrying with a fresh connection\n");

			/* Clean up the existing handle */
			cleanup_curl_handle_for_process(getpid());

			/* Try reinitializing curl again */
			if (reinitialize_curl_for_lazy_pages() != 0) {
				pr_err("Failed to reinitialize curl before retry\n");
			}

			/* Create a new one-time handle */
			retry_handle = curl_easy_init();
			if (!retry_handle) {
				pr_err("Failed to initialize retry curl handle\n");
				free(error_response.memory);
				return -1;
			}

			/* Set all options again */
			set_fixed_curl_options(retry_handle);
			curl_easy_setopt(retry_handle, CURLOPT_FAILONERROR, 0L);
			curl_easy_setopt(retry_handle, CURLOPT_URL, url);
			curl_easy_setopt(retry_handle, CURLOPT_RANGE, range_header);

			/* Reset fetch context for retry */
			fetch_ctx.got_error = 0;
			fetch_ctx.x_cache[0] = '\0';
			fetch_ctx.x_amz_cf_pop[0] = '\0';
			error_response.size = 0;
			curl_easy_setopt(retry_handle, CURLOPT_WRITEFUNCTION, write_router_callback);
			curl_easy_setopt(retry_handle, CURLOPT_WRITEDATA, (void *)&fetch_ctx);
			curl_easy_setopt(retry_handle, CURLOPT_HEADERFUNCTION, header_callback);
			curl_easy_setopt(retry_handle, CURLOPT_HEADERDATA, (void *)&fetch_ctx);

			/* Apply headers for retry if we're using Express One Zone */
			if (headers) {
				curl_easy_setopt(retry_handle, CURLOPT_HTTPHEADER, headers);
			}

			/* Reset chunk size for retry */
			chunk.size = 0;

			/* Retry the request */
			res = curl_easy_perform(retry_handle);
			curl_easy_getinfo(retry_handle, CURLINFO_RESPONSE_CODE, &http_code);

			/* Check if retry succeeded */
			if (res != CURLE_OK || http_code >= 400) {
				pr_err("Retry also failed: %s (HTTP Code: %ld)\n", curl_easy_strerror(res), http_code);

				if (error_response.size > 0) {
					pr_err("--- Retry Error Response (HTTP %ld) ---\n", http_code);
					pr_err("%.*s\n", (int)error_response.size, error_response.memory);
					pr_err("---------------------------\n");
				}

				curl_easy_cleanup(retry_handle);
				free(error_response.memory);
				return -1;
			}

			/* Check size */
			if (chunk.size != length) {
				pr_err("Object Storage fetch: Received size mismatch (Expected %lu, Got %zu)\n", length,
				       chunk.size);
				curl_easy_cleanup(retry_handle);
				free(error_response.memory);
				return -1;
			}

			/* Cleanup the temporary handle */
			curl_easy_cleanup(retry_handle);

			/* Successfully recovered */
			pr_info("Recovery successful, creating new persistent handle\n");
			get_curl_handle_for_current_process();

			free(error_response.memory);
			ret = 0;
			goto cleanup;
		} else {
			/* One-time handle failed */
			curl_easy_cleanup(curl_handle);
			free(error_response.memory);
			return -1;
		}
	}

	/* Check HTTP status code for success */
	if (http_code != 206) {
		pr_warn("Expected HTTP 206 Partial Content, but received %ld\n", http_code);
	}

	/*
	 * Check if the received size matches the requested length.
	 *
	 * A short read is NOT a transport error — it means the requested
	 * range extended past the end of the object. S3 responds with
	 * HTTP 206 Partial Content and returns only the available bytes.
	 * Callers that issue speculative read-ahead windows (e.g. the
	 * read-ahead buffer in maybe_read_page_object_storage) will often
	 * trip this near the end of pages-*.img. Treating it as a hard
	 * error and destroying the curl handle is what used to happen,
	 * and it cost ~100–900ms per subsequent GET (cold TLS handshake
	 * on a brand-new handle). Keep the handle alive so the next real
	 * read reuses the warm TLS session; the caller is expected to
	 * retry with a smaller length if it actually needed more data.
	 */
	/*
	 * Short read = requested range extended past EOF. S3 responds with
	 * HTTP 206 and only the available bytes. Return success; the caller
	 * can check *out_got (via the _short variant) to see the actual
	 * byte count. The public fetch_range wrapper above turns it back
	 * into -1 for callers that require an exact match.
	 */
	if (out_got)
		*out_got = chunk.size;

	/* Calculate fetch duration and log completion */
	clock_gettime(CLOCK_MONOTONIC, &fetch_end);
	fetch_duration_ms = (fetch_end.tv_sec - fetch_start.tv_sec) * 1000.0 +
			    (fetch_end.tv_nsec - fetch_start.tv_nsec) / 1000000.0;
	OBJSTOR_FETCH_DONE_LOG(object_key, offset, length, fetch_duration_ms,
			       fetch_ctx.x_cache, fetch_ctx.x_amz_cf_pop, source);

	/*
	 * Per-fetch sub-step timing via libcurl. Distinguishes
	 *   namelookup  : DNS lookup
	 *   connect     : TCP handshake (0 if connection reused)
	 *   appconnect  : TLS handshake (0 if connection reused)
	 *   pretransfer : authn + setopt path (rarely interesting)
	 *   starttransfer: time-to-first-byte (server processing + 1 RTT)
	 *   total       : full fetch wall time
	 *   body_ms     := total - starttransfer  (pure transfer phase, isolates cwnd effect)
	 * If connect_ms > 0 → connection NOT reused this call.
	 * If body_ms throughput is much lower than total throughput → cwnd-stuck issue.
	 */
	{
		double t_namelookup = 0, t_connect = 0, t_appconnect = 0;
		double t_pretransfer = 0, t_starttransfer = 0, t_total = 0;
		curl_off_t dl_size = 0, dl_speed = 0;
		double body_ms, body_mbps = 0.0;

		curl_easy_getinfo(curl_handle, CURLINFO_NAMELOOKUP_TIME, &t_namelookup);
		curl_easy_getinfo(curl_handle, CURLINFO_CONNECT_TIME, &t_connect);
		curl_easy_getinfo(curl_handle, CURLINFO_APPCONNECT_TIME, &t_appconnect);
		curl_easy_getinfo(curl_handle, CURLINFO_PRETRANSFER_TIME, &t_pretransfer);
		curl_easy_getinfo(curl_handle, CURLINFO_STARTTRANSFER_TIME, &t_starttransfer);
		curl_easy_getinfo(curl_handle, CURLINFO_TOTAL_TIME, &t_total);
		curl_easy_getinfo(curl_handle, CURLINFO_SIZE_DOWNLOAD_T, &dl_size);
		curl_easy_getinfo(curl_handle, CURLINFO_SPEED_DOWNLOAD_T, &dl_speed);

		body_ms = (t_total - t_starttransfer) * 1000.0;
		if (body_ms > 0)
			body_mbps = ((double)dl_size / 1024.0 / 1024.0) / (body_ms / 1000.0);

		pr_info("curl_timing: src=%s len=%lu dl=%ld total_ms=%.1f "
			"namelookup_ms=%.1f connect_ms=%.1f appconnect_ms=%.1f "
			"pretransfer_ms=%.1f starttransfer_ms=%.1f body_ms=%.1f "
			"body_mbps=%.2f avg_speed_mbps=%.2f reused=%s\n",
			source, length, (long)dl_size, t_total * 1000.0,
			t_namelookup * 1000.0, t_connect * 1000.0, t_appconnect * 1000.0,
			t_pretransfer * 1000.0, t_starttransfer * 1000.0, body_ms,
			body_mbps, ((double)dl_speed / 1024.0 / 1024.0),
			t_connect == 0.0 ? "yes" : "no");
	}

	pr_debug("Successfully fetched %zu bytes (range %s) from %s\n", chunk.size, range_header, url);

	/* Handle cleanup based on handle type */
	if (!is_main_thread()) {
		pr_debug("Thread %d: Keeping thread-local handle for reuse\n", get_thread_id());
	} else {
		if (curl_handle != get_curl_handle_for_current_process()) {
			curl_easy_cleanup(curl_handle);
		} else {
			update_handle_stats();
		}
	}

	free(error_response.memory);
	ret = 0;

cleanup:
	if (headers) {
		curl_slist_free_all(headers);
	}
	return ret;
}

int object_storage_cleanup_and_prepare_for_lazy_pages(void)
{
	if (!opts.enable_object_storage)
		return 0;

	pr_info("Cleaning up curl resources after prepare_mappings (PID: %d)\n", getpid());

	/* Clean up all curl resources to prevent fd conflicts with restore process */
	cleanup_all_curl_resources();

	/* Reset lazy-pages mode flag */
	g_is_lazy_pages_context = 0;

	return 0;
}