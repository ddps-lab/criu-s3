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

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "common/config.h"
#include "common/compiler.h"
#include "log.h"
#include "cr_options.h"
#include "object-storage.h"

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
	time_t last_used;
	int request_count;
	struct curl_thread_handle *next;
};

/* Structure to hold both data and error buffers */
struct FetchContext {
	struct MemoryStruct *data_chunk;
	struct MemoryStruct *error_chunk;
	int got_error;
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
static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
	struct FetchContext *ctx = (struct FetchContext *)userdata;
	size_t total_size = size * nitems;

	/* Check if this is the status line */
	if (strncmp(buffer, "HTTP/", 5) == 0) {
		int status_code = 0;
		if (sscanf(buffer, "HTTP/%*d.%*d %d", &status_code) == 1) {
			if (status_code >= 400) {
				ctx->got_error = 1;
				pr_debug("Detected error status code: %d\n", status_code);
			}
		}
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
		/* Remove from global thread handle list */
		pthread_mutex_lock(&g_thread_handles_mutex);
		pp = &g_thread_handles;
		while (*pp) {
			entry = *pp;
			if (pthread_equal(entry->thread_id, thread_id)) {
				*pp = entry->next;
				pr_debug("Thread %lu: Cleaning up thread-local CURL handle (requests: %d)\n",
					 (unsigned long)thread_id, entry->request_count);
				free(entry);
				break;
			}
			pp = &entry->next;
		}
		pthread_mutex_unlock(&g_thread_handles_mutex);

		curl_easy_cleanup(curl_handle);
	}
}

/* Initialize thread-local storage key */
static void init_curl_thread_key(void)
{
	pthread_key_create(&g_curl_thread_key, curl_thread_handle_destructor);
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

	/* Store in thread-local storage */
	pthread_setspecific(g_curl_thread_key, handle);

	/* Add to global thread handle list for tracking */
	entry = malloc(sizeof(struct curl_thread_handle));
	if (entry) {
		entry->thread_id = thread_id;
		entry->handle = handle;
		entry->last_used = time(NULL);
		entry->request_count = 0;

		pthread_mutex_lock(&g_thread_handles_mutex);
		entry->next = g_thread_handles;
		g_thread_handles = entry;
		pthread_mutex_unlock(&g_thread_handles_mutex);

		pr_info("Thread TID=%d (pthread_id=%lu): Created new thread-local CURL handle\n", get_thread_id(),
			(unsigned long)thread_id);
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

	pr_info("Creating new S3 Express One Zone session...\n");

	if (!opts.aws_access_key || !opts.aws_secret_key || !opts.aws_region) {
		pr_err("Missing AWS credentials or region for Express One Zone session\n");
		return -1;
	}

	payload_len = strlen(payload);
	now = time(NULL);
	tm_gmt = gmtime(&now);
	strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", tm_gmt);
	strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", tm_gmt);

	snprintf(session_url, sizeof(session_url), "https://%s.%s/?session", opts.object_storage_bucket,
		 opts.object_storage_endpoint_url);
	pr_info("Session URL: %s\n", session_url);

	_sha256_hex(payload, payload_len, payload_hash);

	snprintf(canonical_headers, sizeof(canonical_headers),
		 "host:%s.%s\n"
		 "x-amz-content-sha256:%s\n"
		 "x-amz-create-session-mode:ReadWrite\n"
		 "x-amz-date:%s\n",
		 opts.object_storage_bucket, opts.object_storage_endpoint_url, payload_hash, amz_date);

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

	pr_info("Successfully created S3 Express One Zone session. Expires at %ld\n", g_session_expiration);

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

	return 0;
}

void object_storage_cleanup(void)
{
	cleanup_all_curl_resources();
	pr_info("Object Storage client cleaned up (libcurl, PID: %d)\n", getpid());
}

int object_storage_fetch_range(const char *object_key, unsigned long offset, unsigned long length, void *buffer)
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
	const char *scheme = "https://";
	CURL *retry_handle = NULL;
	struct curl_slist *headers = NULL;
	int ret = -1;
	struct FetchContext fetch_ctx;

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

	/* Handle endpoint URL scheme */
	endpoint_url = opts.object_storage_endpoint_url;
	if (strncmp(endpoint_url, "https://", 8) == 0) {
		scheme = "";
	} else if (strncmp(endpoint_url, "http://", 7) == 0) {
		scheme = "";
	}

	/* Check if object_key already contains the prefix to avoid duplication */
	if (normalized_prefix[0] != '\0' && strncmp(object_key, normalized_prefix, strlen(normalized_prefix)) == 0) {
		snprintf(full_object_path, sizeof(full_object_path), "%s", object_key);
		pr_debug("Object key already contains prefix, using as is: %s\n", full_object_path);
	} else {
		snprintf(full_object_path, sizeof(full_object_path), "%s%s", normalized_prefix, object_key);
		pr_debug("Prepended prefix to object key: %s\n", full_object_path);
	}

	/* Construct the final URL */
	if (opts.express_one_zone) {
		snprintf(url, sizeof(url), "https://%s.%s/%s", opts.object_storage_bucket,
			 opts.object_storage_endpoint_url, full_object_path);
	} else {
		endpoint_url = opts.object_storage_endpoint_url;
		if (strncmp(endpoint_url, "https://", 8) == 0) {
			scheme = "";
		} else if (strncmp(endpoint_url, "http://", 7) == 0) {
			scheme = "";
		}

		if (opts.object_storage_bucket && opts.object_storage_bucket[0] != '\0') {
			/* Use virtual-hosted-style for S3 */
			if (scheme[0] == '\0') {
				const char *hostname_start = endpoint_url;
				if (strncmp(endpoint_url, "https://", 8) == 0) {
					hostname_start = endpoint_url + 8;
				} else if (strncmp(endpoint_url, "http://", 7) == 0) {
					hostname_start = endpoint_url + 7;
				}
				snprintf(url, sizeof(url), "%.*s%s.%s/%s", (int)(hostname_start - endpoint_url),
					 endpoint_url, opts.object_storage_bucket, hostname_start, full_object_path);
			} else {
				snprintf(url, sizeof(url), "%s%s.%s/%s", scheme, opts.object_storage_bucket,
					 endpoint_url, full_object_path);
			}
		} else {
			/* No bucket - use direct endpoint URL */
			snprintf(url, sizeof(url), "%s%s/%s", scheme, endpoint_url, full_object_path);
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

	/* If AWS credentials are provided, set up authentication */
	if (opts.express_one_zone && opts.aws_access_key && opts.aws_secret_key) {
		/* Express One Zone: Use temporary session credentials and manual SigV4 */
		char session_header[2100];
		char amz_date[17];
		char date_stamp[9];
		char x_amz_date_header[64];
		char x_amz_content_sha256_header[100];
		char payload_hash[65];
		char canonical_uri[1024];
		char canonical_querystring[] = "";
		char canonical_headers[4096];
		char signed_headers[] = "host;range;x-amz-content-sha256;x-amz-date;x-amz-s3session-token";
		char canonical_request[8192];
		char canonical_request_hash[65];
		char string_to_sign[512];
		char credential_scope[128];
		char signature_hex[65];
		char auth_header[1024];
		char range_header_value[64];
		time_t now;
		struct tm *tm_gmt;
		const char *method = "GET";
		const char *service = "s3";
		const char *payload = "";
		size_t payload_len = 0;
		unsigned char *signing_key;
		unsigned int signing_key_len;
		unsigned char *signature_raw;
		unsigned int signature_raw_len;
		int i;

		pr_info("Using Express One Zone session credentials with manual SigV4\n");

		/* Get current time */
		now = time(NULL);
		tm_gmt = gmtime(&now);
		strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", tm_gmt);
		strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", tm_gmt);

		/* Calculate payload hash (empty for GET) */
		_sha256_hex(payload, payload_len, payload_hash);

		/* Prepare canonical URI (path part of URL) */
		snprintf(canonical_uri, sizeof(canonical_uri), "/%s", full_object_path);

		/* Prepare range header value */
		snprintf(range_header_value, sizeof(range_header_value), "bytes=%lu-%lu", offset,
			 offset + length - 1);

		/* Build canonical headers */
		snprintf(canonical_headers, sizeof(canonical_headers),
			 "host:%s.%s\n"
			 "range:%s\n"
			 "x-amz-content-sha256:%s\n"
			 "x-amz-date:%s\n"
			 "x-amz-s3session-token:%s\n",
			 opts.object_storage_bucket, opts.object_storage_endpoint_url, range_header_value, payload_hash,
			 amz_date, g_session_token);

		/* Build canonical request */
		snprintf(canonical_request, sizeof(canonical_request), "%s\n%s\n%s\n%s\n%s\n%s", method, canonical_uri,
			 canonical_querystring, canonical_headers, signed_headers, payload_hash);

		/* Calculate canonical request hash */
		_sha256_hex(canonical_request, strlen(canonical_request), canonical_request_hash);

		/* Build credential scope */
		snprintf(credential_scope, sizeof(credential_scope), "%s/%s/%s/aws4_request", date_stamp,
			 opts.aws_region, service);

		/* Build string to sign */
		snprintf(string_to_sign, sizeof(string_to_sign), "AWS4-HMAC-SHA256\n%s\n%s\n%s", amz_date,
			 credential_scope, canonical_request_hash);

		/* Calculate signature */
		signing_key =
			_get_signature_key(g_session_secret_key, date_stamp, opts.aws_region, service, &signing_key_len);
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
			free(error_response.memory);
			return -1;
		}

		/* Build Authorization header */
		snprintf(auth_header, sizeof(auth_header),
			 "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
			 g_session_access_key, credential_scope, signed_headers, signature_hex);

		/* Add headers */
		snprintf(x_amz_date_header, sizeof(x_amz_date_header), "X-Amz-Date: %s", amz_date);
		headers = curl_slist_append(headers, x_amz_date_header);

		snprintf(x_amz_content_sha256_header, sizeof(x_amz_content_sha256_header), "X-Amz-Content-Sha256: %s",
			 payload_hash);
		headers = curl_slist_append(headers, x_amz_content_sha256_header);

		snprintf(session_header, sizeof(session_header), "x-amz-s3session-token: %s", g_session_token);
		headers = curl_slist_append(headers, session_header);

		headers = curl_slist_append(headers, auth_header);

		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

		pr_info("Manual AWS SigV4 authentication configured for Express One Zone\n");
	} else if (opts.aws_access_key && opts.aws_secret_key) {
		/* Standard S3: Use provided IAM credentials */
		char userpwd[512];
		snprintf(userpwd, sizeof(userpwd), "%s:%s", opts.aws_access_key, opts.aws_secret_key);
		curl_easy_setopt(curl_handle, CURLOPT_USERPWD, userpwd);
	}

	pr_debug("Fetching range %s from %s\n", range_header, url);

	/* Perform the request */
	res = curl_easy_perform(curl_handle);

	/* Get HTTP status code */
	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

	if (res != CURLE_OK || http_code >= 400) {
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

	/* Check if the received size matches the requested length */
	if (chunk.size != length) {
		pr_err("Object Storage fetch: Received size mismatch (Expected %lu, Got %zu)\n", length, chunk.size);

		/* If using a reused handle, handle cleanup */
		if (!is_main_thread()) {
			pr_warn("Thread %d: Size mismatch, but keeping thread-local handle\n", get_thread_id());
		} else {
			if (curl_handle == get_curl_handle_for_current_process()) {
				cleanup_curl_handle_for_process(getpid());
			} else {
				curl_easy_cleanup(curl_handle);
			}
		}

		free(error_response.memory);
		ret = -1;
		goto cleanup;
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