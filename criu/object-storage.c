#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>  // for getpid()
#include <stdlib.h>  // for malloc, free
#include <time.h>    // for time()

#include "common/config.h"
#include "common/compiler.h"
#include "log.h"
#include "cr_options.h"
#include "object-storage.h"

/* Structure to hold data during libcurl transfer */
struct MemoryStruct {
	char *memory;
	size_t size;     /* current size of the downloaded data */
	size_t capacity; /* capacity of the buffer */
};

/* Structure to hold process-specific curl handle */
struct curl_handle_entry {
	pid_t pid;               /* Process ID */
	CURL *handle;            /* Curl handle for this process */
	time_t last_used;        /* Last time this handle was used */
	int request_count;       /* Number of requests made with this handle */
	struct curl_handle_entry *next;  /* Next entry in linked list */
};

/* Global handle storage (linked list head) */
static struct curl_handle_entry *g_curl_handles = NULL;

/* Flag to track if this is a lazy-pages context */
static int g_is_lazy_pages_context = 0;

/* Flag to track if curl was initialized in this process */
static int g_curl_initialized_in_this_process = 0;

/* Mutex-like mechanism might be needed here for multi-threading,
 * but CRIU's process model may not require it.
 */

/* Callback function for libcurl to write received data */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	// Ensure buffer has enough space (consider realloc if needed, but for fixed-size fetch, check capacity)
	if (mem->size + realsize > mem->capacity) {
		pr_err("Object Storage: Received data exceeds buffer capacity (%zu > %zu)\n",
		       mem->size + realsize, mem->capacity);
		return 0; // Indicate error by returning a size different from what was passed
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;

	return realsize;
}

/* Get curl handle for current process (create if not exists) */
static CURL *get_curl_handle_for_current_process(void)
{
	pid_t current_pid = getpid();
	struct curl_handle_entry *entry = g_curl_handles;
	CURL *new_handle;
	
	// Search for existing handle for this PID
	while (entry) {
		if (entry->pid == current_pid) {
			pr_debug("Reusing existing curl handle for PID %d (handle: %p, requests: %d)\n", 
				 current_pid, entry->handle, entry->request_count);
			return entry->handle;
		}
		entry = entry->next;
	}
	
	// No handle found, create a new one
	pr_info("Creating new curl handle for PID %d\n", current_pid);
	new_handle = curl_easy_init();
	if (!new_handle) {
		pr_err("Failed to initialize curl handle for PID %d\n", current_pid);
		return NULL;
	}
	
	// Create new entry
	entry = malloc(sizeof(struct curl_handle_entry));
	if (!entry) {
		curl_easy_cleanup(new_handle);
		pr_err("Failed to allocate memory for curl handle entry (PID %d)\n", current_pid);
		return NULL;
	}
	
	// Initialize entry
	entry->pid = current_pid;
	entry->handle = new_handle;
	entry->last_used = time(NULL);
	entry->request_count = 0;
	
	// Add to global list
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
			pr_debug("Updated curl handle stats for PID %d (requests: %d)\n", 
				 current_pid, entry->request_count);
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
			pr_info("Cleaning up curl handle for PID %d (handle: %p, requests: %d)\n", 
				pid, entry->handle, entry->request_count);
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

/* Clean up all curl handles and resources for the current process */
static void cleanup_all_curl_resources(void)
{
	// Clean up all handles in the list
	struct curl_handle_entry *entry = g_curl_handles;
	struct curl_handle_entry *next;
	
	while (entry) {
		next = entry->next;
		pr_info("Cleaning up curl handle for PID %d (handle: %p, requests: %d)\n", 
			entry->pid, entry->handle, entry->request_count);
		curl_easy_cleanup(entry->handle);
		free(entry);
		entry = next;
	}
	
	g_curl_handles = NULL;
	
	// Only clean up global resources if we initialized them in this process
	if (g_curl_initialized_in_this_process) {
		curl_global_cleanup();
		pr_info("Object Storage client global resources cleaned up (PID: %d)\n", getpid());
		g_curl_initialized_in_this_process = 0;
	}
}

/* Re-initialize curl for lazy-pages context */
static int reinitialize_curl_for_lazy_pages(void)
{
	CURLcode res;
	
	// Clean up all existing curl resources first
	cleanup_all_curl_resources();
	
	// Re-initialize curl
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
	// We can infer we're in lazy-pages context if:
	// 1. We've never seen this process before (first request in restored process)
	// 2. We're not in a process that already knows it's the lazy-pages context

	pid_t current_pid = getpid();
	struct curl_handle_entry *entry = g_curl_handles;
	int found = 0;
	
	// Check if we already have a handle for this process
	while (entry) {
		if (entry->pid == current_pid) {
			found = 1;
			break;
		}
		entry = entry->next;
	}
	
	// If this is the first request in this process and we're not in a known lazy-pages context,
	// we might need to reinitialize
	if (!found && !g_is_lazy_pages_context) {
		pr_info("Detected possible lazy-pages context in PID %d, reinitializing curl\n", current_pid);
		return reinitialize_curl_for_lazy_pages();
	}
	
	return 0;
}

int object_storage_init(void)
{
	CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (res != CURLE_OK) {
		pr_err("curl_global_init() failed: %s\n", curl_easy_strerror(res));
		return -1;
	}
	
	// Mark that we initialized curl in this process
	g_curl_initialized_in_this_process = 1;
	
	// Initialize handle storage
	g_curl_handles = NULL;
	
	// Register cleanup handler for this process
	if (atexit(cleanup_current_process_curl_handle) != 0) {
		pr_warn("Failed to register curl handle cleanup handler\n");
		// Continue anyway, we'll handle cleanup in object_storage_cleanup
	}
	
	pr_info("Object Storage client initialized (libcurl, PID: %d)\n", getpid());
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
	char range_header[64];
	char url[1024]; // Adjust size as needed
	char normalized_prefix[256]; // Buffer for normalized prefix
	char full_object_path[512]; // Buffer for prefix + key - Moved declaration to top
	const char *endpoint_url;
	const char *scheme = "https://"; // Default scheme
	CURL *retry_handle = NULL; /* 변수 선언을 함수 시작 부분으로 이동 */

	// --- DEBUG --- Entry point check
	pr_info("PID %d: Entered object_storage_fetch_range (Key: %s, Offset: %lu, Len: %lu)\n",
		getpid(), object_key, offset, length);

	// Check if we need to reinitialize curl for lazy-pages context
	if (check_and_reinitialize_for_lazy_pages() != 0) {
		pr_err("Failed to reinitialize curl for lazy-pages context\n");
		// Continue anyway, we'll try to use the one-time handle approach
	}

	// Basic validation
	if (!opts.object_storage_endpoint_url || !opts.object_storage_bucket || !object_key || !buffer || length == 0) {
		pr_err("Object Storage fetch range: Invalid arguments provided.\n");
		return -1;
	}

	// Prepare memory structure for received data
	chunk.memory = buffer;
	chunk.size = 0;
	chunk.capacity = length;

	// Normalize the object prefix
	if (opts.object_storage_object_prefix) {
		const char *original_prefix = opts.object_storage_object_prefix;
		size_t prefix_len = strlen(original_prefix);
		if (prefix_len == 1 && original_prefix[0] == '/') {
			// Prefix is just "/", treat as empty
			normalized_prefix[0] = '\0';
		} else if (prefix_len > 0) {
			const char *start = original_prefix;
			size_t copy_len = prefix_len;
			// Remove leading '/' if present
			if (original_prefix[0] == '/') {
				start++;
				copy_len--;
			}
			// Copy the prefix (without leading '/')
			// strncpy(normalized_prefix, start, copy_len);
			// normalized_prefix[copy_len] = '\0'; // Null-terminate
			// Use snprintf for safer string copy
			snprintf(normalized_prefix, sizeof(normalized_prefix), "%.*s", (int)copy_len, start);

			// Ensure trailing '/' if not empty
			if (copy_len > 0 && normalized_prefix[copy_len - 1] != '/') {
				// Need to check strlen again after snprintf, as it might truncate
				size_t current_len = strlen(normalized_prefix);
				if (current_len < sizeof(normalized_prefix) - 1) { // Check buffer space for '/' and null terminator
					normalized_prefix[current_len] = '/';
					normalized_prefix[current_len + 1] = '\0';
				} else {
					pr_warn("Object prefix buffer too small to add trailing slash: %s\n", original_prefix);
				}
			}
		} else {
			// Prefix is empty
			normalized_prefix[0] = '\0';
		}
	} else {
		normalized_prefix[0] = '\0';
	}

	// Handle endpoint URL scheme
	endpoint_url = opts.object_storage_endpoint_url;
	if (strncmp(endpoint_url, "https://", 8) == 0) {
		scheme = ""; // Scheme already present
	} else if (strncmp(endpoint_url, "http://", 7) == 0) {
		scheme = ""; // Scheme already present
	}

	snprintf(full_object_path, sizeof(full_object_path), "%s%s", normalized_prefix, object_key);

	// Construct the final URL
	snprintf(url, sizeof(url), "%s%s/%s/%s",
		 scheme,
		 endpoint_url,
		 opts.object_storage_bucket,
		 full_object_path); // Use combined path

	// Prepare the Range header
	snprintf(range_header, sizeof(range_header), "%lu-%lu", offset, offset + length - 1);

	// Get the reusable curl handle for this process
	curl_handle = get_curl_handle_for_current_process();
	if (!curl_handle) {
		pr_err("Failed to get curl handle for PID %d, falling back to one-time handle\n", getpid());
		
		// Fall back to a one-time handle as before
		curl_handle = curl_easy_init();
		if (!curl_handle) {
			pr_err("Failed to initialize curl easy handle\n");
			return -1;
		}
	} else {
		// Reset the handle for reuse (keeps connections if possible)
		curl_easy_reset(curl_handle);
	}

	// Set libcurl options
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_RANGE, range_header);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1L); // Fail on 4xx/5xx errors
	curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L); // Follow redirects
	
	// TCP keepalive settings
	curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPALIVE, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPIDLE, 120L);  // Seconds the connection needs to remain idle before sending keepalive
	curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPINTVL, 60L);  // Interval in seconds between keepalive probes
	
	// Optional connection caching/reuse settings
	curl_easy_setopt(curl_handle, CURLOPT_FORBID_REUSE, 0L);    // Allow connection reuse
	curl_easy_setopt(curl_handle, CURLOPT_FRESH_CONNECT, 0L);   // Use cached connection if available
	
	// Critical: Avoid using stdin (fd 0)
	curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L);        // Don't use signals (which might use fd 0)
	
	// Add options for timeout, SSL verification etc. as needed
	// curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 30L);        // Timeout for the entire request
	// curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 10L); // Timeout for the connection phase
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);  // Verify hostname in cert

	pr_debug("Fetching range %s from %s\n", range_header, url);
	// --- DEBUG --- URL and Range check
	pr_info("Libcurl Request - URL: %s\n", url);
	pr_info("Libcurl Request - Range: %s\n", range_header);

	// Perform the request
	res = curl_easy_perform(curl_handle);

	if (res != CURLE_OK) {
		pr_err("curl_easy_perform() failed: %s (URL: %s, Range: %s)\n",
		       curl_easy_strerror(res), url, range_header);
		
		// If using a reused handle and got an error, try with a fresh handle
		if (curl_handle == get_curl_handle_for_current_process()) {
			pr_warn("Retrying with a fresh connection\n");
			
			// Clean up the existing handle
			cleanup_curl_handle_for_process(getpid());
			
			// Try reinitializing curl again (in case the error was related to curl's global state)
			if (reinitialize_curl_for_lazy_pages() != 0) {
				pr_err("Failed to reinitialize curl before retry\n");
				// Continue anyway with one-time handle
			}
			
			// Create a new one-time handle
			retry_handle = curl_easy_init();
			if (!retry_handle) {
				pr_err("Failed to initialize retry curl handle\n");
				return -1;
			}
			
			// Set all options again
			curl_easy_setopt(retry_handle, CURLOPT_URL, url);
			curl_easy_setopt(retry_handle, CURLOPT_HTTPGET, 1L);
			curl_easy_setopt(retry_handle, CURLOPT_RANGE, range_header);
			curl_easy_setopt(retry_handle, CURLOPT_WRITEFUNCTION, write_callback);
			curl_easy_setopt(retry_handle, CURLOPT_WRITEDATA, (void *)&chunk);
			curl_easy_setopt(retry_handle, CURLOPT_FAILONERROR, 1L);
			curl_easy_setopt(retry_handle, CURLOPT_FOLLOWLOCATION, 1L);
			curl_easy_setopt(retry_handle, CURLOPT_SSL_VERIFYHOST, 2L);
			curl_easy_setopt(retry_handle, CURLOPT_NOSIGNAL, 1L);
			
			// Retry the request
			res = curl_easy_perform(retry_handle);
			
			// Check if retry succeeded
			if (res != CURLE_OK) {
				pr_err("Retry also failed: %s\n", curl_easy_strerror(res));
				curl_easy_cleanup(retry_handle);
				return -1;
			}
			
			// Get status code
			curl_easy_getinfo(retry_handle, CURLINFO_RESPONSE_CODE, &http_code);
			
			// Check size
			if (chunk.size != length) {
				pr_err("Object Storage fetch: Received size mismatch (Expected %lu, Got %zu)\n", length, chunk.size);
				curl_easy_cleanup(retry_handle);
				return -1;
			}
			
			// Cleanup the temporary handle
			curl_easy_cleanup(retry_handle);
			
			// Successfully recovered, continue with a new persistent handle next time
			pr_info("Recovery successful, creating new persistent handle\n");
			get_curl_handle_for_current_process(); // Create a new persistent handle
			
			return 0;
		} else {
			// One-time handle failed
			curl_easy_cleanup(curl_handle);
			return -1;
		}
	}

	// Check HTTP status code (optional, as FAILONERROR is set)
	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
	// --- DEBUG --- Response code check
	pr_info("Libcurl Response - HTTP Code: %ld\n", http_code);
	if (http_code != 206) { // 206 Partial Content is expected for range requests
		pr_warn("Expected HTTP 206 Partial Content, but received %ld\n", http_code);
		// Depending on the error handling strategy, this might still be considered a failure
	}

	// Check if the received size matches the requested length
	// --- DEBUG --- Received size check
	pr_info("Libcurl Response - Received Bytes: %zu (Expected: %lu)\n", chunk.size, length);
	if (chunk.size != length) {
		pr_err("Object Storage fetch: Received size mismatch (Expected %lu, Got %zu)\n", length, chunk.size);
		
		// If using a reused handle, clean it up since something's wrong
		if (curl_handle == get_curl_handle_for_current_process()) {
			cleanup_curl_handle_for_process(getpid());
		} else {
			curl_easy_cleanup(curl_handle);
		}
		
		return -1;
	}

	pr_debug("Successfully fetched %zu bytes (range %s) from %s\n", chunk.size, range_header, url);

	// If this was a one-time handle, clean it up
	if (curl_handle != get_curl_handle_for_current_process()) {
		curl_easy_cleanup(curl_handle);
	} else {
		// Update stats for the persistent handle
		update_handle_stats();
	}

	return 0; // Success
}

/*
 * Special function to clean up curl resources after prepare_mappings
 * and set a flag to indicate that lazy-pages mode needs to reinitialize curl
 */
int object_storage_cleanup_and_prepare_for_lazy_pages(void)
{
	if (!opts.enable_object_storage)
		return 0;

	pr_info("Cleaning up curl resources after prepare_mappings (PID: %d)\n", getpid());
	
	// Clean up all curl resources to prevent fd conflicts with restore process
	cleanup_all_curl_resources();
	
	// Set lazy-pages mode flag
	g_is_lazy_pages_context = 0;
	
	// When lazy-pages kicks in, it will detect the need to reinitialize
	return 0;
} 