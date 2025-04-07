#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

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

int object_storage_init(void)
{
	CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (res != CURLE_OK) {
		pr_err("curl_global_init() failed: %s\n", curl_easy_strerror(res));
		return -1;
	}
	pr_info("Object Storage client initialized (libcurl)\n");
	return 0;
}

void object_storage_cleanup(void)
{
	curl_global_cleanup();
	pr_info("Object Storage client cleaned up (libcurl)\n");
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

	// --- DEBUG --- Entry point check
	pr_info("Entered object_storage_fetch_range (Key: %s, Offset: %lu, Len: %lu)\n",
			object_key, offset, length);

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

	curl_handle = curl_easy_init();
	if (!curl_handle) {
		pr_err("Failed to initialize curl easy handle\n");
		return -1;
	}

	// Set libcurl options
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_RANGE, range_header);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1L); // Fail on 4xx/5xx errors
	curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L); // Follow redirects
	// Add options for timeout, SSL verification etc. as needed
	// curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 10L); // Example timeout
	// curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L); // Verify SSL peer
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L); // Verify hostname in cert

	pr_debug("Fetching range %s from %s\n", range_header, url);
	// --- DEBUG --- URL and Range check
	pr_info("Libcurl Request - URL: %s\n", url);
	pr_info("Libcurl Request - Range: %s\n", range_header);

	// Perform the request
	res = curl_easy_perform(curl_handle);

	if (res != CURLE_OK) {
		pr_err("curl_easy_perform() failed: %s (URL: %s, Range: %s)\n",
		       curl_easy_strerror(res), url, range_header);
		curl_easy_cleanup(curl_handle);
		return -1;
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
		curl_easy_cleanup(curl_handle);
		return -1;
	}

	pr_debug("Successfully fetched %zu bytes (range %s) from %s\n", chunk.size, range_header, url);

	// Cleanup
	curl_easy_cleanup(curl_handle);

	return 0; // Success
} 