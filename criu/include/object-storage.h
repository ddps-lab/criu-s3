#ifndef __CR_OBJECT_STORAGE_H__
#define __CR_OBJECT_STORAGE_H__

/*
 * Initialize the object storage client
 * Returns 0 on success, -1 on failure
 */
int object_storage_init(void);

/*
 * Fetch a range of bytes from an object in object storage
 *
 * @param object_key: The key/path of the object in the bucket
 * @param offset: The starting byte offset to fetch
 * @param length: The number of bytes to fetch
 * @param buffer: Buffer to store the fetched data (must be at least 'length' bytes)
 *
 * Returns 0 on success, -1 on failure
 */
int object_storage_fetch_range(const char *object_key, unsigned long offset, unsigned long length, void *buffer);

/*
 * Clean up the object storage client and release resources
 */
void object_storage_cleanup(void);

/*
 * Special function to clean up curl resources after prepare_mappings
 * and prepare for lazy-pages mode
 *
 * Returns 0 on success, -1 on failure
 */
int object_storage_cleanup_and_prepare_for_lazy_pages(void);

#endif /* __CR_OBJECT_STORAGE_H__ */