#ifndef __CR_OBJECT_STORAGE_H__
#define __CR_OBJECT_STORAGE_H__

#include <stddef.h> // For size_t

// Initializes the object storage client (e.g., libcurl global init)
extern int object_storage_init(void);

// Cleans up the object storage client resources
extern void object_storage_cleanup(void);

// Cleans up curl resources after prepare_mappings and prepares for lazy-pages
extern int object_storage_cleanup_and_prepare_for_lazy_pages(void);

// Fetches a specific byte range from an object in the storage
// Returns 0 on success, negative value on failure.
extern int object_storage_fetch_range(const char *object_key,
                                      unsigned long offset,
                                      unsigned long length,
                                      void *buffer);

#endif /* __CR_OBJECT_STORAGE_H__ */ 