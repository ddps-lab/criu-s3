#ifndef __CR_HASH_TABLE_H__
#define __CR_HASH_TABLE_H__

#include "common/list.h"

#define HASH_TABLE_BITS 8
#define HASH_TABLE_SIZE (1 << HASH_TABLE_BITS)  /* 256 buckets */

struct hash_node {
	int key;
	void *value;
	struct list_head node;
};

struct hash_table {
	struct list_head buckets[HASH_TABLE_SIZE];
	int count;
};

/* Hash function: simple modulo */
static inline unsigned int hash_func(int key) {
	return (unsigned int)key & (HASH_TABLE_SIZE - 1);
}

/* Initialize hash table */
static inline void hash_table_init(struct hash_table *ht) {
	int i;
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		INIT_LIST_HEAD(&ht->buckets[i]);
	}
	ht->count = 0;
}

/* Insert key-value pair - O(1) */
int hash_table_insert(struct hash_table *ht, int key, void *value);

/* Lookup by key - O(1) average */
void *hash_table_lookup(struct hash_table *ht, int key);

/* Remove by key - O(1) average */
int hash_table_remove(struct hash_table *ht, int key);

/* Cleanup */
void hash_table_cleanup(struct hash_table *ht);

#endif /* __CR_HASH_TABLE_H__ */
