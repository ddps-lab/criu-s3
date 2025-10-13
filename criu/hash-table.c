#include <errno.h>
#include "hash-table.h"
#include "xmalloc.h"

int hash_table_insert(struct hash_table *ht, int key, void *value)
{
	unsigned int hash = hash_func(key);
	struct hash_node *node;

	node = xzalloc(sizeof(*node));
	if (!node)
		return -ENOMEM;

	node->key = key;
	node->value = value;
	list_add_tail(&node->node, &ht->buckets[hash]);
	ht->count++;

	return 0;
}

void *hash_table_lookup(struct hash_table *ht, int key)
{
	unsigned int hash = hash_func(key);
	struct hash_node *node;

	list_for_each_entry(node, &ht->buckets[hash], node) {
		if (node->key == key)
			return node->value;
	}

	return NULL;
}

int hash_table_remove(struct hash_table *ht, int key)
{
	unsigned int hash = hash_func(key);
	struct hash_node *node, *tmp;

	list_for_each_entry_safe(node, tmp, &ht->buckets[hash], node) {
		if (node->key == key) {
			list_del(&node->node);
			xfree(node);
			ht->count--;
			return 0;
		}
	}

	return -ENOENT;
}

void hash_table_cleanup(struct hash_table *ht)
{
	int i;
	struct hash_node *node, *tmp;

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		list_for_each_entry_safe(node, tmp, &ht->buckets[i], node) {
			list_del(&node->node);
			xfree(node);
		}
	}
	ht->count = 0;
}
