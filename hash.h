#ifndef _HASH_H_
#define _HASH_H_

typedef unsigned int (*hashfunc_t)(unsigned int, void*);

typedef struct hash_node
{
	void *key;
	void *value;
	struct hash_node *prev;
	struct hash_node *next;
} hash_node_t;

typedef struct hash
{
	unsigned int buckets;
	hashfunc_t hash_func;
	hash_node_t **nodes;
} hash_t;



hash_t* hash_alloc(unsigned int buckets, hashfunc_t hash_func);

void* hash_lookup_entry(hash_t *hash, void* key, unsigned int key_size);

void hash_add_entry(hash_t *hash, void *key, unsigned int key_size,void *value, unsigned int value_size);

void hash_free_entry(hash_t *hash, void *key, unsigned int key_size);

#endif /* _HASH_H_ */