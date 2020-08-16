#include"common"
#include"hash.h"

typedef struct hash_node
{
	void *key;
	void *value;
	struct hash_node *prev;
	struct hash_node *next;
} hash_node_t;

struct hash
{
	unsigned int buckets;
	hashfunc_t hash_func;
	hash_node_t **nodes;
};

hash_t* hash_create(unsigned int buckets, hashfunc_t hash_func)
{
	hash_t* hash = (hash_t*)malloc(sizeof(hash_t));
	assert(hash);

	hash->buckets = buckets;
	hash->hash_func = hash_func;
	hash->nodes = (hash_node_t**)malloc(sizeof(hash_node_t*) * buckets);
	
	memset(hash->nodes, 0, sizeof(hash_node_t*) * buckets);

	return hash;
}

hash_node_t** hash_get_bucket(hash_t *hash, void *key)
{
	unsigned int bucket = hash->hash_func(hash->buckets, key);
	
	if(bucket >= hash->buckets)
	{
		perror("bad bucket lookup.\n");
		exit(EXIT_FAILURE);
	}

	return hash->nodes[bucket];
}

hash_node_t* hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size)
{
	hahs_node_t** bucket = hash_get_bucket(hash, key);
	hash_node_t* node = *bucket;

	while(node != NULL && memcmp(node->key, key, key_size))
	{
		node = node->next;
	}

	return node;
}

void* hash_lookup_entry(hash_t *hash, void* key, unsigned int key_size)
{
	hash_node_t* node = hash_get_node_by_key(hash, key, key_size);

	if(node == NULL)
	{
		return NULL;
	}

	return node->value;
}

void hash_add_entry(hash_t *hash, void *key, unsigned int key_size,void *value, unsigned int value_size)
{
	if(hash_lookup_entry(hash, key, key_size))
	{
		perror("duplicate hash key.\n");
		return;
	}

	hash_node_t* node = (hash_node_t*)malloc(sizeof(hash_node_t);
	node->prev = NULL;
	node->next = NULL;

	node->key = malloc(sizeof(key_size));
	memcpy(node->key, key, key_size);
	node->value = malloc(sizeof(value_size));
	memcpy(node->value, value, value_size);

	hash_node_t** bucket = hash_get_bucket(hash, key);
	if(*bucket == NULL)
	{
		*bucket = node;
	}
	else
	{
		node->next = *bucket;
		(*bucket)->prev = node;
		*bucket = node;
	}
}

void hash_free_entry(hash_t *hash, void *key, unsigned int key_size)
{
	hash_node_t* node = hash_get_node_by_key(hash, key, key_size);
	if(node == NULL)
	{
		return;
	}

	free(node->key);
	free(node->value);

	if(node->prev)
	{
		node->prev->next = node->next;
	}
	//���û��ǰ����㣬��˵����ǰ�ǵ�һ���ڵ�
	else
	{
		hash_node_t** bucket = hash_get_bucket(hash, key);
		*bucket = node->next;
	}

	if(node->next)
	{
		node->next->prev = node->prev;
	}

	free(node);
	node = NULL;
}

