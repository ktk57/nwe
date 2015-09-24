#ifndef __HASH_CONF__
#define __HASH_CONF__

#include "inpc_item.h"

#define DEFAULT_MIN_HASH_SIZE 1<<23
#define DEFAULT_MAX_HASH_SIZE 1<<28
#define DEFAULT_HASH_GROW_FACTOR 2
#define DEFAULT_HASH_GROW_PROBING_LENGTH_TRIGGER 2
#define DEFAULT_HASH_GROW_FILL_TRIGGER 80
#define HASHTABLE_DEFAULT_LOCKS_SIZE 2<<13
#define HASHTABLE_DEFAULT_LOCKS_AND 0x00000FFF


#define get_lock_ind(ind, hash_size, lock_list_size)  (ind & (lock_list_size))
#define get_hash_lock(ind) (&hash.lock_list.locks[ind])

#define get_atomic_loc(ind) (&hash.atomic[ind])

typedef struct {
	uint32_t min_hash_size;
	uint32_t max_hash_size;
	int hash_grow_factor;
	int hash_grow_probing_length_trigger;
	int hash_grow_fill_trigger;
}hash_properties_t;

typedef struct {
	mem_item_t* next;
}hash_entry_t;

typedef struct {
	pthread_mutex_t *locks;
	int size;
}hash_locks_t;

typedef struct {
	hash_entry_t* list;
	hash_locks_t lock_list;
#ifdef WITH_ATOMIC
	uint32_t atomic[2<<13];
#endif
	uint32_t cur_size;
	uint32_t hash_and_factor;
	uint32_t filled_count;
	uint32_t net_length_count;
	uint32_t max_chain;
}inpc_hash_table_t;



#endif
