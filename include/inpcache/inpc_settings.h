#ifndef _INPC_SETTINGS_
#define _INPC_SETTINGS_

#include "inpc_item.h"
#include "inpc_hash_conf.h"

typedef struct {
	uint64_t max_mem_size;
	hash_properties_t hash_prop;
	item_properties_t it_prop;
#ifdef NOT_IN_USE
	int thread_count;
	int eviction_algo;
	int (*hash_function)(const char*, int len);
	int port;
#endif
} inpc_settings;

#endif
