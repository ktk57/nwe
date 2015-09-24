#ifndef __INPC_API__
#define __INPC_API__

#include "inpc_hash_conf.h"
#include "inpc_item.h"
#include "cache_types.h"

#define DATA_COPY_OFF_FLAG 0
#define DATA_COPY_ON_FLAG 1

uint32_t inpc_init(const uint64_t max_mem_size, const hash_properties_t hash_prop, const item_properties_t it_prop);
char* inpc_get_acquire(const char*key, const uint8_t nkey, uint32_t* nval, uint32_t* error_code, uint8_t flags);
//char* inpc_get_reference_wrapper(cache_handle_t *cache_handle, const char* key, size_t key_length, int* ret_length);
int inpc_set(const char* key, const uint8_t nkey, const char* value, const uint32_t nval, const uint32_t expiry);
void inpc_get_release(char**);

#endif
