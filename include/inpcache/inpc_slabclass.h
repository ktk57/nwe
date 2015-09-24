#ifndef __SLABCLASS__
#define __SLABCLASS__

#include "inpc_item.h"

#define MAX_SLAB_SIZE 64

uint32_t setup_page(const uint32_t slab_id);

typedef struct {
	uint32_t item_size;
	uint32_t page_size;
	struct mem_item* free;
	struct mem_item used_head;
	struct mem_item used_tail;
	uint32_t used_item_count;
	uint32_t free_item_count;
//	uint32_t total_item_count;
	uint32_t page_count;
	uint64_t get_calls;
	uint64_t set_calls;
	uint8_t eviction_started;
	uint16_t thread_back_check_limit;
	pthread_mutex_t lock;
}slabentry_t;

typedef struct {
	slabentry_t list[MAX_SLAB_SIZE];
	uint8_t max_entries;
	uint8_t cur_entries;
}slabclass_t;
#endif
