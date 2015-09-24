#ifndef _INPC_ITEM_
#define _INPC_ITEM_

#define DEFAULT_MIN_ITEM_SIZE 8
#define DEFAULT_MAX_ITEM_SIZE (1<<20)
#define DEFAULT_PAGE_SIZE 1<<20
#define DEFAULT_ITEM_SIZE_GROW_FACTOR 1.25
#define INPC_MAX_KEY_SIZE 255
#define KEY_MARGIN 8

#define ITEM_UPDATE 1
#define ITEM_ADD 2

#define initialize_item(current, nxt, slab_id, item_size) {((mem_item_t*)current)->next = (mem_item_t*)nxt; ((mem_item_t*)current)->slab_id = slab_id; \
							((mem_item_t*)current)->lru_next = NULL; ((mem_item_t*)current)->lru_prev = NULL;}
#define should_page_be_allocated(slab_id) ((slabs.list[slab_id].free_item)_count == 0)
#define get_aligned_item_meta_size() (eight_byte_align(sizeof(mem_item_t)) + eight_byte_align(sizeof(unsigned long long)))
#define get_key(it) ((char*)((char*)it + (eight_byte_align(sizeof(mem_item_t)))))
#define get_value_ptr(it) (get_key(it) + (eight_byte_align(it->key_len)) + sizeof(unsigned long long)) //last 8 for refcount and flags.
#define get_expiry(cur) (cur->expiry)
#define get_value_length(cur) (cur->value_length)
#define increase_item_refcount(cur, count) (cur->ref_count += count)
#define get_refcount(it) (it->ref_count)

#define ITEM_CLAIMABLE 1
//#define ITEM_DELETED 2
#define ITEM_ACCESSED 4

#define get_ref_count_ptr(it) ((uint32_t*)(get_key(it)+eight_byte_align(it->key_len)))
#define get_flags_ptr(it) (get_ref_count_ptr(it) + 1)

typedef struct {
	uint32_t min_item_size;
	uint32_t page_size;
	uint32_t actual_page_size;
	uint32_t max_item_size;
	float item_size_grow_factor;
}item_properties_t;

typedef struct mem_item {
	uint32_t expiry; 
	uint32_t value_length; 
	uint32_t lru_change_time;
	uint8_t key_len;
	uint8_t slab_id;
	uint8_t flags;
	uint8_t filler;
	struct mem_item* next;   
	struct mem_item* lru_next;
	struct mem_item* lru_prev;
}mem_item_t;

#endif
