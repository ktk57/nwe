#ifdef INPC_ENABLED
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include<netinet/in.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#define MAX 80
#define PORT 43454
#include "inpc_api.h"
#include <arpa/inet.h>



#ifdef GOOGLE_PROFILER
#include<google/profiler.h>
#endif

#include "inpc_item.h"
#include "inpc_debug.h"
#include "inpc_settings.h"
#include "inpc_hash.h"
#include "inpc_hash_conf.h"
#include "inpc_common.h"
#include "inpc_slabclass.h"
#include "inpc_stats.h"
#include "inpc_error.h"
#include "inpc_api.h"

#define LRU_ITEM_UPDATE_TIME 120

/**************************************************************************************************************************************************************\
 * 																																	Static Variables.
 **************************************************************************************************************************************************************/

static memory_details_t mem_det;
static inpc_settings settings;
//TODO_SURAJ: Size of slab should be a function of start/end/and grow factor and should be allocated on heap once the size is known.
static slabclass_t slabs;
static inpc_hash_table_t hash;
#ifdef STATS_ON
static inpc_stats_t stats;
#endif
int total_probe = 0;
uint32_t g_time ;
static int g_eviction_started;

#ifdef INPC_TEST_ON
#define MEMORY_LIMIT (((uint64_t)1)<<32)
#define KEY_FACTOR 21
#define GET_LIMIT ((1<<21)-1)
#define SET_LIMIT ((1<<21)-1)
#define GET_LOOP (20)
#define SET_LOOP (20)
#define MAIN_THREAD_WAIT_TIME (20)
#define TEST_SET_TIMEOUT 9000
#define MAX_OBJ_SZ (20)
#define SET_THREAD_COUNT 0
#define GET_THREAD_COUNT 1
#define KEY_LEN 20
char key_list[1<<23][20];
const char val_src[(1<<20)+1]="Namah";
#endif

/**************************************************************************************************************************************************************\
 * 																																	Utility Functions.
 **************************************************************************************************************************************************************/

static inline uint32_t eight_byte_align(const uint32_t v) {
	uint8_t m = v & 0xFFFFFF07;
		switch(m) {
			case 1:	return v + 7;
			case 2: return v + 6;
			case 3: return v + 5;
			case 4: return v + 4;
			case 5: return v + 3;
			case 6: return v + 2;
			case 7: return v + 1;
			case 0: return v;
		}
		//Theorotically can never reach here.
		return v;
}

static inline void my_memcpy(char* dest, const char* src, const uint32_t len) {
	memcpy(dest, src, len);
}

/**********************************************************************************************************************************************************\
 * 									Eco Functions.
 **********************************************************************************************************************************************************/
//LRU
void put_item_to_lru(mem_item_t* prev, mem_item_t* it) {
	assert(prev != NULL && it != NULL);
	it->lru_next = prev->lru_next;
	it->lru_prev = prev;
	prev->lru_next->lru_prev = it;
	prev->lru_next = it;
	slabs.list[it->slab_id].used_item_count++;

}

void remove_item_from_lru(mem_item_t* it) {
	assert(it != NULL);
	it->lru_prev->lru_next = it->lru_next;
	it->lru_next->lru_prev = it->lru_prev;
	slabs.list[it->slab_id].used_item_count--;
}

//HASH
void remove_item_from_hash_list(mem_item_t* prev, mem_item_t* cur, const uint32_t ind) {
	assert(cur != NULL && ind <= DEFAULT_MIN_HASH_SIZE);
	(prev != NULL) ? (prev->next = cur->next) : (hash.list[ind].next = cur->next);
	__stats_check(__sync_fetch_and_sub(&stats.cur_hash_items, 1));
}

void put_item_to_hash_head(const uint32_t ind, mem_item_t* it) {
	assert(it != NULL && ind <= DEFAULT_MIN_HASH_SIZE);
	it->next = hash.list[ind].next;
	hash.list[ind].next = it;
	__stats_check(__sync_fetch_and_add(&stats.cur_hash_items, 1));
}

/*void remove_item_from_hash_ind(const uint32_t ind, const mem_item_t* it) {
	assert(NULL != it);
	assert(ind < DEFAULT_MIN_HASH_SIZE); 
	mem_item_t* iter = hash.list[ind].next;
	while(iter && iter->next != it) {
		iter = iter->next;
	}
	assert(iter != NULL);
	iter->next = it->next;
}
*/
//Free List
void put_item_to_free_list(const uint32_t slab_id, mem_item_t* it) {
	assert(slab_id < slabs.cur_entries);
	assert(it != NULL);
	it->next = slabs.list[slab_id].free;
	slabs.list[slab_id].free = it;
	slabs.list[slab_id].free_item_count++;
}

mem_item_t* remove_item_from_free_list(const uint32_t slab_id) {
	assert(slab_id < slabs.cur_entries);
	assert(slabs.list[slab_id].free_item_count > 0);
	mem_item_t* it = slabs.list[slab_id].free;
	slabs.list[slab_id].free = it->next;
	slabs.list[slab_id].free_item_count--;
	return it;
}

uint32_t get_slab(const uint8_t klen, const uint32_t vlen) {
	uint32_t object_len = eight_byte_align(klen) + eight_byte_align(vlen) + get_aligned_item_meta_size();
	uint32_t last_slab = slabs.cur_entries - 1;
	if (object_len > slabs.list[last_slab].item_size) {
		return -1;
	}
	uint32_t slab_id = 0;
	while (object_len > slabs.list[slab_id].item_size) {
		slab_id++;
	}
	inpc_debug("key:%u:Val:%u:Object:%u:SlabID:%u:SlabITSize:%u", klen, vlen, object_len, slab_id, slabs.list[slab_id].item_size);
	return slab_id;
}

void make_item(mem_item_t* it, const char* val, const uint32_t nval, const uint32_t expiry) {
	assert(val != NULL);
	assert(expiry > 0);
	uint32_t ctime = current_time();
	inpc_debug("EXP:%u", ctime + expiry);
	my_memcpy(get_value_ptr(it), val, nval);
	it->expiry = ctime + expiry;
	it->lru_change_time = ctime;
	it->value_length = nval;
	it->flags = 0;
	it->filler = 0;
	*(get_ref_count_ptr(it)) = 0;
	it->next = it->lru_next = it->lru_prev = NULL;
}

#ifdef STATS_ON
void dump_stats() {
	inpc_stats_t t_stats = stats;
	inpc_log("RunningTime:%lu", g_time - t_stats.start_time);
	inpc_log("CopyGetCalls:%lu", t_stats.copy_get_calls);
	inpc_log("NoCopyGetCalls:%lu",  t_stats.no_copy_get_calls);
	inpc_log("GetInvalidCalls:%lu",  t_stats.get_invalid_params);
	inpc_log("SetInvalidCalls:%lu",  t_stats.set_invalid_params);
	inpc_log("GetHits:%lu", t_stats.copy_get_calls + t_stats.no_copy_get_calls - t_stats.get_misses);
	inpc_log("GetMisses:%lu", t_stats.get_misses);
	inpc_log("GetExpiryClaimed:%lu", t_stats.get_expiry_claimed);
	inpc_log("GetExpiryUnFetched:%lu", t_stats.exp_unfetched);
	inpc_log("LRUAccessUpdate:%lu", t_stats.lru_access_update);
	inpc_log("SetCalls:%lu", t_stats.set_calls);
	inpc_log("SetFailNoSpace:%lu", t_stats.set_fail_no_space);
	inpc_log("SetFailTooLarge:%lu", t_stats.set_fail_too_large_object);
	inpc_log("SetOverwrite:%lu", t_stats.set_overwrite);
	inpc_log("SetOverwriteUnfetched:%lu", t_stats.ovw_unfetched);
	inpc_log("CurItems:%lu", t_stats.cur_hash_items);
	inpc_log("TotalItems:%lu", stats.total_items);
	inpc_log("MaxMemSize:%lu", stats.max_mem_size);
	inpc_log("UsedMemory:%lu", mem_det.used_size);
	inpc_log("AvailableMemory:%lu", mem_det.max_size - mem_det.used_size);
	inpc_log("Evictions:%lu", stats.evictions);
	inpc_log("ExpiredByThread:%lu", stats.expired_by_thread);
	inpc_log("ClaimedByThread:%lu", stats.claimed_by_thread);
	inpc_log("HashSize:%lu", stats.hash_size);
	inpc_log("MaxItemSize:%lu", stats.max_item_size);
	inpc_log("PageGuideline:%lu", stats.page_guideline);
}
#endif

#ifdef STATS_ON
void dump_slab_stats() {
	uint32_t i = 0;
	for (i = 0; i < slabs.cur_entries; i++) {
		slabentry_t* slab = &slabs.list[i];
		inpc_log("SlabID:%d:ITSize:%u:PageSize:%u:FreeItem:%u:UsedItem:%u:PageCount:%u:GetCount:%lu:SetCount:%lu", i, slab->item_size, slab->page_size, slab->free_item_count, slab->used_item_count, slab->page_count, slab->get_calls, slab->set_calls);
	}
}
#endif

/* Function deleted - Returns item in below order
 * 1. Expired item belonging to same slab.
 * 2. If not 1, expired item. //commented. Only item belonging to same slab id.
 * 3. If not 2, item near LRU end and belonging to same slab.
 * 4. NULL.
 * Caller if *WANTS* to evict needs to pick up the element at tail if used_count > 0. Also validate that the item returned is not of state 3 above.
 */

void* process_for_eviction_and_expiry() {
	while (1) {
		sleep(CLEANUP_THREAD_SLEEP_INTERVAL);
		__stats_check(dump_stats());
		__stats_check(dump_slab_stats());
		uint32_t slab_id = 0;
		char key_map[BACKWARD_EXPIRY_CHECK_LIMIT][INPC_MAX_KEY_SIZE + 1];
		uint8_t keylen[BACKWARD_EXPIRY_CHECK_LIMIT];
		uint32_t expired_count = 0;
		for (slab_id = 0;  slab_id < slabs.cur_entries; slab_id++) {
			pthread_mutex_lock(&slabs.list[slab_id].lock);
			uint32_t count = 0;
			mem_item_t* it = slabs.list[slab_id].used_tail.lru_prev;
			uint32_t lim = min((slabs.list[slab_id].item_size > AGGRESSIVE_EXPIRY_SIZE_CUTOFF ? BACKWARD_EXPIRY_CHECK_LIMIT : DEF_BACKWARD_EXPIRY_CHECK_LIMIT), slabs.list[slab_id].used_item_count);
			uint32_t expcount  = 0;
			while (it->lru_prev && count++ < lim) {
				int need_to_free = 0;
				if ((it->flags & ITEM_CLAIMABLE) && *(get_ref_count_ptr(it)) == 0) { 
					remove_item_from_lru(it);
					put_item_to_free_list(it->slab_id, it);
					__stats_check(__sync_fetch_and_add(&stats.claimed_by_thread, expired_count));
				}
				else if ((it->expiry < current_time())) {
					need_to_free = 1;
				}
				if (need_to_free) {
//					it->expiry = GUARANTEED_EXPIRY_TIME;
					keylen[expcount] = it->key_len;
					memcpy(key_map[expcount], get_key(it), it->key_len);
					key_map[expcount][it->key_len] = '\0';
					expcount++;
				}
				it = it->lru_prev;
			}
			pthread_mutex_unlock(&slabs.list[slab_id].lock);
			uint32_t i = 0;
			uint32_t flags = 0 | DATA_COPY_OFF_FLAG;
			for (i = 0; i < expcount; i++) {
				uint32_t nval = 0, error_code = 0;
				char* retval = inpc_get_acquire(key_map[i], keylen[i], &nval, &error_code, flags);
				if (retval) {
					inpc_get_release(&retval);
				}
				if (error_code == INPC_ERROR_ITEM_EXPIRED) expired_count++;
			}
		}
		__stats_check(__sync_fetch_and_add(&stats.expired_by_thread, expired_count));
	}
	return NULL;
}

mem_item_t* get_item(const char* key, const uint32_t nkey, const char* val, const uint32_t nval, const uint32_t slab_id, const uint32_t expiry) {
	mem_item_t* it = NULL;
	inpc_debug("SlabID:%u:FreeCount:%u", slab_id, slabs.list[slab_id].free_item_count);
	if (slabs.list[slab_id].free_item_count == 0) {
		if (g_eviction_started) {
			inpc_error_log("NoMemory.EvictionAlreadyBegun");
			return NULL;
		}
		if ((0 != setup_page(slab_id))) {
			g_eviction_started = 1;
			inpc_error_log("NoMemory");
			return NULL;
		}
	}
	it = remove_item_from_free_list(slab_id);
	it->slab_id = slab_id;
	it->key_len = nkey;
	my_memcpy(get_key(it), key, nkey);
	make_item(it, val, nval, expiry);
	return it;
}

void print_settings() {
	inpc_log("- Max Mem Size:%lukB", settings.max_mem_size/1024);
	inpc_log("- Hash Prop");
	inpc_log("----MinHashSize:%ukB", settings.hash_prop.min_hash_size/1024);
	inpc_log("----MaxHashSize:%ukB", settings.hash_prop.max_hash_size/1024);
	inpc_log("----HashGrowFactor:%u", settings.hash_prop.hash_grow_factor);
	inpc_log("----HashGrowProbingLengthTrigger:%u", settings.hash_prop.hash_grow_probing_length_trigger);
	inpc_log("----HashGrowFillTrigger:%u", settings.hash_prop.hash_grow_fill_trigger);
	inpc_log("- Item Prop");
	inpc_log("----MinItemSize:%uB", settings.it_prop.min_item_size);
	inpc_log("----MaxItemSize:%ukB", settings.it_prop.max_item_size/1024);
	inpc_log("----PageSize:%ukB", settings.it_prop.page_size/1024);
	inpc_log("----ActPageSize:%ukB", settings.it_prop.actual_page_size/1024);
	inpc_log("----ItemSizeGrowFactor:%f", settings.it_prop.item_size_grow_factor);
	inpc_log("- Memory Details");
	inpc_log("----MaxSize:%lu", mem_det.max_size);
	inpc_log("----UsedSize:%lu", mem_det.used_size);
	inpc_log("- Hash Table Details");
	inpc_log("----CurSize:%u", hash.cur_size);
	inpc_log("----FilledCount:%u", hash.filled_count);
	inpc_log("----NetLengthCount:%u", hash.net_length_count);
	inpc_log("----LockCount:%u", hash.lock_list.size);
	inpc_log("- Slabs Details");
	inpc_log("----MaxEntries:%u", slabs.max_entries);
	inpc_log("----CurEntries:%u", slabs.cur_entries);
}

static inline char* get_data(mem_item_t* cur, uint32_t *nval, uint8_t data_copy_on) {
	char* ptr = NULL;
	*nval = get_value_length(cur);
	if (data_copy_on == 1) {
		ptr = malloc(*nval);
		if (ptr) my_memcpy(ptr, (char*) get_value_ptr(cur), *nval);
	}
	else {
		ptr = get_value_ptr(cur);
		uint32_t* refptr = (uint32_t *)(ptr - sizeof(unsigned long long));
		__sync_fetch_and_add(refptr, 1);
	}
	return ptr;
}


static inline void handle_get_item_lru(mem_item_t* cur) {
	const uint8_t slab_id = cur->slab_id;
	assert(slab_id < slabs.cur_entries);
	uint32_t ctime = current_time();
	if (cur->lru_change_time + LRU_ITEM_UPDATE_TIME < ctime) {
		__with_lock(pthread_mutex_lock(&slabs.list[slab_id].lock));
		remove_item_from_lru(cur);
		cur->lru_change_time = ctime;
		put_item_to_lru(&slabs.list[slab_id].used_head, cur);
		__with_lock(pthread_mutex_unlock(&slabs.list[slab_id].lock));
		__stats_check(__sync_fetch_and_add(&stats.lru_access_update, 1));
	}
	cur->flags |= ITEM_ACCESSED;
	__stats_check(__sync_fetch_and_add(&slabs.list[slab_id].get_calls, 1));
}

static inline int process_expired_item_get(mem_item_t* cur, uint8_t data_copy_on) {
	inpc_debug("Expired:%s", get_key(cur));
	uint32_t slab_id = cur->slab_id;
	__with_lock(pthread_mutex_lock(&slabs.list[slab_id].lock));
	remove_item_from_lru(cur);
	uint32_t expired = 0;
	if (data_copy_on == 1 || (*(get_ref_count_ptr(cur)) == 0)) {
		expired = 1;
		put_item_to_free_list(slab_id, cur);
	}
	else {
		put_item_to_lru(slabs.list[slab_id].used_tail.lru_prev, cur);
		cur->flags |= ITEM_CLAIMABLE;
	}
	__with_lock(pthread_mutex_unlock(&slabs.list[slab_id].lock));
	return expired;
}

static inline void locate_item(mem_item_t** cur, mem_item_t** prev, const char* key, uint16_t nkey) {
	mem_item_t* l_cur = *cur;
	mem_item_t* l_prev = *prev;
	for (; l_cur; l_prev = l_cur, l_cur = l_cur->next) {
		if (l_cur->key_len != nkey) continue;
		if (!memcmp(key, get_key(l_cur), nkey)) break;
	}
	*cur = l_cur;
	*prev = l_prev;
}

/**********************************************************************************************************************************************************\
 * 									GetSet.
 **********************************************************************************************************************************************************/

char* inpc_get_acquire(const char*key, const uint8_t nkey, uint32_t* nval, uint32_t* error_code, uint8_t flags) {
	/* Locate Item */
	if (key == NULL || nkey == 0 || error_code == NULL) {
		inpc_debug("BADPARAM:key:%s:nkey:%u", key, nkey);
		__stats_check(__sync_fetch_and_add(&stats.get_invalid_params, 1));
		if (error_code != NULL) *error_code = INPC_ERROR_INVALID_GET_PARAMS;
		return NULL;
	}
	uint8_t data_copy_on = (flags & DATA_COPY_ON_FLAG);
	uint32_t h = get_inpc_hash(key, nkey, 0);
	uint32_t ind = h & (hash.hash_and_factor);
	uint32_t lock_ind;
	if (data_copy_on) 
	{	
		__stats_check(__sync_fetch_and_add(&stats.copy_get_calls, 1));
	} else {
		__stats_check(__sync_fetch_and_add(&stats.no_copy_get_calls, 1));
	}
	__with_lock(lock_ind = get_lock_ind(ind, hash.hash_and_factor, HASHTABLE_DEFAULT_LOCKS_AND));
	*nval = 0;
	mem_item_t* prev = NULL;
	char* ptr = NULL;
	__with_lock(pthread_mutex_lock(get_hash_lock(lock_ind)));
	mem_item_t* cur = hash.list[ind].next;
	locate_item(&cur, &prev, key, nkey);
	if (cur) {	
		if (get_expiry(cur) > current_time()) {
			ptr = get_data(cur, nval, data_copy_on);
			//Can it be beneficial to release the hash lock here and move to spinlock.
			handle_get_item_lru(cur);
		}
		else {
			remove_item_from_hash_list(prev, cur, ind); 
			uint32_t is_expired = process_expired_item_get(cur, data_copy_on);
			if (is_expired) {
				if ((cur->flags & ITEM_ACCESSED)) {
					__stats_check(__sync_fetch_and_add(&stats.get_expiry_claimed, 1));
				}
				else {
					__stats_check(__sync_fetch_and_add(&stats.exp_unfetched, 1));
				}
			}
			__stats_check(__sync_fetch_and_add(&stats.get_misses, 1));
			*error_code = INPC_ERROR_ITEM_EXPIRED;
		}
	}
	else {
			__stats_check(__sync_fetch_and_add(&stats.get_misses, 1));
			*error_code = INPC_ERROR_ITEM_ABSENT;
	}
	__with_lock(pthread_mutex_unlock(get_hash_lock(lock_ind)));
	inpc_debug("Key:%s:nkey:%u:nval:%u:Error:%u:Flags:%u", key, nkey, *nval, *error_code, flags);
	return ptr;
}

void inpc_get_release(char** ptr) {
	assert(ptr && *ptr);
	if (*ptr < mem_det.ptr || *ptr >= mem_det.ptr + mem_det.max_size) {
		free(*ptr);
	}
	else {
		uint32_t* refct_ptr = (uint32_t*)(*ptr - sizeof(uint64_t));
		__sync_fetch_and_sub(refct_ptr, 1);
	}
	*ptr = NULL;
}

int inpc_set(const char* key, const uint8_t nkey, const char* value, const uint32_t nval, const uint32_t expiry) {
	//Validate that item fits into page.
	if (key == NULL || nkey == 0 || value == NULL || nval == 0) {
		inpc_debug("BadParam:Key:%s:nkey:%u:nval:%u", key, nkey, nval);
		__stats_check(__sync_fetch_and_add(&stats.set_invalid_params, 1));
		return INPC_ERROR_INVALID_SET_COMMAND;
	}
	inpc_debug("Key:%s:nKey:%u:nval:%u:exp:%u", key, nkey, nval, expiry);
	__stats_check(__sync_fetch_and_add(&stats.set_calls, 1));
	int new_slab_id = get_slab(nkey, nval);
	if (new_slab_id == -1) {
		inpc_error_log("TOOLargeObject:Key:%s:K:%u:V:%u", key, nkey, nval);
		__stats_check(__sync_fetch_and_add(&stats.set_fail_too_large_object, 1));
		return INPC_ERROR_SET_FAILED_TOO_BIG_OBJECT;
	}

	int expiration_time = expiry;
	if (!expiration_time) expiration_time = 31104000;
	uint32_t h = get_inpc_hash(key, nkey, 0);
	uint32_t ind = h & (hash.hash_and_factor);
	uint32_t lock_ind = get_lock_ind(ind, hash.hash_and_factor, HASHTABLE_DEFAULT_LOCKS_AND);
	inpc_debug("%lu:Key:%s:hash:%u:ind:%u:lock_ind:%u:KSize:%u:VSize:%u:Exp:%u:SlabID:%u:SlabITSize:%u", pthread_self(), key, h, ind, lock_ind, nkey, nval, expiry, new_slab_id, slabs.list[new_slab_id].item_size);
	__with_lock(pthread_mutex_lock(get_hash_lock(lock_ind)));
	mem_item_t *cur = hash.list[ind].next;
	mem_item_t* prev = NULL;
	locate_item(&cur, &prev, key, nkey);
	//locate_item(&cur, &prev, key, msb16_hash);
	int rc = 0;
	int old_slab_id = -1;
	mem_item_t *it = NULL;
	if (cur) {
		if (cur->flags & ITEM_ACCESSED) {
			__stats_check(__sync_fetch_and_add(&stats.set_overwrite, 1));
		}
		else {
			__stats_check(__sync_fetch_and_add(&stats.ovw_unfetched, 1));
		}
		old_slab_id = cur->slab_id;
		inpc_debug("ItemFound:Key:%s:oldSalb:%u:NewSlab:%u", key, old_slab_id, new_slab_id);
		remove_item_from_hash_list(prev, cur, ind);
		__with_lock(pthread_mutex_lock(&slabs.list[old_slab_id].lock));
		remove_item_from_lru(cur);
		int ref_count = *((int*)get_ref_count_ptr(cur));
		if (ref_count > 0 ) {
			put_item_to_lru(slabs.list[old_slab_id].used_tail.lru_prev, cur);
			cur->flags |= ITEM_CLAIMABLE;
			inpc_debug("ClaimMark:%s", key);
		}
		else {
			inpc_debug("Claimed:%s", key);
			put_item_to_free_list(old_slab_id, cur);
		}
		if (old_slab_id != new_slab_id) {
			__with_lock(pthread_mutex_unlock(&slabs.list[old_slab_id].lock));
		}
	}
	if (old_slab_id != new_slab_id) {
		__with_lock(pthread_mutex_lock(&slabs.list[new_slab_id].lock));
	}	
	it = get_item(key, nkey, value, nval, new_slab_id, expiration_time);
	if (it == NULL) {
		inpc_error_log("SETFAIL:%s", key);
		rc = INPC_ERROR_SET_FAILED_NO_SPACE; 
		__stats_check(__sync_fetch_and_add(&stats.set_fail_no_space, 1));
		goto done;
	}
	put_item_to_hash_head(ind, it);
	put_item_to_lru(&slabs.list[new_slab_id].used_head, it);
	__stats_check(__sync_fetch_and_add(&slabs.list[new_slab_id].set_calls, 1));
done:
	__with_lock(pthread_mutex_unlock(&slabs.list[new_slab_id].lock));
	__with_lock(pthread_mutex_unlock(get_hash_lock(lock_ind)));
	return rc;
}

/**********************************************************************************************************************************************************\
 * 									Slabbing.
 **********************************************************************************************************************************************************/

void setup_items(const uint32_t slab_id, const uint64_t base_offset) {
//TODO_SURAJ: Should be in lock from caller.
	uint32_t item_size = slabs.list[slab_id].item_size;
	assert(slabs.list[slab_id].free_item_count == 0);
	char* start =  (mem_det.ptr + base_offset);
	int item_count = slabs.list[slab_id].page_size / item_size;
	inpc_debug("PageItemization:Slab:%u:PageSize:%u:ItemSize:%u:Count:%u", slab_id, slabs.list[slab_id].page_size, item_size, item_count);
	int i = 0;
	char* current = start;
	char* next = start;
	for (; i < item_count; i++) {
		current = next;
		next = current + item_size;
		initialize_item(current, next, slab_id, item_size);
	}
//	INITIALIZE_ITEM(current, slabs[slab_id].free, slab_id, item_size);
	((mem_item_t*)current)->next = slabs.list[slab_id].free;
	slabs.list[slab_id].free = (mem_item_t*)start;
	slabs.list[slab_id].free_item_count += item_count;
//	slabs.list[slab_id].total_item_count += item_count;
//	__sync_fetch_and_add(&slabs[slab_id].free_item_count, item_count);
}

uint32_t setup_page(const uint32_t slab_id) {
	inpc_debug("Page Requested:Slab:%u:Size:%u", slab_id, slabs.list[slab_id].item_size);
	assert(slabs.list[slab_id].free_item_count == 0);
	__with_lock(pthread_mutex_lock(&mem_det.lock));
	uint64_t current_used_size = mem_det.used_size;
	if (current_used_size + slabs.list[slab_id].page_size > mem_det.max_size) {
		__with_lock(pthread_mutex_unlock(&mem_det.lock));
		inpc_error_log("Cannot Allocate page.Requested:%u CurrentUsed:%lu Max:%lu", settings.it_prop.actual_page_size, current_used_size, mem_det.max_size);
		return INPC_ERROR_PAGE_ALLOCATION_FAIL;
	}
	mem_det.used_size += slabs.list[slab_id].page_size;
	uint64_t l_used_size = mem_det.used_size;
	uint64_t l_max_size = mem_det.max_size;	
	__with_lock(pthread_mutex_unlock(&mem_det.lock));
	if (l_used_size > 3*(l_max_size >> 2)) {
		send_inpc_mem_percent_stats(MEM_CROSSED_75_PERCENT);
	}
	setup_items(slab_id, current_used_size);
	inpc_debug("Memory:Assigned:%luNew:%lu:Slab:%u:FreeITCt:%u", current_used_size, mem_det.used_size, slab_id, slabs.list[slab_id].free_item_count);
	slabs.list[slab_id].page_count++;
	return 0;
}


/**********************************************************************************************************************************************************\
 * 									Init.
 **********************************************************************************************************************************************************/
void slabbing_init() {
	uint32_t start_size = settings.it_prop.min_item_size;
	uint32_t end_size = settings.it_prop.max_item_size;
	uint32_t page_size = settings.it_prop.actual_page_size;
	float grow_factor = settings.it_prop.item_size_grow_factor;
	uint32_t next_size = eight_byte_align(start_size);
	inpc_log("StartSize:%u:EndSize:%u:PageSize:%u:GrowthFactor:%f:ItemMetaSize:%u", start_size, end_size, page_size, grow_factor, get_aligned_item_meta_size());	
	uint32_t slab_id = 0;
	memset(&slabs, 0, sizeof(slabs));
	slabs.max_entries = MAX_SLAB_SIZE;
	uint32_t extra_space = get_aligned_item_meta_size() + eight_byte_align(KEY_MARGIN);
	uint32_t item_size = next_size + extra_space;
	inpc_debug("NextSize:%u:ItemSize:%u", next_size, item_size);
	for ( ; slab_id < slabs.max_entries && next_size <= end_size && item_size <= page_size; slab_id++) {
		next_size = (float)next_size * (float)grow_factor;
		next_size = eight_byte_align(next_size);
		__with_lock(pthread_mutex_init(&slabs.list[slab_id].lock, NULL));
		__with_lock(pthread_mutex_lock(&slabs.list[slab_id].lock));
		if (next_size + extra_space > page_size) item_size = page_size;
		slabs.list[slab_id].item_size = item_size;
		slabs.list[slab_id].page_size = (page_size/item_size)*item_size;
		setup_page(slab_id);
		slabs.list[slab_id].used_head.lru_next = &slabs.list[slab_id].used_tail;
		slabs.list[slab_id].used_tail.lru_prev = &slabs.list[slab_id].used_head;
		slabs.list[slab_id].used_head.lru_prev = slabs.list[slab_id].used_tail.lru_next = NULL;
		slabs.list[slab_id].used_head.expiry = slabs.list[slab_id].used_tail.expiry = 0xFFFFFFFF;
		slabs.list[slab_id].used_head.slab_id= slabs.list[slab_id].used_tail.slab_id= -1;
		slabs.list[slab_id].get_calls = slabs.list[slab_id].set_calls = 0;
		__with_lock(pthread_mutex_unlock(&slabs.list[slab_id].lock));
		item_size = next_size + extra_space;
		inpc_debug("NextSize:%u:ItemSize:%u", next_size, item_size);
//		item_size = eight_byte_align(item_size);
	}
	slabs.cur_entries = slab_id; 
	assert(slabs.cur_entries != 0);
}

void memory_space_init() {
	mem_det.ptr = (char *) malloc(settings.max_mem_size);
	assert(mem_det.ptr != NULL);
	memset(mem_det.ptr, 0, settings.max_mem_size);
	mem_det.max_size = settings.max_mem_size;
	inpc_log("MemoryDetails:Start:%lu:Size:%lu", (unsigned long)mem_det.ptr, mem_det.max_size);
	__with_lock(pthread_mutex_init(&mem_det.lock, NULL));
}

void hash_prop_init(const hash_properties_t hash_prop) {
	settings.hash_prop = hash_prop;
	//TODO_SURAJ: Replace with set property macro.
	if (!settings.hash_prop.min_hash_size) settings.hash_prop.min_hash_size = DEFAULT_MIN_HASH_SIZE;
	if (!settings.hash_prop.max_hash_size) settings.hash_prop.max_hash_size = DEFAULT_MAX_HASH_SIZE;
	if (!settings.hash_prop.hash_grow_factor) settings.hash_prop.hash_grow_factor = DEFAULT_HASH_GROW_FACTOR;
	if (!settings.hash_prop.hash_grow_probing_length_trigger) settings.hash_prop.hash_grow_probing_length_trigger = DEFAULT_HASH_GROW_PROBING_LENGTH_TRIGGER;
	if (!settings.hash_prop.hash_grow_fill_trigger) settings.hash_prop.hash_grow_fill_trigger = DEFAULT_HASH_GROW_FILL_TRIGGER;
}	

void item_prop_init(const item_properties_t it_prop) {
	settings.it_prop = it_prop;
	if (!settings.it_prop.min_item_size) settings.it_prop.min_item_size = DEFAULT_MIN_ITEM_SIZE;
	if (!settings.it_prop.max_item_size) settings.it_prop.max_item_size = DEFAULT_MAX_ITEM_SIZE;
	if (!settings.it_prop.page_size) settings.it_prop.page_size= DEFAULT_PAGE_SIZE;
	settings.it_prop.actual_page_size = settings.it_prop.page_size + eight_byte_align(INPC_MAX_KEY_SIZE) + get_aligned_item_meta_size();
	if (!settings.it_prop.item_size_grow_factor) settings.it_prop.item_size_grow_factor = DEFAULT_ITEM_SIZE_GROW_FACTOR;
}

void assert_properties_values() {
	assert(settings.hash_prop.min_hash_size > 0);
	assert(settings.hash_prop.max_hash_size >= settings.hash_prop.min_hash_size); 
	assert(settings.hash_prop.hash_grow_factor >= 1);
	assert(settings.hash_prop.hash_grow_probing_length_trigger > 1);
	assert(settings.hash_prop.hash_grow_fill_trigger > 0);
	assert(settings.it_prop.min_item_size > 0);
	assert(settings.it_prop.page_size >= eight_byte_align(settings.it_prop.max_item_size));
	assert(settings.it_prop.max_item_size > settings.it_prop.min_item_size);
	assert(settings.it_prop.item_size_grow_factor > 1);
	assert(settings.max_mem_size > 0);
}

void hashtable_locks_init() {
	hash.lock_list.locks = malloc(sizeof(pthread_mutex_t) * HASHTABLE_DEFAULT_LOCKS_SIZE);
	assert(hash.lock_list.locks != NULL);
	hash.lock_list.size = HASHTABLE_DEFAULT_LOCKS_SIZE;
	int i = 0;
	for (; i < HASHTABLE_DEFAULT_LOCKS_SIZE; i++) {
		__with_lock(pthread_mutex_init(&hash.lock_list.locks[i], NULL));
	}
}

void hashtable_init() {
	hash.list = malloc(sizeof(hash_entry_t) * settings.hash_prop.min_hash_size);
	assert(hash.list != NULL);
	memset(hash.list, 0, sizeof(hash_entry_t)*settings.hash_prop.min_hash_size);
	hash.cur_size = settings.hash_prop.min_hash_size;
	hash.hash_and_factor = hash.cur_size - 1;
	hash.filled_count = 0;
	hash.net_length_count = 0;
	hash.max_chain = 0;
	hashtable_locks_init();
	inpc_debug("HashTable:CurSize:%u:AndFactor:%u:FilledCount:%u:NetLengthChain:%u:MaxChain:%u:StrippedLocks:%u", hash.cur_size, hash.hash_and_factor, hash.filled_count,
		hash.net_length_count, hash.max_chain, HASHTABLE_DEFAULT_LOCKS_SIZE);
}

void* manage_timer() {
	while (1) {
		uint32_t c_time = (uint32_t) time(NULL);
		g_time = c_time;
		sleep(1);
	}
	return NULL;
}

void inpc_stats_init() {
	__stats_check(memset(&stats, 0, sizeof(stats)));
	__stats_check(stats.start_time = g_time);
}

uint32_t inpc_init(const uint64_t max_mem_size, const hash_properties_t hash_prop, const item_properties_t it_prop) {
	settings.max_mem_size = max_mem_size;
	hash_prop_init(hash_prop);
	item_prop_init(it_prop);
	assert_properties_values();
	pthread_t id, id1;
	pthread_create(&id, NULL, manage_timer, NULL);
	pthread_create(&id1, NULL, process_for_eviction_and_expiry, NULL);
	memory_space_init() ;
	hashtable_init();
	slabbing_init();
	__stats_check(inpc_stats_init());
	print_settings();
	return 0;
}

/**********************************************************************************************************************************************************\
 * 									Test Suite.
 **********************************************************************************************************************************************************/
#ifdef INPC_TEST_ON
uint32_t test_slabbing() {
	inpc_log("TestSuiteID:%s\n", __FUNCTION__);
	uint64_t max_mem_size = MEMORY_LIMIT;
	hash_properties_t hash_prop = {0, 0, 0, 0, 0};
	item_properties_t it_prop = {0, 0, 0, 0, 0};
	inpc_init(max_mem_size, hash_prop, it_prop);
	return 0;
}

uint32_t get_test(int start, int limit) {
	uint32_t error_code = 0;
	int count = -1;
	uint32_t ind = start & limit;
	uint32_t nval = 0;
	char* val;
	uint32_t s_count = 0, f_count = 0;
	uint8_t flags = 0 | DATA_COPY_ON_FLAG;
	while (++count <= limit) {
		if (NULL != (val = inpc_get_acquire(key_list[ind & limit], KEY_LEN, &nval, &error_code, flags))) {
			++s_count;
			inpc_debug("Value:%s", val);
			assert(strncmp(val_src, val, strlen(val_src)) == 0 );
			inpc_get_release(&val);
		}
		else {
			inpc_debug("GetFail:%s", key_list[count]);
			++f_count;
		}
		ind = ((ind + 1) & limit);
//		assert(NULL != (val = data_copy_get(buffer, nkey + printed, &nval, &error_code)));
	}
	aprint("GetTest:%u:NetProbe:%u:Avg:%u:S:%u:F:%u", limit, total_probe, total_probe/count, s_count, f_count);
	return 0;
}

uint32_t set_test(int start, int limit) {
	int count = -1;
	uint32_t ind = start & limit;
	uint32_t s_count = 0, f_count = 0;
	while (++count <= limit) {
		(0 == inpc_set(key_list[ind], KEY_LEN, val_src, MAX_OBJ_SZ, TEST_SET_TIMEOUT)) ? ++s_count : ++f_count;
		ind = ((ind + 1) & limit);
	}
	aprint("SetTest:%u:MaxChain:%u:NetChain:%u:S:%u:F:%u", limit, hash.max_chain, hash.net_length_count, s_count, f_count);
	return 0;
}

typedef uint32_t (*fptr)(int, int);
uint32_t timed_run( int limit, fptr f) {
//	sleep(2);
	struct timeval st_tv, end_tv;
	gettimeofday(&st_tv, NULL);
	f(rand(), limit);
	gettimeofday(&end_tv, NULL);
	aprint("Time(us):%lu", (end_tv.tv_sec - st_tv.tv_sec)*1000000 + (end_tv.tv_usec - st_tv.tv_usec));
	return 0;
}

void* set_caller() {
	struct timeval st_tv, end_tv;
	gettimeofday(&st_tv, NULL);
	int ct = 0;
	while (ct++ < SET_LOOP) {
		timed_run( SET_LIMIT, set_test);
	}
	gettimeofday(&end_tv, NULL);
	unsigned long net_count = SET_LOOP*SET_LIMIT;
	unsigned long net_time = (end_tv.tv_sec - st_tv.tv_sec)*1000000 + (end_tv.tv_usec - st_tv.tv_usec); 
	aprint("SETTime:Count:%lu:%lu:Throughput:%lu", net_count, net_time, (net_count*1000000)/net_time);
	return NULL;
}

void* get_caller() {
	struct timeval st_tv, end_tv;
	gettimeofday(&st_tv, NULL);
	int ct = 0;
	while(ct++ < GET_LOOP) {
		timed_run( GET_LIMIT, get_test);
	}
	gettimeofday(&end_tv, NULL);
	unsigned long net_count = GET_LOOP*GET_LIMIT;
	unsigned long net_time = (end_tv.tv_sec - st_tv.tv_sec)*1000000 + (end_tv.tv_usec - st_tv.tv_usec); 
	aprint("GETTime:Count:%lu:%lu(us):Throughput:%lu", net_count, net_time, (net_count*1000000)/net_time);
	return NULL;
}

void create_keys(const uint32_t lim) {
	int max = (1 << lim) - 1;
	int i = 0;
	while (i <= max) {
		sprintf(key_list[i], "ShreeGanesh%d", i);
		i++;
	}
	aprint("KeysGenerated:%d", i);
	return ;
}

/**********************************************************************************************************************************************************\
 * 									Main.
 **********************************************************************************************************************************************************/
int main() {
	int n_threads = SET_THREAD_COUNT + GET_THREAD_COUNT;
	pthread_t *id = malloc(sizeof(pthread_t)*n_threads);
	assert(id != NULL);
	create_keys(KEY_FACTOR);
	test_slabbing();
	timed_run( SET_LIMIT, set_test);
#ifdef GOOGLE_PROFILER
	ProfilerStart("./google_prof");
#endif
	int i = 0;
	for (; i < SET_THREAD_COUNT; i++) {
		pthread_create(&id[i], NULL, set_caller, NULL);
	}
	for (i = 0; i < GET_THREAD_COUNT; i++) {
		pthread_create(&id[SET_THREAD_COUNT + i], NULL, get_caller, NULL);
	}
	sleep(MAIN_THREAD_WAIT_TIME);
#ifdef GOOGLE_PROFILER
	ProfilerStop();
#endif
	for (i = 0; i < SET_THREAD_COUNT; i++) {
		pthread_join(id[i], NULL);
	}
	for (i = 0; i < GET_THREAD_COUNT; i++) {
		pthread_join(id[SET_THREAD_COUNT + i], NULL);
	}
	dump_stats();
	return 0;
}
#endif
#endif
