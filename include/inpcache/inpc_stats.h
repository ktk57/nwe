#ifndef __INPC_STATS__
#define __INPC_STATS__

#define MEM_CROSSED_75_PERCENT "INPC:75CROSS"
void send_inpc_mem_percent_stats(const char* key);

typedef struct {
	unsigned long start_time;									//handled.
	unsigned long copy_get_calls;							//handled. GetHits - get_calls - get_misses - get_expiry_claimed
	unsigned long no_copy_get_calls;					//handled.
	unsigned long get_invalid_params;					//handled.
	unsigned long set_invalid_params;					//handled.
	unsigned long get_misses;									//handled. GetMisses - get_misses + get_expiry_claimed.
	unsigned long get_expiry_claimed;					//handled.
	unsigned long exp_unfetched;							//handled.
	unsigned long lru_access_update;					//handled.
	unsigned long cur_hash_items;
	unsigned long set_calls;									//handled.
	unsigned long set_fail_no_space;					//handled.
	unsigned long set_fail_too_large_object;	//handled.
	unsigned long set_overwrite;							//handled.
	unsigned long total_items;								//handled Set_calls - set_fail_no_space - set_fail_too_large_object
	unsigned long evictions;									//handled.
	unsigned long expired_by_thread;					//handled.
	unsigned long claimed_by_thread;					//handled.
//	unsigned long evictions_unfetched;
	unsigned long ovw_unfetched;							//handled.
	unsigned long hash_size;
	unsigned long max_mem_size;
	unsigned long max_item_size;
	unsigned long page_guideline;
	unsigned long bytes_read;
	unsigned long bytes_written;
}inpc_stats_t;

#endif
