#ifndef __COMMON__
#define __COMMON__

#define true 1
#define false 0

#define min(a, b) (((a) > (b)) ? (b) : (a))

//#define CURRENT_TIME() time(NULL)
#define current_time() g_time
//#define EIGHT_BYTE_ALIGN(val)  ((val%8) ? (val + (8 - (val%8))) : val)
#define CLEANUP_THREAD_SLEEP_INTERVAL 100
#define BACKWARD_EXPIRY_CHECK_LIMIT 100
#define DEF_BACKWARD_EXPIRY_CHECK_LIMIT 20
#define AGGRESSIVE_EXPIRY_SIZE_CUTOFF 40000

#define EXPIRE_CLAIMABLE_ITEM_FLAG (128)
#define __with_lock(args) (args)
#define __with_atomic(args) 
#ifdef WITH_ATOMIC
#define __with_atomic(args) args;
#else
#define __with_atomic(args) 
#endif
#ifdef STATS_ON
#define __stats_check(args) (args)
#else 
#define __stats_check(args)
#endif

#ifdef SEQ_CHECK
#define __seq_check(args) (args)
#else
#define __seq_check(args)
#endif


typedef struct {
	char* ptr;
	uint64_t max_size;
//	int paged_size;
//	int unpaged_size;
	uint64_t used_size;
//	int available_size;
	pthread_mutex_t lock;
}memory_details_t;

#endif
