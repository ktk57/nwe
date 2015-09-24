#ifndef __TIMER_H__
#define __TIMER_H__

#include "ev.h"

struct Reactor;
struct Timer;

//typedef void (*FPTRTimeoutCB) (struct ev_loop* loop, struct Timer* timer, void* ctxt, int revents);
typedef void (*FPTRTimeoutCB) (struct Reactor* reactor, struct Timer* timer, void* ctxt, int revents);


struct DList {
	struct Timer* head;
	struct Timer* tail;
	int size;
};

struct TimerList {
	/*
	 * This will be set once and never changed
	 */
	ev_tstamp timeout;
	/*
	 * Actual timer object in the libev library
	 */
	ev_timer timer;

	/*
	 * Doubly-linked-list of timers ALL having the timeout value = "timeout"
	 * i.e all having the same timeout value
	 */
	struct DList timer_list;
};

/*
 * Timer states
 */
enum TimerState {
	TIMER_STATE_UNKNOWN,
	TIMER_STATE_INIT,
	TIMER_STATE_STARTED
};

/*
 * This Timer supports only millisecond level granularity because it
 * uses epoll() which supports only ms level granularity
 */
struct Timer {
#ifdef STRINGENT_ERROR_CHECKING
	/*
	 * This is being used to ensure that the timer timedout at right time
	 */
	struct timespec start_time;
	struct timespec expire_time;
#endif
	/*
	 * This timeout keeps changing.
	 * I know you don't understand this comment
	 */
	ev_tstamp actual_timeout; 
	/*
	 * libev loop to which this timer belongs
	 * TODO is this required?
	 * The Reactor to which this timer belongs
	 */
	struct Reactor* reactor;
	/*
	 * Context passed in the callback
	 */
	void* ctxt;
	/*
	 * Callback to be invoked on timeout
	 */
	FPTRTimeoutCB cb;

	struct Timer* next;
	struct Timer* prev;
	/*
	 * TimerList to which this timer belongs
	 * TimerList identifies all the timers which have the same timeout value say "500ms"
	 */
	struct TimerList* timer_list;
	/*
	 * Timer Stat
	 */
	enum TimerState state;
};

/*
 * Macro functions
 */

struct TimerListMap {
	/*
	 * A dynamically allocated array of TimerList*
	 * We are using an array of TimerList* which will be sorted
	 * according to the timeout of each TimerList
	 */
	struct TimerList** timers;
	int size;
	int max_size;
};
void initTimerListMap(
		struct TimerListMap* map
		);

/*
 * To be called on startup by each thread
 * after calling initTimerListMap
 * AND/OR
 * during call to getTimerList
 *
 * Returns 0 on success and ERR_HEAP_ALLOC_FAILURE
 * in case of realloc() failure
 */
int setTimerListMap(
		struct TimerListMap* map,
		int max_size
		);

/*
 * This function initializes a timer
 * return 0 on success
 * OR
 * ERR_HEAP_ALLOC_FAILURE
 * This function MUST be called for every Timer object
 * atleast(EXACTLY?..for efficieny) ONCE
 */
int initTimer(
		struct Reactor* reactor,
		struct Timer* timer,
		FPTRTimeoutCB cb,
		void* ctxt,
		int timeout
		);

/*
 * Must have called initTimer() at least once before calling this
 */

void startTimer(
		struct Timer* timer
		);

/*
 * Must have called startTimer() before calling this
 */
void stopTimer(
		struct Timer* timer
		);

/*
	 double timeLeft(
	 struct Timer* timer
	 );
	 */
#endif
