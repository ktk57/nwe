#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include "Timer.h"
#include "Err.h"
#include "Utils.h"
#include "hp.h"

#ifdef DEBUG
static void printTimerTimeouts(
		struct TimerListMap* map,
		int left,
		int right
		)
{
	struct TimerList** timers = map->timers;
	fprintf(stderr, "\nDEBUG printing the timers:\n**************************\n");
	while (left <= right) {
		fprintf(stderr, "%d:", (int) timers[left]->timeout);
		left++;
	}
	fprintf(stderr, "Milliseconds\n**************************\n");
}
#endif

static void insertAtTimerListTail(
		struct TimerList* list,
		struct Timer* timer
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL && timer != NULL);
#endif

	struct DList* timer_list = &(list->timer_list);

	struct Timer* tail = timer_list->tail;

	timer->next = NULL;
	if (tail == NULL) {
		/*
		 * i.e the timer_list is empty
		 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		assert(timer_list->size == 0);
#endif
		timer_list->head = timer;
		timer->prev = NULL;
	} else {
		/*
		 * there is at least 1 element in the DList
		 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		assert(timer_list->size > 0 && timer_list->head != NULL && timer_list->tail != NULL);
#endif
		timer->prev = tail;
		tail->next = timer;
	}
	timer_list->tail = timer;
	timer_list->size += 1;
}


/*
 * this is duplicate code
 */
static void removeTimer(
		struct DList* list,
		struct Timer* timer
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL && timer != NULL);
#endif
	if (list->head == timer) {
		list->head = timer->next;
	} else {
		timer->prev->next = timer->next;
	}
	if (list->tail == timer) {
		list->tail = timer->prev;
	} else {
		timer->next->prev = timer->prev;
	}
	list->size -= 1;
	/*
	 * reset the state of the timer which was removed
	 */
	timer->state = TIMER_STATE_INIT;
	/*
	 * This is un-necessary but...lets keep it
	 *
	 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	timer->next = NULL;
	timer->prev = NULL;
#endif
}

static void initDList(
		struct DList* l
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(l != NULL);
#endif
	l->head = NULL;
	l->tail = NULL;
	l->size = 0;
}

static struct Timer* getDListHead(
		struct DList* list
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL);
#endif
	return list->head;
}

/*
static void removeTimerFromTimerList(
		struct TimerList* list,
		struct Timer* timer
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL && timer != NULL);
#endif
	removeTimer(&(list->timer_list), timer);
}
*/

/*
static struct Timer* getDListTail(
		struct DList* list
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL);
#endif
	return list->tail;
}
*/

/*
 * Yeah, the name is pretty bad
 */
static void startRealTimer(
		struct ev_loop* loop,
		struct TimerList* list,
		ev_tstamp timeout
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(loop != NULL && list != NULL);
#endif
#ifdef DEBUG
	fprintf(stderr, "\nstartRealTimer() invoked with timeout:%lf seconds\n", timeout);
#endif
	if (timeout < 0.0) {
		/*
		 * TODO this is a HACK
		 * Might cause performance degradation
		 * I am very tired for now...going ahead with this one
		 * Sorry :-|
		 */
		list->timer.repeat = 0.0001;
	} else {
		list->timer.repeat = timeout;
	}
	ev_timer_again(loop, &(list->timer));
}

/*
 * Stop the libev timer
 */
static void stopRealTimer(
		struct ev_loop* loop,
		struct TimerList* list
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(loop != NULL && list != NULL);
#endif
#ifdef DEBUG
	fprintf(stderr, "\nstopRealTimer() invoked\n");
#endif
	ev_timer_stop(loop, &(list->timer));
}

static int getTimerListTimeout(
		struct TimerList* l
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(l != NULL);
#endif
	return l->timeout;
}

/*
 *
 * Removes the timer
 * and then rearms or stops the REAL timer
 * This function will be called only when we are stopping
 * a timer at the head of TimerList
 * 
 */
static void rearmOrStopTimer(
		struct Reactor* reactor,
		struct TimerList* timer_list,
		struct DList* list
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(reactor != NULL && reactor->loop != NULL && list != NULL && timer_list != NULL && (&(timer_list->timer_list) == list));
#endif

	/*
	 * If we are removing the head timer,
	 * We need to start the libev timer with a new value or stop it
	 * if there are no more timers in the list
	 */
	struct Timer* head = getDListHead(list);
	if (head == NULL) {
		/*
		 * there are no more timers in the TimerList
		 * Stop the libev timer
		 */
		stopRealTimer(reactor->loop, timer_list);
	} else {
		/*
		 * Set a new timeout value
		 */
		ev_tstamp timeout = head->actual_timeout - timeNowD();
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		//fprintf(stderr, "\nTimeNow() = %lf\n", timeNowD());
#endif
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		/*
		 * TODO is the right expectation in case of heavy load???
		 * Imagine the case when data comes and timer times out
		 */
		//assert(timeout > 0.0);
#endif
		//if (timeout >= 0) {
		/*
		 * I believe we should not assume timeout to be non-negative
		 */
		startRealTimer(reactor->loop, timer_list, timeout);
		//}
	}
}

/*
 * TODO need to code this
 */

static void evTimerTimedOutCB(
		struct ev_loop* loop,
		ev_timer* w,
		int revents
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(revents & EV_TIMER);
#endif
#ifdef DEBUG
	fprintf(stderr, "\nevTimerTimedOutCB() invoked\n");
#endif
	struct TimerList* list = (struct TimerList*) (((char*) w - offsetof(struct TimerList, timer)));
	struct DList* timer_list = &(list->timer_list);
	struct Timer* tmr = getDListHead(timer_list);
	double now;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(tmr != NULL && &(tmr->timer_list->timer) == w);
	//assert(tmr->actual_timeout <= (now = timeNowD()));
#endif
	ev_tstamp actual_timeout;
	if (tmr != NULL) {
		do {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			assert(tmr->state == TIMER_STATE_STARTED);
#endif
			removeTimer(timer_list, tmr);
#ifdef STRINGENT_ERROR_CHECKING
			clock_gettime(CLOCK_MONOTONIC_RAW, &(tmr->expire_time));
			fprintf(stderr, "\nDEBUG expire_time - start_time = %lf ms\n", (tmr->expire_time.tv_sec * 1000.0 + tmr->expire_time.tv_nsec/1000000.0) - (tmr->start_time.tv_sec * 1000.0 + tmr->start_time.tv_nsec/1000000.0));
#endif
			/*
			 * TODO TODO 
			 * is this ORDERING correct?
			 * rearmOrStopTimer(tmr, timer_list, true);
			 */
			/*
			 * This is little tedious
			 * TODO * TODO * TODO * TODO
			 * What all operations regarding timer are permitted within this callback?
			 * TODO * TODO * TODO * TODO
			 */
			tmr->cb(tmr->reactor, tmr, tmr->ctxt, revents);
			now = timeNowD();
		} while((tmr = getDListHead(timer_list)) != NULL && (actual_timeout = tmr->actual_timeout) <= now);
		if (tmr == NULL) {
			/*
			 * No more timers left in this list
			 */
			stopRealTimer(loop, list);
		} else {
			/*
			 * Install a new timer
			 */
			ev_tstamp timeout = actual_timeout - now;
			startRealTimer(loop, tmr->timer_list, timeout);
		}
	} else {
		/*
		 * TODO is this possible?
		 */
		assert(0);
	}
}

static void initTimerList(
		struct TimerList* l,
		int timeout
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(l != NULL);
#endif

	l->timeout = timeout;
	initDList(&(l->timer_list));

	/*
	 * init the timer
	 */
	ev_init(&(l->timer), evTimerTimedOutCB);
}
/*
 * This returns the index at which "key" is found
 * On exact match it sets *flag = 1 and sets index accordingly
 * Otherwise it sets index to right most location which has key < "key"
 */
static int searchBinary(
		struct TimerList** timers,
		int left,
		int right,
		int key,
		int* flag
		)
{
	*flag = 0;
	int index = -1;
	while (left <= right) {
		int middle = (left + right)/2;
		if (timers[middle]->timeout < key) {
			left = middle + 1;
			index = middle;
		} else if (timers[middle]->timeout > key) {
			right = middle - 1;
		} else {
			*flag = 1;
			index = middle;
			break;
		}
	}
	return index;
}

/*
 * Returns the TimerList for a given timeout
 * uses binary search
 * returns NULL on error
 */
static struct TimerList* getTimerList(
		struct TimerListMap* map,
		int timeout
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(map != NULL && map->timers != NULL && map->max_size > 0 && timeout > 0);
#endif

	struct TimerList** timers = map->timers;
	int size = map->size;

	struct TimerList* result = NULL;

	/*
	 * Flag to indicate that we got the exact match
	 */

	int flag = 0;

	int index = -1;

	index = searchBinary(timers, 0, size - 1, timeout, &flag);

	if (flag == 1) {
		result = timers[index];
	} else {
		int max_size = map->max_size;
		if (size >= max_size) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			assert(size == max_size);
#endif
			int ret = setTimerListMap(map, max_size * 2);
			if (ret != 0) {
				result = NULL;
				goto END;
			}
		}

		int i = index + 1;
		int j = size - 1;
		struct TimerList* temp = timers[size];
		while (j >= i) {
			timers[j+1] = timers[j];
			j--;
		}
		result = timers[i] = temp;
		initTimerList(result, timeout);
		map->size += 1;
	}
#ifdef DEBUG
	printTimerTimeouts(map, 0, map->size - 1);
#endif
END:
	return result;
}

static void setTimerTimeout(
		struct Timer* timer,
		int timeout
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(timer != NULL && timer->reactor != NULL && timer->reactor->loop != NULL);
#endif
	timer->actual_timeout = timeNowD() + timeout/1000.0;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	//fprintf(stderr, "\nActual Timeout = %lf\n", timer->actual_timeout);
#endif
}

/*
 * PUBLIC API
 */
void initTimerListMap(
		struct TimerListMap* map
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(map != NULL);
#endif
	map->timers = NULL;
	map->size = 0;
	map->max_size = 0;
}

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
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(map != NULL && max_size > 0);
#endif
	int ret = 0;
	struct TimerList** timers = (struct TimerList**) realloc(map->timers, sizeof(struct TimerList*) * max_size);
	if (timers == NULL) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		fprintf(stderr, "\nERROR realloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
		ret = ERR_HEAP_ALLOC_FAILURE;
	} else {
		map->timers = timers;
		int old_size = map->max_size;
		int i = 0;

		for (i = old_size; i < max_size; i++) {
			timers[i] = (struct TimerList*) malloc(sizeof(struct TimerList));
			if (timers[i] == NULL) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
				break;
			}
		}

		map->max_size = i;
		if (i == old_size) {
			ret = ERR_HEAP_ALLOC_FAILURE;
		}
	}
	return ret;
}

/*
 * This function initializes a timer
 * return 0 on success
 * OR
 * ERR_HEAP_ALLOC_FAILURE
 * This function MUST be called for every Timer object
 * atleast(EXACTLY?..for efficieny) ONCE
 */
int initTimer(
		//struct ev_loop* loop,
		struct Reactor* reactor,
		struct Timer* timer,
		FPTRTimeoutCB cb,
		void* ctxt,
		int timeout
		)
{
	/*
	 * Find the TimerList having timeout = "timeout"
	 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(reactor != NULL && reactor->loop != NULL && timer != NULL && cb != NULL && timeout > 0);
#endif
#ifdef DEBUG
	fprintf(stderr, "\nDEBUG initTimer() invoked with timeout = %d %s:%d\n", timeout, __FILE__, __LINE__);
#endif
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	errno = 0;
#endif
	int ret = 0;
	// TODO VERIFY THIS
	//struct Reactor* worker = (struct Reactor*) ev_userdata(reactor);

	struct TimerList* list = getTimerList(&(reactor->timers), timeout);
	if (list == NULL) {
		ret = ERR_HEAP_ALLOC_FAILURE;
		goto END;
	}
#ifdef DEBUG
	fprintf(stderr, "\nDEBUG the list alloted for the timer with timeout = %d is = %p %s:%d\n", timeout, (void*) list, __FILE__, __LINE__);
#endif

	timer->actual_timeout = -1.0;
	timer->reactor = reactor;
	timer->ctxt = ctxt;
	timer->cb = cb;
	timer->next = NULL;
	timer->prev = NULL;
	timer->timer_list = list;
	timer->state = TIMER_STATE_INIT;

END:
	return ret;
}

/*
 * Must have called initTimer() at least once before calling this
 */

void startTimer(
		struct Timer* timer
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(timer != NULL);
	assert(timer->state == TIMER_STATE_INIT || timer->state == TIMER_STATE_STARTED);
#endif
	if (timer->state != TIMER_STATE_STARTED) {
#ifdef STRINGENT_ERROR_CHECKING
		clock_gettime(CLOCK_MONOTONIC_RAW, &(timer->start_time));
#endif
		/*
		 * Get the TimerList to which this timer belongs
		 * This belongingness is set in the initTimer
		 */
		struct TimerList* list = timer->timer_list;

		/*
		 * Insert the Timer at the tail of TimerList
		 */
		insertAtTimerListTail(list, timer);

		/*
		 * Get the TimerList's timeout value
		 */
		int timeout = getTimerListTimeout(list);

		/*
		 * Set the Timer's actual_timeout value
		 * which is absolute rather than relative number
		 */
		setTimerTimeout(timer, timeout);

		struct Timer* head = getDListHead(&(list->timer_list));
		if (head == timer) {
			/*
			 * IF the libev timer needs to be started/restarted with some changed value
			 * Do it.
			 */
			startRealTimer(timer->reactor->loop, timer->timer_list, (ev_tstamp) timeout/1000.0);
		}
		/*
		 * Change the state
		 */
		timer->state = TIMER_STATE_STARTED;
	}

#if 0
	int size = getTimerListSize(list);

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(size > 0);
#endif
#endif
}

/*
 * Must have called startTimer() before calling this
 */
void stopTimer(
		struct Timer* timer
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(timer != NULL);
#endif
	if (timer->state == TIMER_STATE_STARTED) {
		/*
		 * This flag indicates whether this timer was at head of
		 * TimerList or not
		 */
		bool flag = false;
		/*
		 * Get the TimerList to which this timer belongs
		 * This belongingness is set in the initTimer
		 */
		struct TimerList* timer_list = timer->timer_list;
		struct DList* list = &(timer_list->timer_list);

		/*
		 * Check if the timer is at head of TimerList
		 */
		struct Timer* head = getDListHead(list);
		if (head == timer) {
			flag = true;
		}
		/*
		 * Remove the Timer from the TimerList
		 */
		removeTimer(list, timer);
		if (flag == true) {
			rearmOrStopTimer(timer->reactor, timer_list, list);
		}
	}
	return;
}

/*
double timeLeft(
		struct Timer* timer
		)
{
	return timer->actual_timeout - timeNowD();
}
*/
#if 0
/*
 * Change the timestamp of timer in a node
 */
void changeNodeTimestamp(
		struct node* element,
		ev_tstamp timeout
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(element != NULL && timeout > 0.0);
#endif
	element->timeout = timeout;
}
/*
 * Remove a node from the DList and move it to the tail of DList
 */
void moveToTail(
		struct DList* list,
		struct node* element
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(DList != NULL && element != NULL);
#endif
	/*
	 * If element is already at tail of DList
	 * return
	 */
	if (element == list->tail) {
		return;
	}

	/*
	 * If we are here => there are atleast 2 elements in the DList
	 */

	if (list->head == element) {
		/*
		 * If element is at the head of DList
		 */
		list->head = element->next;

	} else {
		/*
		 * element is neither at head nor at tail
		 */
		element->prev->next = element->next;
		element->next->prev = element->prev;

	}

	element->prev = list->tail;
	list->tail->next = element;
	element->next = NULL;
	list->tail = element;
}
void removeHeadTimer(
		struct DList* l
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(l != NULL && l->size >= 1);
#endif
	l->head = l->head->next;
	if (l->size == 1) {
		/*
		 * update the tail as well
		 */
		l->tail = l->head;
	}
	l->head->prev = NULL;
	l->size--;
}

int getDListSize (
		struct DList* l
		)
{
	return l->size;
}
/*
 * Timer list API
 */

int getTimerListSize(
		TimerList* l
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(l != NULL && l->timer_list != NULL);
#endif
	return getDListSize(&(l->timer_list));
}
void incrementTimerListSize(
		TimerList* l
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(l != NULL);
#endif
	return l->timer_list.size++;
}
#endif
