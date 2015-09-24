// gcc -DDEBUG -D_GNU_SOURCE -g -Wall -Wextra -Werror -Wfatal-errors -std=c99 -I/usr/local/include/ -I../../ -I../../include timer_test.c ../../Timer.c ../../util/Utils.c -lev -lrt

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "Timer.h"
#include "ev.h"
#include "server.h"

#define MAX_TMRS 100000
void timercb(
		struct Reactor* reactor,
		struct Timer* tmr,
		void* ctxt,
		int revents
		)
{
	(void) reactor;
	(void) tmr;
	assert(revents & EV_TIMER);
	fprintf(stderr, "\nTimerCB invoked for tmr %d\n", (int)(intptr_t) ctxt);
	startTimer(tmr);
}

int main()
{
#if 0
	ev_tstamp x = ev_now(loop);
	fprintf(stderr, "\n x = %lf and time = %lu\n", x, (unsigned long) time(0));
#endif
	struct Reactor reactor;

	reactor.loop = ev_loop_new(0);
	if (reactor.loop == NULL) {
		fprintf(stderr, "\nERROR ev_loop_new() failed\n");
		exit(-1);
	}
	ev_set_userdata(reactor.loop, &reactor);

	initTimerListMap(&(reactor.timers));
	int ret = setTimerListMap(&(reactor.timers), 10);
	if (ret != 0) {
		fprintf(stderr, "\nERROR setTimerListMap() failed\n");
		exit(-1);
	}

	struct timespec wait_time;
	memset(&wait_time, 0, sizeof(struct timespec));
	wait_time.tv_sec = 0;
	wait_time.tv_nsec = 1000000;
	int x = 1;
	struct Timer t[MAX_TMRS];
	for (int i = 0; i < MAX_TMRS; i++) {
		ret = initTimer(&reactor, &t[i], timercb, (void*) (intptr_t) i, x);
		if (ret != 0) {
			fprintf(stderr, "\nERROR initTimer() failed\n");
			exit(-1);
		}
		startTimer(&t[i]);
		//nanosleep(&wait_time, NULL);
		//ev_now_update(reactor.loop);
	}
	bool rc = ev_run(reactor.loop, 0);
	fprintf(stderr, "\nERROR thread returning from ev_run() with return value = %d %s:%d\n", rc, __FILE__, __LINE__);
	return 0;
}
