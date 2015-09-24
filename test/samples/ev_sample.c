#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include "ev.h"

#define MAXBUF 124
static void io_cb(EV_P_ ev_io* w, int revents)
{
	int fd;
	int bytes = 0;
	if (revents & EV_WRITE) {
		fprintf(stderr, "\nstdin ready for write\n");
	} else if (revents & EV_READ) {
		fprintf(stderr, "\nstdin ready for read\n");
	} else {
		assert(0);
	}
	char buf[MAXBUF + 1];
	if (revents & EV_READ) {
		fd = *(int*) ev_userdata(loop);
		bytes = read(fd, buf, MAXBUF);
		if (bytes < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				fprintf(stderr, "\nread() would block\n");
			} else {
				perror("read error");
			}
		} else {
			buf[bytes] = '\0';
			fprintf(stderr, "\n%s\n", buf);
		}
		//ev_io_stop(EV_A_ w);
		//ev_break(EV_A_ EVBREAK_ONE);
	}
}
static void timeout_cb(EV_P_ ev_timer* w, int revents)
{
	fprintf(stderr, "\ntimer expired\n");
	//ev_break(EV_A_ EVBREAK_ONE);
	//ev_timer_stop(loop, w);
}
int main()
{
	ev_io io_watcher;
	ev_timer timeout_watcher;
	struct ev_loop* loop = NULL;
	int fd = 0;

	loop = ev_loop_new(0);
	if (loop == NULL) {
		fprintf(stderr, "\nev_loop_new() failed\n");
	}
	ev_set_userdata(loop, &fd);

	ev_io_init(&io_watcher, io_cb, 1, EV_READ);
	//ev_timer_init(&timeout_watcher, timeout_cb, 0.100, 0);
	ev_init(&timeout_watcher, timeout_cb);
	timeout_watcher.repeat = 3;
	ev_io_start(loop, &io_watcher);
	//ev_timer_start(loop, &timeout_watcher);
	ev_timer_again(loop, &timeout_watcher);
	ev_run(loop, 0);
}
