#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <time.h> 

#include <pthread.h>
//#include <sys/eventfd.h>
#include <stdint.h>

#include <fcntl.h>
#include <signal.h>
#include "ev.h"
#include "hp.h"
#include "Handlers.h"
#include "Err.h"
#include "mtwist.h"


#ifdef DEBUG
void printHandlers(
		const struct URLActionsAndHandler* handlers,
		int left,
		int right
		)
{
	while (left <= right) {
		fprintf(stderr, "\n%s : %s : %u", handlers[left].url, handlers[left].fptr_name, handlers[left].actions);
		left++;
	}
	fprintf(stderr, "\n");
}
#endif

/*
 * ALL the configuration settings go here
 * Including the TCP tuning parameters
 */
extern int g_num_worker_threads;
extern int g_port_num;
extern int g_listen_backlog;
/*
 * Number of timeouts...can't explain it better
 */
extern int g_hint_num_of_timeouts;

extern const char* g_listening_ip;
/*
 * Size of the application circular read buffer per connection
 */
extern int g_tcp_conn_r_buf;
/*
 * Size of the application circular write buffer per connection
 */
/*
 * TODO this won't be required now
 */

/*
 extern int g_tcp_conn_w_buf; 
 */

/*
 * Timeout for waiting to receive data on a TCP connection
 */
extern int g_tcp_conn_r_timeout;
/*
 * Timeout for waiting to write data to the kernel bufffers on a TCP connection
 * write()/writev() should ideally never block until or unless the send buffer
 * is configured to a very low value AND/OR the peer application is never(or very slowly)
 * picking up data from its TCP
 */
extern int g_tcp_conn_w_timeout;

/*
 * Callback settings for http request and response parsing respectively
 */
http_parser_settings g_http_req_settings;
/*
 * TODO not required RIGHT NOW
 */
/*
 *
 http_parser_settings g_http_res_settings;
 */


/*
 * Structure containing information about a worker thread
 * A worker thread is one that should-never-block(ideally)
 */
struct Reactor* g_reactors;

//#define NUM_WORKERS 20
//#define g_num_worker_threads 1
//#define MAX_EVENTS 500
//#define NUM_CLIENTS 500

// Define this and the program will print the request made
// by the http client and then exit.
// #define SHOW_REQUEST

// This makes the bug more likely to happen, but it can happen without this.
//#define READ_EVENT_FD

// Fill this in with the http request that your
// weighttp client sends to the server. This is the
// request that I get.
#if 0
char EXPECTED_HTTP_REQUEST[] =
"GET / HTTP/1.1\r\nHost: 192.168.1.58:8080\r\n"
"User-Agent: weighttp/0.3\r\nConnection: keep-alive\r\n\r\n";
int EXPECTED_RECV_LEN;

char RESPONSE[] =
"HTTP/1.1 200 OK\r\n"
"Date: Tue, 09 Oct 2012 16:36:18 GMT\r\n"
"Content-Length: 151\r\n"
"Server: Mighttpd/2.8.1\r\n"
"Last-Modified: Mon, 09 Jul 2012 03:42:33 GMT\r\n"
"Content-Type: text/html\r\n\r\n"
"<html>\n<head>\n<title>Welcome to nginx!</title>\n</head>\n"
"<body bgcolor=\"white\" text=\"black\">\n"
"<center><h1>Welcome to nginx!</h1></center>\n</body>\n</html>\n";
size_t RESPONSE_LEN;
#endif

/*
 * Initializes the Reactor structure for all worker threads
 * TODO add the memory allocators as well
 * Heaven holds the faithful RETARDED
 */

static int sortHandlers(
		const void* l,
		const void* r
		)
{
	const struct URLActionsAndHandler* left = (const struct URLActionsAndHandler*) l; 
	const struct URLActionsAndHandler* right = (const struct URLActionsAndHandler*) r; 
	return strcmp(left->url, right->url);
}

static int installURLHandler(
		struct Reactor* rtr,
		struct URLActionsAndHandler* src
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(rtr != NULL && src != NULL);
#endif
	int ret = 0;
	int size = rtr->n_url_handlers;
	if (size < MAX_URL_HANDLERS) {
		rtr->url_handler_info[size++] = *src;
		rtr->n_url_handlers = size;
	} else {
		ret = ERR_BUFF_OVERFLOW;
	}
	return ret;
}
static void initWorkers(
		struct Reactor* reactors,
		int n,
		int n_timeouts
		)
{
	int i;
	int ret = 0;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	errno = 0;
#endif
	struct ev_loop* loop = NULL;

	for (i = 0; i < n; i++) {
		loop = ev_loop_new(0);
		if (loop == NULL) {
			fprintf(stderr, "\nERROR ev_loop_new() failed %s:%d\n", __FILE__, __LINE__);
			exit(-1);
		}

		/*
		 * 
		 * a) either the new accept4()'ed connection to the worker thread
		 * OR
		 * b) send the value of < 0 to the worker thread, which is a
		 * signal to the worker thread to shutdown
		 */
		ret = pipe2(g_reactors[i].r_w_pipe, O_CLOEXEC | O_NONBLOCK);
		if (ret < 0) {
			perror("\nERROR pipe2() failed");
			exit(-1);
		}
		g_reactors[i].loop = loop;
		initTimerListMap(&(reactors[i].timers));
		ret = setTimerListMap(&(reactors[i].timers), n_timeouts);
		if (ret != 0) {
			fprintf(stderr, "\nERROR setTimerListMap() failed %s:%d\n", __FILE__, __LINE__);
			exit(-1);
		}
		/*
		 * TODO TODO
		 * Put the handler information here
		 * TODO TODO
		 */
		mt_state* rand_state = (mt_state*) malloc(sizeof(mt_state));
		if (rand_state == NULL) {
			fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
			exit(-1);
		}
		mts_seed(rand_state);
		/*
		 * Install the URL handlers here
		 */
		struct URLActionsAndHandler handlers[] = 
		{
			{
				"/helloWorld", HTTP_PARSE_QUERY_PARAMS | HTTP_PARSE_HEADERS | HTTP_PARSE_COOKIES, helloWorld, NULL
				//"/helloWorld", 0, helloWorld, NULL
#ifdef DEBUG
					, "helloWorld()"
#endif
			},
			{
				"/dsp", HTTP_PARSE_QUERY_PARAMS, dspSim, NULL
#ifdef DEBUG
					, "dspSim()"
#endif
			},
			{
				"/getSP", HTTP_PARSE_QUERY_PARAMS, getSP, (void*) rand_state
#ifdef DEBUG
					, "getSP()"
#endif
			}
		};

		int size = sizeof(handlers)/sizeof(struct URLActionsAndHandler);

		for (int j = 0; j < size; j++) {
			ret = installURLHandler(&g_reactors[i], &handlers[j]);
			if (ret != 0) {
				fprintf(stderr, "\nERROR installURLHandler() failed %s:%d\n", __FILE__, __LINE__);
				exit(-1);
			}
		}
		if (size > 1) {
			qsort(g_reactors[i].url_handler_info, size, sizeof(struct URLActionsAndHandler), sortHandlers);
		}
#ifdef DEBUG
		printHandlers(g_reactors[i].url_handler_info, 0, size - 1);
#endif
	}
}

static void initHTTPReqCBs(
		http_parser_settings* settings
		)
{
	/*
	 * Mandatory
	 */
	settings->on_message_begin = onHTTPReqMsgBegin;
	settings->on_url = onHTTPReqURL;
	/*
	 * Next 3 are ALL Optional OR ALL 3 Mandatory
	 */
	settings->on_header_field = onHTTPReqHeaderField;
	settings->on_header_value = onHTTPReqHeaderValue;
	settings->on_headers_complete = onHTTPReqHeadersComplete;
	/*
	 * Next is optional
	 */
	settings->on_body = onHTTPReqBody;
	/*
	 * Mandatory
	 */
	settings->on_message_complete = onHTTPReqMsgComplete;
}

/*
 * This callback is invoked when the main thread writes to the loop's pipe write fd
 * to indicate an incoming accept()'ed connection
 *
 * OR 
 *
 * Some other thread signals this worker thread to shutdown
 * TODO
 * THIS function IS THE "hot" PATH
 */
static void newConnOrShutdownCB(
		struct ev_loop* loop,
		ev_io* w,
		int revents
		)
{
	(void) w;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(revents & EV_READ);
	errno = 0;
#else
	(void) revents;
#endif

	int fd;
	int ret = 0;

	// TODO VERIFY THIS
	struct Reactor* reactor = (struct Reactor*) ev_userdata(loop);
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(reactor != NULL);
#endif

	if (sizeof(int) != (ret = read(reactor->r_w_pipe[0], &fd, sizeof(int)))) {
		/*
		 * There could be wrong "read-readiness" notification
		 */
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			goto END;
		} else {
			/*
			 * If read() failed because of some other reason, we better
			 * puke it
			 */
			/*
			 * Any error here is probably NON-RECOVERABLE
			 * hence the assert()
			 */
			fprintf(stderr, "\nERROR read() return with ret = %d, errno = %d %s:%d\n", ret, errno, __FILE__, __LINE__);
			assert(0);
		}
	}

	if (fd < 0) {
		/*
		 * if shutdown
		 * TODO, we need to write this....
		 * do the cleanup for this thread
		 * and do shutdown
		 */
		//ev_stop(loop, w);
		ev_break(loop, EVBREAK_ONE);
		/*
		 * TODO for now
		 */
		exit(1);
	} else {
		/*
		 * fd is the accept4()'ed connection socket fd
		 */
		/*
		 * Create a corresponding parser for the data expected on this connection
		 * Last argument identifies if we need to parse http headers
		 */
		struct HTTPParser* parser = createHTTPParser(HTTP_REQUEST);
		if (parser != NULL) {

			struct TCPConnInfo* conn = TCPConnInit(fd, g_tcp_conn_r_buf, /*g_tcp_conn_w_buf,*/ g_tcp_conn_r_timeout, g_tcp_conn_w_timeout, APP_HTTP_PARSER, (void*) parser, reactor, processHTTPReqCB, processWriteReadyCB/*processHTTPWriteReadyCB*/, readTimeoutCB, writeTimeoutCB);
			if (conn == NULL) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				fprintf(stderr, "\nERROR TCPConnInit() failed %s:%d\n", __FILE__, __LINE__);
#endif
				destroyHTTPParser(parser);
				if (close(fd) != 0) {
					perror("\nERROR close() failed");
					assert(0);
				}
			}
		} else {
			if (close(fd) != 0) {
				perror("\nERROR close() failed");
				assert(0);
			}
		}
	}
END:
	return;
}

static void* workerLoop(
		void* arg
		)
{

	int w = (int) (intptr_t) arg;

	struct ev_loop* loop = g_reactors[w].loop;

	/*
	 * So that we can always get the Reactor from the loop
	 */

	ev_set_userdata(loop, &(g_reactors[w]));


	ev_io io_new_conn_or_shutdown_watcher;
	ev_io_init(&io_new_conn_or_shutdown_watcher, newConnOrShutdownCB, g_reactors[w].r_w_pipe[0], EV_READ);
	ev_io_start(loop, &io_new_conn_or_shutdown_watcher);

	bool ret = ev_run(loop, 0);
	fprintf(stderr, "\nERROR thread returning from ev_run() with return value = %d %s:%d\n", ret, __FILE__, __LINE__);
#if 0
	if (ret == true) {
		fprintf("\nERROR All events have been processed and no watcher is active, ev_run() has exited\n");
		sleep(10);
	} else {
		fprintf("\nERROR ev_run() exited due to break either due to shutdown or ERROR...thread is exiting\n");
		break;
	}
#endif
	return NULL;
}

static void startWorkers()
{
	int i;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	errno = 0;
#endif
	for (i = 0; i < g_num_worker_threads; i++) {
		pthread_t thread;

		if ((errno = pthread_create(&thread, NULL, workerLoop, (void *)(intptr_t) i)) != 0) {
			perror("\nERROR pthread_create() failed");
			exit(-1);
		}
	}
}

static void acceptLoop()
{
	/*
	 * Listening socket
	 */
	int sd;
	/*
	 * TODO make this work for IPv6
	 * Should we enable IPv6 and listen on IPv6 address?
	 * I don't think so. The only requirement we need to fulfill is that 
	 * an IPv6 client doesn't face any problem communicating with this
	 * server
	 * TODO how to make this server listen to multiple IP addresses
	 * Eg. listen on a.b.c.d and e.f.g.h and NOT on i.j.k.l
	 * I think that would require maintainig 2 listening sockets instead of 1
	 */
	struct sockaddr_in addr;
	socklen_t alen = sizeof(addr);
	short port = g_port_num;
	int sock_tmp;
	int current_worker = 0;
	int optval;
	int ret = 0;
	errno = 0;

	if (-1 == (sd = socket(AF_INET, SOCK_STREAM, 0))) {
		perror("\nERROR socket() failed");
		exit(-1);
	}

	addr.sin_family = AF_INET;

	/*
	 * TODO Current implementation can bind one or ALL interfaces
	 * and no other combination
	 */

	if (g_listening_ip == NULL || (strcmp(g_listening_ip, "0.0.0.0") == 0)) {
		addr.sin_addr.s_addr = INADDR_ANY;
	} else {
		ret = inet_pton(AF_INET, g_listening_ip, &(addr.sin_addr.s_addr));
		if (ret != 1) {
			if (errno != 0) {
				perror("\nERROR inet_pton() failed");
			} else {
				fprintf(stderr, "\nERROR inet_pton() failed with ret = %d for ip:%s %s:%d\n", ret, g_listening_ip, __FILE__, __LINE__);
			}
			exit(-1);
		}
	}

	addr.sin_port = htons(port);

	optval = 1;
	/*
	 * TODO GET ALL the socket options HERE
	 * TODO SET ALL the socket options HERE
	 * TODO error checking
	 */
	ret = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (ret < 0) {
		perror("\nERROR setsockopt() failed");
		exit(-1);
	}

	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr))) {
		perror("\nERROR bind() failed");
		exit(-1);
	}

	if (listen(sd, g_listen_backlog)) {
		perror("\nERROR listen() failed");
		exit(-1);
	}

	fprintf(stderr, "\nThe server is listening on %s:%d\n", g_listening_ip == NULL?"NULL":g_listening_ip, g_port_num);

	while(1) {
		/*
		 * THIS IS THE "hot" PATH
		 */
		if (0 > (sock_tmp = accept4(sd, (struct sockaddr*)&addr, &alen, SOCK_NONBLOCK | SOCK_CLOEXEC))) {
			perror("\nERROR accept4() failed");
			assert(0);
		}
#ifdef DEBUG
		fprintf(stderr, "\nDEBUG A new connection accept4()'ed fd = %d %s:%d\n", sock_tmp, __FILE__, __LINE__);
#endif

		/*
		 * Pass this new connection to the worker loop
		 * TODO this is DEFINITELY an OVERHEAD...Don't know how to remove this
		 * i.e per connection accept4()'ed, there are 2 system calls i.e write() by the
		 * accept4() thread and read() by the worker thred before any ACTUAL work starts
		 * for that connection
		 */

		if (sizeof(int) != (ret = write(g_reactors[current_worker].r_w_pipe[1], &sock_tmp, sizeof(int)))) {
			/*
			 * Implicit assumption here is that write() shouldn't block EVER for this pipe
			 * If EVER this happens we can change this to make the code more robust in case of 
			 * write() blocks....which ideally should never happen...but can't say when the
			 * load is exceptionally HIGH or We are draining out all the Kernel buffers
			 * TODO Should I change the code right now? Naaaah!
			 * Code change required here is HUGE, you need one more event loop
			 * I don't think this situation SHALL ever come.
			 */
			fprintf(stderr, "\nERROR write() failed with ret = %d, errno = %d %s:%d\n", ret, errno, __FILE__, __LINE__);
			assert(0);
		}

		// Move the following to a init_conn
		/*
			 sockets[current_client] = sock_tmp;
			 event.data.fd = sock_tmp;
			 event.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
			 epoll_ctl(g_workers[current_worker].efd, EPOLL_CTL_ADD, sock_tmp, &event);
			 current_client++;
			 */
		current_worker = (current_worker + 1) % g_num_worker_threads;
	}
	fprintf(stderr, "\nERROR acceptLoop() is breaking...%s:%d\n", __FILE__, __LINE__);
}

int main()
{
	/*
		 EXPECTED_RECV_LEN = strlen(EXPECTED_HTTP_REQUEST);
		 fprintf(stderr, "\n%d\n", EXPECTED_RECV_LEN);
		 RESPONSE_LEN = strlen(RESPONSE);
		 */
	/*
	 * Ignore the SIGPIPE signal
	 * TODO, use a function better than signal & work on other signals as well
	 */

	signal(SIGPIPE, SIG_IGN);
	/*
	 * TODO Read the config file...will code later
	 * TODO
	 */
	g_reactors = (struct Reactor*) malloc(sizeof(struct Reactor) * g_num_worker_threads);
	if (g_reactors == NULL) {
		fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
		exit(-1);
	}

	int ret = 0;
	/*
	 * Initialize the Reactor for each thread
	 */
	initWorkers(g_reactors, g_num_worker_threads, g_hint_num_of_timeouts);
	/*
	 * Set the http request parsing settings
	 */
	initHTTPReqCBs(&g_http_req_settings);


	/*
	 * Start the worker threads
	 */

	startWorkers();

	/*
	 * This is purely for safety...mostly not required
	 * Sleep for 3 seconds
	 * Just to ensure that all spawned threads are in epoll_wait() before we start
	 * accept4()'ing
	 */
	errno = 0;
	struct timespec slp;
	slp.tv_sec = 3;
	slp.tv_nsec = 0;
	ret = nanosleep(&slp, NULL);
	if (ret != 0) {
		perror("\nERROR nanosleep() failed");
		exit(-1);
	}

	/*
	 * accept4() loop being run by the main thread
	 */
	acceptLoop();
	return 0;
}
