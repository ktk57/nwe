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
#include <sys/eventfd.h>
#include <stdint.h>
//#include <sys/epoll.h>
//#include <netinet/tcp.h>
//#include <fcntl.h>
//#include <sys/ioctl.h>

#include "ev.h"
//#include "HTTPParser.h"
#include "NetUtils.h"
#include "Timer.h"
#include "Err.h"




/*
 * return 0 on success
 * ERR_HEAP_ALLOC_FAILURE in case of malloc() failure
 */
int netwBuffInit(
		struct TCPConnInfo* conn,
		struct NetwBuff* buf,
		int max_size,
		enum NetwBuffType type
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(type == NETW_BUFF_READ || type == NETW_BUFF_WRITE);
	if (type = NETW_BUFF_READ) {
		assert(conn != NULL && buf != NULL && buf == &(conn->rbuf));
	} else {
		assert(conn != NULL && buf != NULL && buf == &(conn->wbuf));
	}
#endif

	buf->data = (unsigned char*) malloc(sizeof(unsigned char) * max_size);
	if (buf->data == NULL) {
		fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		assert(0);
#endif
		return ERR_HEAP_ALLOC_FAILURE;
	}
	buf->start_index = 0;
	/*
	 * It is a circular buffer
	 */
	buf->end_index = 0;
	buf->max_len = max_size;
	buf->conn = conn;
	buf->empty_space = max_size;
	buf->type = type;
	/*
	 * Should there be a field to specify the space left?
	 * It would remove the need for index arithmetic + some corner cases
	 */
	return 0;
}

int initTCPConnBuff(
		struct TCPConnInfo* conn,
		struct TCPConnBuff* buf,
		int max_size
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(conn != NULL && buf != NULL && buf == &(conn->rbuf));
#endif

	int ret = 0;
	struct DBinaryBuff* data = &(buf->data);

	data->buf = (unsigned char*) malloc(sizeof(unsigned char) * max_size);
	if (data->buf == NULL) {
		fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		assert(0);
#endif
		ret = ERR_HEAP_ALLOC_FAILURE;
		goto END;
	}

	data->max_size = max_size;
	data->size = 0;
	buf->conn = conn;

END:
	return ret;
}

/*
 * Returns the number of bytes that need to be processed by the application
 * *ptr1 would contain the first pointer
 * *bytes1 would contain the bytes to process for first buffer
 * *ptr2 would contain the second pointer
 * rc - *byte1 contains bytes to process for second buffer
 */

#if 0
int netwBuffBytesToProcess(
		struct NetwBuff* buf
		unsigned char** ptr1,
		int* bytes1,
		unsigned char** ptr2
		)
{

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(buf != NULL && buf->type = NETW_BUFF_READ);
#endif

	unsigned char* data = buf->data;
	int start_index = buf->start_index;
	int end_index = buf->end_index;
	int max_size = buf->max_size;
	int result = 0;

	**ptr1 = data + end_index;
	if (start_index <= end_index) {

		*bytes1 = max_size - end_index;
		**ptr2 = data;
		result = *bytes1 + start_index;
	} else {
		*bytes1 = start_index - end_index;
		**ptr2 = NULL;
		result = *bytes1;
	}
	return result;
}
int getTCPConnBytesToProcess(
		struct TCPConnBuff* buf
		)
{

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(buf != NULL);
#endif
	return buf->data.size;
}
#endif

/*
 * 
 void netw_buff_get_data
 *
 */

/*
 * Returns the amount of empty space in the NetwBuff
 */

int netw_buff_empty_space(
		struct NetwBuff* buf
		)
{
	return buf->empty_space;
}

void netwBuffDestroy(
		struct NetwBuff* buf
		)
{
	free(buf->data);
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	buf->data = NULL;
	buf->start_index = 0;
	buf->end_index = 0;
	buf->max_len = 0;
	buf->conn = NULL;
	buf->type = NETW_BUFF_UNDEFINED;
	buf->empty_space = 0;
#endif
}

void destroyTCPConnBuff(
		struct TCPConnBuff* buf
		)
{
	/*
	 * TODO remove code duplication by using destroy
	 * function for &(buf->data)
	 */
	free(buf->data.buf);
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	buf->data.buf = NULL;
	buf->data.size = 0;
	buf->data.max_size = 0;
	buf->conn = NULL;
#endif
}

/*
 * Try to send all of data in the network buffer to the kernel
 * returns > 0 to indicate some bytes were sent to the kernel buffer
 * returns -1 to indicate that send blocked i.e kernel write buffers are full caller must
 * try again to send the data
 * return -2 to indicate that send()/writev() failed
 * return 0, which means that there was nothing to send, which means wrong invocation by
 * caller
 * OR
 * http://stackoverflow.com/questions/3081952/with-c-tcp-sockets-can-send-return-zero
 * that there was something to send but writev return 0 and
 * caller can treat this an "NOT AN ERROR"
 * The caller should try again.
 * I don't know if this can happen in Linux or not, but I am not handling this
 */
int netw_buff_send(
		struct NetwBuff* buf
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(buf->type == NETW_BUFF_WRITE);
#endif
	int fd = buf->conn->fd;
	int start_index = buf->start_index;
	int end_index = buf->end_index;
	int max_size = buf->max_size;
	int empty_space = buf->empty_space;
	void* data = buf->data;

	int bytes_to_send = 0; // number of bytes in the network buffer
	int right_space_filled = 0;
	int left_space_filled = 0;
	/* reset the errno */
	errno = 0;

	int nbytes = 0; // bytes sent to kernel
	if (empty_space == max_size) {
		/*
		 * The write buffer is empty, hence nothing to send
		 * Wrong invocation by the caller
		 */
		nbytes = 0;
	} else {
		/*
		 * There is atleast 1 byte to write to the kernel
		 */
		if (end_index < start_index) {
			/*
			 * data to be sent > 0 and contiguous
			 */
			bytes_to_send = start_index - end_index;
			data = data + end_index;
			nbytes = send(fd, data, bytes_to_send, 0);

		} else {
			/*
			 * Data wraps over or start_index == end_index
			 */
			struct io_vec vec[2];
			int index = 0;
			right_space_filled = max_size - end_index; // this can be 0
			if (right_space_filled > 0) {
				vec[index].iov_base = data + end_index;
				vec[index].iov_len = right_space_filled;
				index++;
			}

			left_space_filled = start_index - 0; // this can be 0

			if (left_space_filled > 0) {
				vec[index].iov_base = data + start_index - 1;
				vec[index].iov_len = left_space_filled;
				index++;
			}
			nbytes = writev(fd, vec, index);
		}
	}

	if (nbytes < 0) {

		if (errno != EAGAIN && errno != EWOULDBLOCK) {

			perror("\nERROR send() failed");
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			assert(0);
#endif
			nbytes = -2; // indicates to the caller that send failed
		} else {
			/*
			 * Ideally this should never happen
			 * It happens only if the caller invoked this function without first writing
			 * anything into the buffer
			 */
			nbytes = -1;// indicates that send would block
		}
	}
	if (nbytes > 0) {
		/*
		 * Update the end_index and empty_space of buffer if something was
		 * writev()
		 */
		end_index = (end_index + nbytes) % max_size;
		empty_space += nbytes;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		assert(end_index >=0 && end_index < max_size);
		assert(empty_space >= 0);
#endif
		buf->end_index = end_index;
		buf->empty_space = empty_space;
	}
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	/*
	 * Verify that errno hasn't been set
	 */
	assert(errno == 0);
#endif
	return nbytes;
}

/*
 * Try to recv as much of the kernel data to the network buffer as possible :p
 * returns > 0 to indicate some bytes were read from the kernel buffer
 * returns -1 to indicate that read blocked i.e kernel read buffers are empty
 * which actually means wrong "read-ready" notification by event mechanism/library
 * return -2 to indicate that recv()/readv() failed
 * return 0 which means that the peer closed the connection
 * return -3 which means that read buffer is full, hence can't recv()/readv() from the kernel
 * i.e application needs to process "previous data" first
 */
int netwBuffRecv(
		struct NetwBuff* buf
		)
{

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(buf->type == NETW_BUFF_READ);
#endif

	int fd = buf->conn->fd;
	int start_index = buf->start_index;
	int end_index = buf->end_index;
	int max_size = buf->max_size;
	int empty_space = buf->empty_space;
	void* data = buf->data;

	/* 
	 * Number of bytes in the network buffer
	 */

	int bytes_to_recv = 0;
	int right_space_left = 0;
	int left_space_left = 0;

	/*
	 * reset the errno
	 */

	errno = 0;
	/*
	 * bytes recv()/readv()'ed from kernel
	 */
	int nbytes = 0;
	if (empty_space == 0) {
		/*
		 * The read buffer is full, hence nothing to recv
		 * The application needs to "process" this data first
		 */
		nbytes = -3;
		goto END;
	} else {
		/*
		 * At least 1 byte can be read from the kernel buffers
		 */
		if (start_index < end_index) {
			/*
			 * data to be recv()'ed > 0 and contiguous
			 */
			bytes_to_recv = end_index - start_index;
			data = data + start_index;
			nbytes = recv(fd, data, bytes_to_recv, 0);

		} else {
			/*
			 * Data wraps over or start_index == end_index
			 */
			struct io_vec vec[2];
			int index = 0;
			/*
			 * this can be 0
			 */
			right_space_left = max_size - start_index;

			if (right_space_left > 0) {
				vec[index].iov_base = data + start_index;
				vec[index].iov_len = right_space_left;
				index++;
			}
			/*
			 * this can be 0
			 */
			left_space_left = end_index;

			if (left_space_left > 0) {
				//vec[index].iov_base = data + end_index - 1;
				vec[index].iov_base = data;
				vec[index].iov_len = left_space_left;
				index++;
			}
			nbytes = readv(fd, vec, index);
		}
	}

	if (nbytes < 0) {

		if (errno != EAGAIN && errno != EWOULDBLOCK) {

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			perror("\nERROR recv() failed");
			assert(0);
#endif
			/*
			 * indicates to the caller that read()/readv() failed
			 */
			nbytes = -2;
		} else {
			/*
			 * It happens only if there is some error in the event mechanism/library
			 * i.e false read "readiness"
			 * Indicates to the caller the read()/readv() would block
			 */
			nbytes = -1;
		}
	}
	if (nbytes > 0) {
		/*
		 * Update the start_index and empty_space of buffer if something was
		 * recv()'ed
		 */
		start_index = (start_index + nbytes) % max_size;
		empty_space += nbytes;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		assert(start_index >=0 && start_index < max_size);
		assert(empty_space >= 0);
#endif
		buf->start_index = start_index;
		buf->empty_space = empty_space;
	}

END:
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	/*
	 * Verify that errno hasn't been set
	 */
	assert(errno == 0);
#endif
	return nbytes;
}

/*
 * Try to recv as much of the kernel data to the network buffer as possible :p
 * returns > 0 to indicate some bytes were read from the kernel buffer
 * returns -1 to indicate that read blocked i.e kernel read buffers are empty
 * which actually means wrong "read-ready" notification by event mechanism/library
 * return -2 to indicate that recv()/readv() failed
 * return 0 which means that the peer closed the connection
 */
int recvNetwData(
		struct TCPConnBuff* buf
		)
{

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(buf != NULL && buf->data.size == 0);
#endif

	int fd = buf->conn->fd;
	int max_size = buf->data.max_size;
	void* data = (void*) buf->data.buf;


	/*
	 * reset the errno
	 */

	errno = 0;

	/*
	 * bytes recv()/readv()'ed from kernel
	 */
	int nbytes = 0;
	/*
	 * data to be recv()'ed > 0 and contiguous
	 */
	nbytes = recv(fd, data, max_size, 0);


	if (nbytes < 0) {

		if (errno != EAGAIN && errno != EWOULDBLOCK) {

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			perror("\nERROR recv() failed");
			assert(0);
#endif
			/*
			 * indicates to the caller that read()/readv() failed
			 */
			nbytes = -2;
		} else {
			/*
			 * It happens only if there is some error in the event mechanism/library
			 * i.e false read "readiness"
			 * Indicates to the caller the read()/readv() would block
			 */
			nbytes = -1;
		}
	}
	buf->data.size = nbytes;
}

int netw_buff_snprintf(
		struct NetwBuff* buf,
		const char* format,
		...
		)
{
	/*
	 * The current implementation is pretty inefficient and SHOULD be replaced with a
	 * better alternative
	 */
	va_list args;
	va_start(args, format);
	int start_index = buf->start_index;
	int end_index = buf->end_index;
	int max_size = buf->max_size;
	void* data = buf->data;

	int space_left = 0;
	int right_space_left = 0;
	int left_space_left = 0;
	int flag = 0; // to indicate that data wraps over in the circular buffer
	if (start_index < end_index) {
		space_left = end_index - start_index;
	} else {
		// data wraps over or space_left = 0;
		flag = 1;
		space_left = max_size - start_index;
		right_space_left = max_size - start_index;
		left_space_left = end_index;
	}
	if (space_left != 0) {
		if (!flag) {
			// Space available is contiguous
			int bytes_written;
			bytes_written = vsnprintf(data, space_left, format, args);
			if (result >= buf->max_size) {
				/* The network buffer is full, we must write it to the kernel */
#ifdef DEBUG
				/*
				 * If this occurs a lot, there is a need to increase the buf->max_size so that we can
				 * avoid extra send() system calls
				 */
				fprintf(stderr, "\nERROR Network buffer is full, writing it to the kernel %s:%d\n", __FILE__, __LINE__);
				errno = 0;
				int nbytes = send(fd, buf->data, buf->max_size, 0);
				if (nbytes < 0) {
					if (errno != EAGAIN && errno != EWOULDBLOCK) {
						perror("\nERROR send() failed");
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
						assert(0);
#endif
					}
				}
				else if (nbytes == 0) {
					/*
					 * I don't know if this can happen in Linux or not, but I am surely not handling this
					 * http://stackoverflow.com/questions/3081952/with-c-tcp-sockets-can-send-return-zero
					 */
				} else {
					/* Data written to kernel buffers, update the netw_buf */
				}
			}
		} else {
		}
	} else {
		/*
		 * There is no space left in the network buffer, write it to the kernel
		 */
	}
	va_end(args);
	return result;
}

/*
 * Initialize a tcp structure from an accept4()'ed fd
 * May be this function needs to be divided into 2 sub functions
 * Common functionality for both connect() and accept4() sockets
 * and then special functions for them respectively
 */
struct TCPConnInfo* TCPConnInit(
		int fd,
		int r_buf_size,
		/*int w_buf_size,*/
		int r_timeout,
		int w_timeout,
		//EV_READ | EV_WRITE,
		//int revents,
		enum ConnDataParserType parser_type,
		void* parser,
		struct ev_loop* loop,
		FPTRIOCB io_rcb,
		FPTRIOCB io_wcb,
		FPTRTimeoutCB r_timeout_cb,
		FPTRTimeoutCB w_timeout_cb
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(fd >= 0 && r_buf_size > 0 /*&& w_buf_size > 0*/ && r_timeout > 0 && w_timeout > 0 && loop != NULL && io_rcb != NULL && io_wcb != NULL && r_timeout_cb != NULL && w_timeout_cb != NULL && parser != NULL);
#endif

	/*
	 * TODO use a per-thread allocator rather than malloc
	 */
	struct TCPConnInfo* conn = (struct TCPConnInfo*) malloc(sizeof(struct TCPConnInfo));
	if (conn == NULL) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
		goto END;
	}

	errno = 0;
	conn->fd = fd;
	conn->loop = loop;
	conn->read_timeout = r_timeout;
	conn->write_timeout = w_timeout;

	socklen_t len;
	struct sockaddr_storage addr;
	len = sizeof(addr);

#ifdef DEBUG
	char ipstr[INET6_ADDRSTRLEN];
#endif

	if (getpeername(fd, (struct sockaddr*) &addr, &len) != 0) {
		perror("\nERROR getpeername() failed");
		exit(-1);
	}

	/*
	 * deal with both IPv4 and IPv6:
	 */
	if (addr.ss_family == AF_INET) {
		struct sockaddr_in* s = (struct sockaddr_in*) &addr;
		conn->peer_addr.port = ntohs(s->sin_port);
		conn->peer_addr.ip.ipv4_addr = s->sin_addr;
#ifdef DEBUG
		inet_ntop(AF_INET, &(conn->peer_addr.ip.ipv4_addr), ipstr, sizeof(ipstr));
		fprintf(stderr, "\nPeer IP address: %s and port = %d, %s:%d\n", ipstr, conn->peer_addr.port, __FILE__, __LINE__);
#endif
	} else {
		/*
		 * AF_INET6
		 */
		struct sockaddr_in6* s = (struct sockaddr_in6 *) &addr;
		conn->peer_addr.port = ntohs(s->sin6_port);
		conn->peer_addr.ip.ipv6_addr = s->sin6_addr;
#ifdef DEBUG
		inet_ntop(AF_INET6, &(conn->peer_addr.ip.ipv6_addr), ipstr, sizeof(ipstr));
		fprintf(stderr, "\nPeer IP address: %s and port = %d, %s:%d\n", ipstr, conn->peer_addr.port, __FILE__, __LINE__);
#endif
	}

	/*
	 * initialize the write context
	 * TODO? is there any need for it?
	 * atleast 1 variable needs to be initialized
	 */
	conn->w_ctxt.is_write_blocked = false;

	/*
	 * TODO TODO TODO
	 * 1) Minimize the amount of memory consumed per connection
	 *
	 * Think about a strategy to
	 * 2) Minimize the impact of a DoS attack with minimal impact on run-time efficiency
	 * TODO TODO TODO
	 */

	int ret = 0;
	/*
	 * if ((ret = netwBuffInit(conn, &(conn->rbuf), r_buf_size, NETW_BUFF_READ)) != 0)
	 */
	if ((ret = initTCPConnBuff(conn, &(conn->rbuf), r_buf_size)) != 0) {
		/*
		 * Just crash in case of out-of-memory, 
		 * TODO make this more robust when there is enough time.
		 * Basically to tackle DoS or actual SUPER-SURGE
		 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		fprintf(stderr, "\ninitTCPConnRBuff() failed with ret = %d %s:%d\n", ret, __FILE__, __LINE__);
		assert(0);
#endif
		free(conn);
		conn = NULL;
		goto END;
	}

#if 0
	if ((ret = netwBuffInit(conn, &(conn->wbuf), w_buf_size, NETW_BUFF_WRITE)) != 0) {
		/*
		 * Just crash in case of out-of-memory, Will make this more robust when there is
		 * enough time.
		 * Basically to tackle DoS or actual SUPER-SURGE
		 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		fprintf(stderr, "\nnetwBuffInit() failed with ret = %d %s:%d\n", ret, __FILE__, __LINE__);
		assert(0);
#endif
		netwBuffDestroy(&(conn->rbuf));
		free(conn);
		conn = NULL;
		goto END;
	}
#endif

	/*
	 * Set the parser
	 */
	conn->parser = parser;

	/*
	 * Set the parser type
	 */
	conn->parser_type = parser_type;
	/*
	 * Depending upon the parser_type, initialize the generic application parser
	 * and message list
	 * TODO This might look UGLY but that's what will be rolled out for now
	 */

	switch(parser_type) {

		case APP_HTTP_PARSER:
			{
				/*
				 * Set the context for the parser
				 */
				setHTTPParserContext((struct HTTPParser*) parser, conn);

				/*
				 * TODO use per loop allocators instead of malloc()
				 */

				conn->msg_list = (struct HTTPMsgDList*) malloc(sizeof(struct HTTPMsgDList));
				if (conn->msg_list == NULL) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
					assert(0);
#endif
					destroyTCPConnBuff(&(conn->rbuf));
					free(conn);
					conn = NULL;
					goto END;
				}
				initHTTPMsgDList(conn->msg_list);
				break;
			}

		default:
			{
				/*
				 * crash in default
				 */
				assert(0);
			}
	}

	/*
	 * Set up the watcher for read I/O on this connection
	 */
	ev_io_init(&(conn->io_rwatcher), io_rcb, fd, EV_READ);
	/*
	 * Set I/O callbacks to higher priority so that if timeout and
	 * I/O happens, I/O callback is invoked first
	 */
	ev_set_priority((&conn->io_rwatcher), 1);

	/*
	 * Set up the watcher for write I/O on this connection
	 */
	ev_io_init(&(conn->io_wwatcher), io_wcb, fd, EV_WRITE);

	/*
	 * Set I/O callbacks to higher priority so that if timeout and
	 * I/O happens, I/O callback is invoked
	 */
	ev_set_priority((&conn->io_wwatcher), 1);


	/*
	 * Initialize the read timeout timer for this connection
	 */

	if ((ret = initTimer(loop, &(conn->r_tmr), r_timeout_cb, conn, r_timeout)) != 0) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		fprintf(stderr, "\ninitTimer() failed with ret = %d %s:%d\n", ret, __FILE__, __LINE__);
		assert(0);
#endif
		destroyHTTPMsgDList(conn->msg_list);
		destroyTCPConnBuff(&(conn->rbuf));
		free(conn);
		conn = NULL;
		goto END;
	}

	/*
	 * Initialize the write timeout timer for this connection
	 * This will ideally never be started
	 */
	if ((ret = initTimer(loop, &(conn->w_tmr), w_timeout_cb, conn, w_timeout)) != 0) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		fprintf(stderr, "\ninitTimer() failed with ret = %d %s:%d\n", ret, __FILE__, __LINE__);
		assert(0);
#endif
		destroyHTTPMsgDList(conn->msg_list);
		destroyTCPConnBuff(&(conn->rbuf));
		free(conn);
		conn = NULL;
		goto END;
	}

	/*
	 * TODO TODO
	 * Always start the I/O watcher before starting the timeout watcher
	 * Start the read I/O watcher
	 */
	ev_io_start(loop, &(conn->io_rwatcher));

	/*
	 * Start the read timeout timer
	 * But don't start the write timeout timer
	 * Start the write timeout timer when write()/writev() blocks
	 */
	startTimer(&(conn->r_tmr));


	/*
	 *
	 */

#if 0
	conn->w_tmr = NULL;

	conn->r_tmr = NULL;
#endif


	/*
	 * Start the read timeout watcher
	 */

	/*
	 * DON'T START THE write I/O watcher, it will be started only when a write blocks
	 */

	/*
	 * Start the read timeout watcher
	 * The first implementation allows one ev_timer per connection....this needs to be made
	 * efficient since we will use a single timeout value for all read operations, a linked
	 * list would be much better providing O(1) timer operations....I know this comment
	 * makes no sense to you.
	 */
	//ev_timer_start(loop, &(conn->read_timeout_watcher));

END:
	return conn;
}


/*
 * It means that we have been waiting for data to arrive on an open connection but it hasn't
 * arrived.
 * Actions :-
 * Stop all the watchers i.e for io and timeout
 * Free the read and write buff
 * Close the connection
 * Free conn_info structure
 */
void readTimeoutCB(
		struct ev_loop* loop,
		ev_timer* w,
		int revents
		)
{
#ifdef DEBUG
	assert(revents & EV_TIMER);
#endif
	struct TCPConnInfo* conn = (struct TCPConnInfo*) (((char*) w - offsetof(struct TCPConnInfo, read_timeout_watcher)));

	conn_destroy(conn);

}

void destroyTCPConn(
		struct TCPConnInfo* conn
		)
{

	errno = 0;
	/*
	 * Cleanup the parser and msg list
	 */
	switch (conn->parser_type) {
		case APP_HTTP_PARSER:
			{
				destroyHTTPParser(struct HTTPParser* (conn->parser));
				destroyHTTPMsgDList(struct HTTPMsgDList* (conn->msg_list))
					break;
			}
		default:
			assert(0);
	}
	/*
	 * destroy the read buffer
	 */
	destroyTCPConnBuff(&(conn->rbuf));
	/*
	 * destroy the write buffer
	 */

	struct ev_loop* loop = conn->loop;
	/*
	 * Stop the io_rwatcher for this connection
	 */
	ev_io_stop(loop, conn->io_rwatcher);
	/*
	 * Stop the io_wwatcher for this connection
	 * TODO will this API cause problem when io_wwatcher is not even started?
	 * I believe it won't be a problem...just checked code
	 */
	ev_io_stop(loop, conn->io_wwatcher);
	/*
	 * Stop the read timeout timer
	 */
	stopTimer(*(conn->r_tmr));
	/*
	 * Stop the read timeout timer
	 */
	stopTimer(*(conn->w_tmr));

	if (close(conn->fd) != 0) {
		perror("\nERROR close() failed");
		assert(0);
	}
	/*
	 * free() the conn structure
	 */
	free(conn);
}
/*
 * It means that we have been trying to write data to an open connection but it hasn't
 * been written within write_timeout_watcher.
 * This shouldn't be called EVER ideally(unless the Kernel buffers are full)
 * or there is some serious issue
 * Actions :-
 * Stop all the watchers i.e for io and timeout
 * Free the read and write buff
 * Close the connection
 * Free conn_info structure
 */
void writeTimeoutCB(struct ev_loop* loop, ev_timer* w, int revents)
{
#ifdef DEBUG
	assert(revents & EV_TIMER);
#endif
	struct TCPConnInfo* conn = (struct TCPConnInfo*) (((char*) w - offsetof(struct TCPConnInfo, write_timeout_watcher)));
	conn_destroy(conn);
}


static void processHTTPMsgDList(
		struct HTTPMsgDList* list
		)
{
	struct HTTPMsg* msg = getNextHTTPMsg(list);
	while (msg != NULL) {
		/*
		 * This message request is complete, call its URL handler
		 */
		msg->state = HTTP_MSG_STATE_HANDLER_INVOKED;
		msg->url_handler(msg);
		list->next_msg = msg->next;
		msg = getNextHTTPMsg(list);
	}
}

void processHTTPReqCB(
		struct ev_loop* loop,
		ev_io* w,
		int revents
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(revents & EV_READ);
	assert(loop != NULL && w != NULL);
#endif
	/*
	 * Get the TCPConnInfo structure
	 */
	struct TCPConnInfo* conn = (struct TCPConnInfo*) (((char*) w - offsetof(struct TCPConnInfo, io_rwatcher)));

	recvNetwData(&(conn->rbuf));

	int nbytes = conn->rbuf.data.size;

	int should_parse = 0;

	switch(nbytes) {
#if 0
		case -3:
			{
				/*
				 * The connection's rbuf is already full, application needs to process it first
				 */
				should_parse = 1;
				break;
			}
#endif
		case -2:
			{
				/*
				 * recv()/readv() failed. This is OS error and IMHO, it should manifest in
				 * application crash
				 */
				perror("\nERROR recv()/readv() failed");
				assert(0);
				break;
			}
		case -1:
			{
				/*
				 * read()/readv() is blocking which means there is false read "readiness"
				 * Which means there is some problem with event mechanism/library
				 */
				break;
			}
		case 0:
			{
				/*
				 * The peer close()'ed the TCP connection. We must do "cleanup"
				 * Cleanup could be tricky as we might get I/O notificaitons for http messages
				 * which are being processed
				 *
				 */
				destroyTCPConn(conn);
				break;
			}
		default:
			{
				should_parse = 1;
			}
	}
	if (should_parse == 1) {

		const char* ptr = conn->rbuf.data.buf;

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		assert(nbytes > 0);
#endif

		struct HTTPParser* parser = (struct HTTPParser*) conn->parser;
		ret = executeHTTPParser(parser, ptr, nbytes);
		if (ret != 0) {
			/*
			 * In case of parsing failure, destroy the TCP connection
			 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			fprintf(stderr, "\nERROR executeHTTPParser() failed %s:%d\n", __FILE__, __LINE__);
#endif
			destroyTCPConn(conn);
		} else {
			/*
			 * Process the HTTPMsgDList
			 */
			struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->msg_list;
			processHTTPMsgDList(list);
		}
	}
}

#if 0
void setNonBlocking(int fd) {
	int flags;
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		perror("Getting NONBLOCKING failed.\n");
		exit(-1);
	}
	if ( fcntl(fd, F_SETFL, flags | O_NONBLOCK ) < 0 ) {
		perror("Setting NONBLOCKING failed.\n");
		exit(-1);
	}
	return;
}
#endif
// assume s is a connected socket
