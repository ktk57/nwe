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
// assume s is a connected socket
void initHTTPHeaders(
		struct KVPArray* h
		)
{
	h->headers = NULL;
	h->size = 0;
}

void initQueryParams(
		struct QueryParams* q
		)
{
	q->params = NULL;
	q->size = 0;
}
int HTTPParserExecute(
		void* parser_obj,
		int args,
		...
		)
{
	va_list list;
	va_start(list, args);

	struct HTTPParser* x = (struct HTTPParser*) parser_obj;
	struct http_parser* parser = &(x->parser);

	http_parser_settings* settings = x->settings;

	unsigned char* buf = va_arg(list, unsigned char*);
	int len = var_arg(list, int);

	size_t nparsed = http_parser_execute(parser, settings, buf, len);

	if (nparsed != (size_t)len) {
		return -1;
	}
	fprintf(stderr,
			"Error: %s (%s)\n",
			http_errno_description(HTTP_PARSER_ERRNO(&parser)),
			http_errno_name(HTTP_PARSER_ERRNO(&parser)));
	return EXIT_FAILURE;
	return 0;
}

int HTTPParserError(
		void* parser_obj,
		int args,
		...
		)
{
	va_list list;
	va_start(list, args);

	struct HTTPParser* x = (struct HTTPParser*) parser_obj;
	struct http_parser* parser = &(x->parser);

	fprintf(stderr,
			"\nError: %s (%s)\n",
			http_errno_description(HTTP_PARSER_ERRNO(&parser)),
			http_errno_name(HTTP_PARSER_ERRNO(&parser)));
	return 0;
}

int HTTPParserDestroy(
		void* parser_obj,
		int settings,
		void* ctxt
		)
{
	return 0;
}
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
/*
 * Returns the number of bytes that need to be processed by the application
 * *ptr1 would contain the first pointer
 * *bytes1 would contain the bytes to process for first buffer
 * *ptr2 would contain the second pointer
 * rc - *byte1 contains bytes to process for second buffer
 */

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
socklen_t len;
struct sockaddr_storage addr;
char ipstr[INET6_ADDRSTRLEN];
int port;

len = sizeof addr;
getpeername(s, (struct sockaddr*)&addr, &len);

// deal with both IPv4 and IPv6:
if (addr.ss_family == AF_INET) {
    struct sockaddr_in *s = (struct sockaddr_in *)&addr;
    port = ntohs(s->sin_port);
    inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
} else { // AF_INET6
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
    port = ntohs(s->sin6_port);
    inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
}

printf("Peer IP address: %s\n", ipstr);
printf("Peer port      : %d\n", port);
//ev_set_userdata(loop, &fd)
void receiveLoop(int sock, int epfd, char recvbuf[]) {
	ssize_t m;
	int numSent;
	struct epoll_event event;

	while(1) {
		//m = recv(sock, recvbuf, EXPECTED_RECV_LEN, 0);
		m = read(sock, recvbuf, EXPECTED_RECV_LEN);
		fprintf(stderr, "\nrecv() called and returned %d\n", m);
		//m = recv(sock, recvbuf, 1000, 0);
		if (m==0) break;
		if (m > 0) {
			recvbuf[m] = '\0';
			if (m == EXPECTED_RECV_LEN && !strcmp(recvbuf, EXPECTED_HTTP_REQUEST)) {
				fprintf(stderr, "\nhi\n");
				numSent = send(sock, RESPONSE, RESPONSE_LEN, 0);
				if (numSent == -1) {
					perror("send failed");
					exit(-1);
				}
				if (numSent != RESPONSE_LEN) {
					perror("partial send");
					exit(-1);
				}
				if (eventfd_write(evfd, 1)) {
					perror("eventfd_write");
					exit(-1);
				}
			} else { 
				perror("partial recv");
				exit(-1);
			}
		}
		if (m==-1) {
			if (errno==EAGAIN || errno == EWOULDBLOCK) {
				// re-arm the socket with epoll.
				fprintf(stderr, "\nArming again");
				event.data.fd = sock;
				event.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
				if (epoll_ctl(epfd, EPOLL_CTL_MOD, sock, &event)) {
					perror("rearm epoll_ctl");
					exit(-1);
				}
				break;
			} else {
				perror("recv");
				exit(-1);
			}
		}
	}
}

void startWakeupThread(void) {
	pthread_t wait_thread;
	if (pthread_create(&wait_thread, NULL, wakeupThreadLoop, NULL) != 0) {
		perror("Thread create failed.");
		exit(-1);
	}
}

void * wakeupThreadLoop(void * null) {

	evfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (evfd == -1) {
		perror("eventfd failed");
		exit(-1);
	}
#ifdef READ_EVENT_FD
	int epfd;
	struct epoll_event event;
	struct epoll_event *events;
	uint64_t val;
	int n;

	epfd = epoll_create1(0);
	events = calloc (1, sizeof event);
	event.data.fd = evfd;
	event.events = EPOLLIN;

	if (epoll_ctl (epfd, EPOLL_CTL_ADD, evfd, &event)) {
		perror("epoll_ctl");
		exit(-1);
	}
	while(1) {
		n = epoll_wait(epfd, events, 1, -1);
		if (n>0) {
			if (eventfd_read(evfd, &val)) {
				perror("eventfd_read");
				exit(-1);
			}
		}
	}
#else
	sleep(20);
#endif
	pthread_exit(NULL);
}

// Sleep for 10 seconds, then show the sockets which have data.
void startSocketCheckThread(void) {
	pthread_t thread;
	if (pthread_create(&thread, NULL, socketCheck, (void *)NULL)) {
		perror("pthread_create");
		exit(-1);
	}
	return;
}

void *socketCheck(void * arg) {
	int i, bytesAvailable;
	sleep(10);
	for (i = 0; i < NUM_CLIENTS; i++) {
		if (ioctl(sockets[i], FIONREAD, &bytesAvailable) < 0) {
			perror("ioctl");
			exit(-1);
		}
		if (bytesAvailable > 0) {
			printf("socket %d has %d bytes of data ready\n", sockets[i], bytesAvailable);
		}
	}
	pthread_exit(NULL);
}
#endif
