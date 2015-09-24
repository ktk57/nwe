#include "hp.h"
#include "Utils.h"
#include <stdbool.h>
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
#include <stddef.h>
#include <stdarg.h>

//#include <pthread.h>
//#include <sys/eventfd.h>
#include <stdint.h>
//#include <sys/epoll.h>
//#include <netinet/tcp.h>
//#include <fcntl.h>
//#include <sys/ioctl.h>

#include "ev.h"
#include "hp.h"
#include "Timer.h"
#include "Err.h"
#include "Constants.h"
#include "Handlers.h"
#include "http_parser.h"


/*
	 http_cb      on_message_begin;
	 http_data_cb on_url;
	 http_data_cb on_status;
	 http_data_cb on_header_field;
	 http_data_cb on_header_value;
	 http_cb      on_headers_complete;
	 http_data_cb on_body;
	 http_cb      on_message_complete;
	 */
/*
 * Allocates and initializes an HTTPParser
 */
/*
 * TODO  TODO
 * avoid code duplication in onHTTPReqHeaderField() and onHTTPReqHeaderValue()
 * callbacks
 *
 * The callbacks on onHTTPReqHeaderField(), onHTTPReqHeaderValue()
 * onHTTPReqHeadersComplete() are OPTIONAL and either all 3 MUST be there
 * OR
 * NONE of the 3 should be there in settings before calling http_parser_execute();
 * onHTTPReqBody() is ALSO Optional, Rest ALL are mandatory(depending upon whether Request
 * or Response is being parsed)
 * TODO  TODO
 */
extern int g_hint_url_size;
extern int g_hint_n_qparams;
extern int g_hint_n_headers;
extern int g_hint_n_cookies;
extern int g_hint_req_body_size;
extern int g_hint_res_header_size;
extern int g_hint_res_body_size;
extern http_parser_settings g_http_req_settings;

static int binSearch(
		const struct URLActionsAndHandler* haystack,
		int left,
		int right,
		const char* url,
		int len
		)
{
	int index = -1;
	while (left <= right) {
		int middle = (left + right)/2;
		if (strncmp(haystack[middle].url, url, len) < 0) {
			left = middle + 1;
		} else if (strncmp(haystack[middle].url, url, len) > 0) {
			right = middle - 1;
		} else {
			index = middle;
			break;
		}
	}
	return index;
}

static uint8_t getActionsAndURLHandler(
		struct URLActionsAndHandler* arr,
		int size,
		const char* url,
		uint16_t len,
		FPTRURLHandler* handler,
		void** app_data
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(url != NULL);
#endif
	uint8_t actions = 0;
	int index = binSearch(arr, 0, size - 1, url, len);
	if (index == -1) {
		actions = 0;
		*handler = defaultHandler;
	} else {
		actions = arr[index].actions;
		*handler = arr[index].handler;
		*app_data = arr[index].app_data;
	}
	return actions;
}

#ifdef DEBUG
static void printSortedQueryParms(
		const char* buf,
		const struct OffsetPair* kvparray,
		int left,
		int right
		)
{
	fprintf(stderr, "\nDEBUG printing the query_params:\n");
	fprintf(stderr, "**********************************\n");
	while (left <= right) {
		fprintf(stderr, "\n%s:%s", buf + kvparray[left].key, buf + kvparray[left].value);
		left++;
	}
	fprintf(stderr, "**********************************\n");
}
static void printSortedHTTPHeaders(
		const struct KeyValuePair* kvparray,
		int left,
		int right
		)
{
	fprintf(stderr, "\nDEBUG printing the headers:\n");
	fprintf(stderr, "**********************************\n");
	while (left <= right) {
		fprintf(stderr, "\n%s:%s", kvparray[left].key, kvparray[left].value);
		left++;
	}
	fprintf(stderr, "**********************************\n");
}

static void printCookies(
		const char* buf,
		struct OffsetPair* kvparray,
		int left,
		int right
		)
{
	fprintf(stderr, "\nDEBUG printing the cookies:\n");
	fprintf(stderr, "**********************************\n");
	while (left <= right) {
		fprintf(stderr, "\n%s:%s", buf + kvparray[left].key, buf + kvparray[left].value);
		left++;
	}
	fprintf(stderr, "**********************************\n");
}
#endif

static int sortHTTPHeaders(
		const void* l,
		const void* r
		)
{
	const struct KeyValuePair* left = (const struct KeyValuePair*) l;
	const struct KeyValuePair* right = (const struct KeyValuePair*) r;
	return strcmp(left->key, right->key);
}

static char* searchCookie(
		char* buf,
		struct OffsetPair* kvparray,
		int left,
		int right,
		const char* key
		)
{
	int index = -1;
	while (left <= right) {
		int middle = (left + right)/2;
		if (strcmp(key, buf + kvparray[middle].key) < 0) {
			right = middle - 1;
		} else if (strcmp(key, buf + kvparray[middle].key) > 0) {
			left = middle + 1;
		} else {
			index = middle;
			break;
		}
	}
	return (index == -1)?NULL:((buf + kvparray[index].value)[0] == '\0'?NULL:buf + kvparray[index].value);
}

static const char* searchQParam(
		const char* url,
		struct OffsetPair* kvparray,
		int left,
		int right,
		const char* key
		)
{
	int index = -1;
	while (left <= right) {
		int middle = (left + right)/2;
		if (strcmp(key, url + kvparray[middle].key) < 0) {
			right = middle - 1;
		} else if (strcmp(key, url + kvparray[middle].key) > 0) {
			left = middle + 1;
		} else {
			index = middle;
			break;
		}
	}
	return (index == -1)?NULL:(((url + kvparray[index].value)[0] == '\0')?NULL:url + kvparray[index].value);
}
static char* searchHeader(
		struct KeyValuePair* kvparray,
		int left,
		int right,
		const char* key
		)
{
	int index = -1;
	while (left <= right) {
		int middle = (left + right)/2;
		if (strcmp(key, kvparray[middle].key) < 0) {
			right = middle - 1;
		} else if (strcmp(key, kvparray[middle].key) > 0) {
			left = middle + 1;
		} else {
			index = middle;
			break;
		}
	}
	return (index == -1)?NULL:(kvparray[index].value[0] == '\0'?NULL:kvparray[index].value);
}

struct HTTPParser* createHTTPParser(
		enum http_parser_type type
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(type == HTTP_REQUEST || type == HTTP_RESPONSE);
#endif
	/*
	 * TODO use allocators instead of malloc
	 */
	struct HTTPParser* p = (struct HTTPParser*) malloc(sizeof(struct HTTPParser));
	if (p != NULL) {
		http_parser_init(&(p->parser), type);
		p->ctxt_last_header_copied = 0;
		p->ctxt_last_header_max_size = 0;
	} else {
		fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
	}
	return p;
}

/*
 * Deallocates and destroys an HTTPParser
 */
void destroyHTTPParser(
		struct HTTPParser* parser
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(parser != NULL);
#endif
	/*
	 * TODO use allocators instead of malloc
	 */
	free(parser);
}

/*
 * Sets the context for an HTTPParser
 */
void setHTTPParserContext(
		struct HTTPParser* parser,
		void* ctxt
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(parser != NULL && ctxt != NULL);
#endif
	parser->parser.data = ctxt;
}

int executeHTTPParser(
		struct HTTPParser* parser,
		const char* ptr,
		int bytes,
		struct TCPConnInfo* conn
		)
{
	(void) conn;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(parser != NULL && ptr != NULL && bytes > 0);
#endif
	http_parser* p = &(parser->parser);
	int ret = 0;
	//HTTPParserLastState state = parser->state;
	//bool parse_headers = parser->parse_headers;
	size_t nparsed = http_parser_execute(p, &g_http_req_settings, ptr, bytes);
	if (p->upgrade) {
		/*
		 * TODO TODO TODO
		 * Handle this
		 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		fprintf(stderr, "\nERROR: p->upgrade is set and nparsed = %lu %s:%d\n", nparsed, __FILE__, __LINE__);
#endif
		assert(0);
	} else if (nparsed != (size_t) bytes) {
		if (HTTP_PARSER_ERRNO(p) != HPE_PAUSED) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			fprintf(stderr, "\nERROR: nparsed = %lu, %s (%s) %s:%d\n", nparsed, http_errno_description(HTTP_PARSER_ERRNO(p)), http_errno_name(HTTP_PARSER_ERRNO(p)), __FILE__, __LINE__);
#endif
			ret = ERR_HTTP_PARSER;
		}
	}
	return ret;
}

void initHTTPMsgDList(
		struct HTTPMsgDList* list
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL);
#endif
	list->head = NULL;
	list->tail = NULL;
	list->next_msg = NULL;
	list->size = 0;
}

/*
 * This is duplicate code...sighh
 */
void insertHTTPMsgAtTail(
		struct HTTPMsgDList* list,
		struct HTTPMsg* msg
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL && msg != NULL);
#endif

	struct HTTPMsg* tail = list->tail;

	msg->next = NULL;

	if (tail == NULL) {
		/*
		 * i.e the list is empty
		 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		assert(list->size == 0);
#endif

		list->head = msg;
		msg->prev = NULL;
	} else {
		/*
		 * there is at least 1 element in the DList
		 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		assert(list->size > 0 && list->head != NULL && list->tail != NULL);
#endif
		msg->prev = tail;
		tail->next = msg;
	}

	list->tail = msg;

	if (list->next_msg == NULL) {
		list->next_msg = msg;
	}

	list->size += 1;
}

/*
 * free() memory of an HTTPMsg
 */
void destroyHTTPMsg(
		struct HTTPMsg* msg
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL);
#endif

	destroyDTextBuff(&(msg->parsed_url.rurl));

	destroyKVPBuffer(&(msg->parsed_url.qparams));

	destroyKVPArray(&(msg->headers));

	destroyKVPBuffer(&(msg->cookies));

	destroyDBinaryBuff(&(msg->body));

	destroyDTextBuff(&(msg->response.header));

	destroyDBinaryBuff(&(msg->response.body));

	free(msg);
}

void destroyHTTPMsgDList(
		struct HTTPMsgDList* list
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL);
#endif
	struct HTTPMsg* msg = list->head;
	struct HTTPMsg* tmp = msg;
	while(msg != NULL) {
		tmp = msg->next;
		if (msg->state >= HTTP_MSG_STATE_HANDLER_INVOKED) {
			/*
			 * This msg will be destroyed when the
			 * finishHTTPMsg() will be invoked for this msg
			 * from the URL handler
			 */
			msg->state = HTTP_MSG_STATE_TCP_CONN_CLOSED;
		} else {
			destroyHTTPMsg(msg);
		}
		msg = tmp;
	}
	free(list);
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
		int fd,
		struct DBinaryBuff* rbuf
		)
{

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(rbuf != NULL && rbuf->size == 0);
#endif

	int max_size = rbuf->max_size;
	void* data = (void*) rbuf->buf;


	/*
	 * reset the errno
	 */

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	errno = 0;
#endif

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
			/*
			 * indicates to the caller that read()/readv() failed
			 */
			fprintf(stderr, "\nERROR recv() failed with errno = %d %s:%d\n", errno, __FILE__, __LINE__);
			nbytes = -2;
		} else {
			/*
			 * It happens only if there is some error in the event mechanism/library
			 * i.e false read "readiness"
			 * Indicates to the caller the read()/readv() would block
			 */
			nbytes = -1;
		}
	} else if (nbytes > 0) {
		/*
		 * i.e case of connection close 
		 * or bytes recv()'ed by the connection socket
		 */
		rbuf->size = nbytes;
	}
	return nbytes;
}

/*
 * returns -2 in case of writev() failure
 * -1 in case writev() blocks
 *  > 0
 *  = 0 ==> I don't believe this will happen in Linux
 *  but still theoretically it is possible
 */

int sendNetwData(
		int fd,
		struct iovec* vio,
		int size
		)
{

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(fd >= 0 && vio != NULL && size > 0);
#endif

	/*
	 * reset the errno
	 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	errno = 0;
#endif

	/*
	 * bytes writev()n to the kernel
	 */
	int nbytes = 0;
	/*
	 * data to be writev()'ed > 0 and contiguous
	 */
	nbytes = writev(fd, vio, size);
	/*
	 * TODO 
	 */

	if (nbytes < 0) {

		if (errno != EAGAIN && errno != EWOULDBLOCK) {

			fprintf(stderr, "\nERROR writev() failed for fd = %d with errno = %d %s:%d\n", fd, errno, __FILE__, __LINE__);
			/*
			 * indicates to the caller that writev() failed
			 */
			nbytes = -2;
		} else {
			/*
			 * It happens only if there is some error in the event mechanism/library
			 * i.e false write "readiness"
			 * Indicates to the caller the writev() would block
			 */
			fprintf(stderr, "\nERROR FWR %s:%d\n", __FILE__, __LINE__);
			nbytes = -1;
		}
	} else if (nbytes == 0) {
		fprintf(stderr, "\nERROR writev() returned 0 %s:%d\n", __FILE__, __LINE__);
		assert(0);
		/*
		 * I don't know if this can happen in Linux or not, but I am surely not handling this
		 * http://stackoverflow.com/questions/3081952/with-c-tcp-sockets-can-send-return-zero
		 */
	}
	return nbytes;
}

void sendHTTPMsgs(
		struct TCPConnInfo* conn,
		struct HTTPMsgDList* msg_list
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(conn != NULL && msg_list != NULL);
#endif
	struct WriteCtxt* ctxt = &(conn->w_ctxt);
	struct HTTPMsg* msg = NULL;
	//while (!is_write_blocked && (msg = removeHTTPMsgDListHead(msg_list)))
	while (!(ctxt->is_write_blocked) && (msg = getHTTPMsgDListHead(msg_list))) {
		if (msg->state == HTTP_MSG_STATE_RESP_COMPLETE) {
			int h_size = msg->response.header.size;
			int b_size = msg->response.body.size;
			int bytes_to_send = h_size + b_size;
			bool register_write_watcher = false;

			ctxt->index = 0;
			struct iovec* vio = ctxt->vio;
			vio[0].iov_base = msg->response.header.buf;
			vio[0].iov_len = h_size;
			if (b_size > 0) {
				vio[1].iov_base = msg->response.body.buf;
				vio[1].iov_len = b_size;
			}
#ifdef DEBUG
			fprintf(stderr, "\nWriting the Response :\n%.*s%.*s\n", (int) vio[0].iov_len, (char*) vio[0].iov_base, (int) vio[1].iov_len, (char*) vio[1].iov_base);
#endif
			int nbytes = (b_size > 0)?sendNetwData(conn->fd, vio, 2):sendNetwData(conn->fd, vio, 1);
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
						 * writev() failed. This is OS error and IMHO, it should manifest in
						 * application crash
						 */
						break;
					}
				case -1:
					{
						/*
						 * writev() is blocking which means there is false write "readiness"
						 * Which means there is some problem with event mechanism/library
						 * 
						 */
						/*
						 * Let it fall through
						 */
					}
				case 0:
					{
						/*
						 * Don't know in which condition this will occur
						 * I think the current decision would lead to 
						 * busy polling.
						 * this is being done in case a connection sends only 1 HTTPMsg
						 * and never sends a message again
						 */
						register_write_watcher = true;
						break;
					}
				default:
					{
						if (nbytes == bytes_to_send) {
							removeHTTPMsg(msg_list, msg);
							destroyHTTPMsg(msg);
#ifdef DEBUG
							fprintf(stderr, "\nDEBUG response http msg written on fd = %d %s:%d\n", conn->fd, __FILE__, __LINE__);
#endif
							if (conn->r_tmr.state == TIMER_STATE_INIT) {
								startTimer(&(conn->r_tmr));
							}
						} else {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
							assert(nbytes < bytes_to_send);
#endif
							if (nbytes >= h_size) {
								ctxt->index = 1;
								vio[1].iov_base = msg->response.body.buf + nbytes;
								vio[1].iov_len -= (nbytes - h_size);
							} else {
								ctxt->index = 0;
								vio[0].iov_base = msg->response.header.buf + nbytes;
								vio[0].iov_len -= nbytes;
							}
							register_write_watcher = true;
						}
					}
			}
			if (register_write_watcher) {
				/*
				 * Start the connection's write readiness watcher and the write-readiness timeout
				 */
				ev_io_start(conn->reactor->loop, &(conn->io_wwatcher));
				startTimer(&(conn->w_tmr));
				ctxt->is_write_blocked = true;
				ctxt->ctxt = (void*) msg;
			}
		} else {
			fprintf(stderr, "\nERROR the msg state is not HTTP_MSG_STATE_RESP_COMPLETE %s:%d\n", __FILE__, __LINE__);
			/*
			 * TODO do we need assertion here?
			 */
			assert(0);
			break;
		}
	}
}


struct HTTPMsg* getHTTPMsg(
		enum http_parser_type type,
		struct TCPConnInfo* conn
		)
{
	/*
	 * TODO use per loop allocators instead of malloc
	 */
	struct HTTPMsg* msg = (struct HTTPMsg*) malloc(sizeof(struct HTTPMsg));
	if (msg != NULL) {

		msg->type = type;
		msg->conn = conn;
		/*
		 * TODO
		 */
		msg->method = HTTP_NONE;
		msg->status_code = 0;
		msg->actions = 0;
		msg->url_handler = NULL;
		msg->state = HTTP_MSG_STATE_INIT;

		/*
		 * commenting the first to avoid memset of struct http_parser_url
		 */

		/*
		 * memset(msg->parsed_url, 0, sizeof(struct HTTPParsedURL));
		 */
		memset(&(msg->parsed_url.rurl), 0, sizeof(struct DTextBuff));
		memset(&(msg->parsed_url.qparams), 0, sizeof(struct KVPParser));
		memset(&(msg->headers), 0, sizeof(struct KVPArray));
		memset(&(msg->body), 0, sizeof(struct DBinaryBuff));
		memset(&(msg->cookies), 0, sizeof(struct KVPParser));
		memset(&(msg->response), 0, sizeof(struct HTTPResponse));

		msg->next = NULL;
		msg->prev = NULL;
	}
	return msg;
}

/*
 * This is duplicate code
 */
void removeHTTPMsg(
		struct HTTPMsgDList* list,
		struct HTTPMsg* msg
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL && msg != NULL);
#endif
	if (list->head == msg) {
		list->head = msg->next;
	} else {
		msg->prev->next = msg->next;
	}
	if (list->tail == msg) {
		list->tail = msg->prev;
	} else {
		msg->next->prev = msg->prev;
	}
	list->size -= 1;
	/*
	 * This is un-necessary but...lets keep it

	 msg->next = NULL;
	 msg->prev = NULL;
	 */
}

struct HTTPMsg* getHTTPMsgDListHead(
		struct HTTPMsgDList* list
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL);
#endif
	return list->head;
}

struct HTTPMsg* removeHTTPMsgDListHead(
		struct HTTPMsgDList* list
		)
{
	struct HTTPMsg* msg = getHTTPMsgDListHead(list);
	if (msg != NULL) {
		removeHTTPMsg(list, msg);
	}
	return msg;
}

struct HTTPMsg* getHTTPMsgDListTail(
		struct HTTPMsgDList* list
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL && list->tail != NULL);
#endif
	return list->tail;
}

/*
 * Returns the next HTTPMsg whose URL handler
 * needs to be invoked
 */
struct HTTPMsg* getNextHTTPMsg(
		struct HTTPMsgDList* list
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(list != NULL);
#endif
	struct HTTPMsg* msg = list->next_msg;
	/*
	 * msg CAN be NULL
	 */
	if (msg != NULL && msg->state == HTTP_MSG_STATE_REQ_COMPLETE) {
		return msg;
	}
	return NULL;
}

/*
 * This is MANDATORY callback
 */
int onHTTPReqMsgBegin(
		http_parser* p
		)
{
#ifdef DEBUG 
	fprintf(stderr, "\n***MESSAGE BEGIN*** %s:%d\n", __FILE__, __LINE__);
#endif
	int ret = 0;
	/*
	 * For an HTTP request, we would have got the HTTP Method by now
	 * NOTE:-
	 * This is not necessarily TRUE
	 */
#if 0
	switch (p->method) {
		case HTTP_HEAD:
		case HTTP_POST:
		case HTTP_GET:
			break;
		default:
			ret = ERR_HTTP_METHOD_NOT_IMPLEMENTED;
			goto END;
	}
#endif

	struct TCPConnInfo* conn = (struct TCPConnInfo*) p->data;
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->in_data;
#if 0
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(state == HTTP_MSG_STATE_NONE || state == HTTP_MSG_STATE_REQ_COMPLETE);
#endif

	/*
	 * TODO VERIFY if this callback can be invoked multiple times EVER?
	 */
	if (state != HTTP_MSG_STATE_NONE && state != HTTP_MSG_STATE_REQ_COMPLETE) {
		/*
		 * TODO is assert(0) required?
		 */
		assert(0);
		goto END;
	}
#endif
	/*
	 * Create and initialize struct HTTPMsg
	 */
	struct HTTPMsg* msg = getHTTPMsg(HTTP_REQUEST, conn);
	if (msg == NULL) {
#ifdef DEBUG
		fprintf(stderr, "\nERROR getHTTPMsg() failed %s:%d\n", __FILE__, __LINE__);
#endif
		ret = ERR_HEAP_ALLOC_FAILURE;
	} else {
		/*
		 * TODO remove this code duplication
		 */
		insertHTTPMsgAtTail(list, msg);
		msg->state = HTTP_MSG_STATE_PARSING_METHOD;
	}
	return ret;
}

/*
 * This is MANDATORY callback for HTTP Response
 */
int onHTTPResStatus(
		http_parser* p,
		const char* at,
		size_t length
		)
{
	(void) p;
	(void) at;
	(void) length;
	fprintf(stderr, "\n***MESSAGE Status***\n\n");
	return 0;
}


/*
 * This is MANDATORY callback for HTTP Request
 */
/*
 * Handle the fact that this callback can be called multiple times
 * for a single header field
 */
int onHTTPReqURL(
		http_parser* p,
		const char* at,
		size_t len
		)
{

#ifdef DEBUG 
	fprintf(stderr, "\nonHTTPReqURL() invoked with %.*s *** %s:%d\n", (int) len, at, __FILE__, __LINE__);
#endif

	int ret = 0;

	struct TCPConnInfo* conn = (struct TCPConnInfo*) p->data;
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->in_data;
	struct HTTPMsg* msg = getHTTPMsgDListTail(list);
	enum HTTPMsgState state = msg->state;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL);
	assert(state == HTTP_MSG_STATE_PARSING_METHOD || state == HTTP_MSG_STATE_PARSING_URL);
#endif

	switch (state) {
		case HTTP_MSG_STATE_PARSING_METHOD:
			{
				/*
				 * this is first time this callback was invoked
				 */
				/*
				 * For an HTTP request, we would have got the HTTP Method by now
				 */
				enum http_method m = (enum http_method) p->method;
				switch (m) {
					case HTTP_HEAD:
					case HTTP_POST:
					case HTTP_GET:
						{
							msg->method = m;
						}
						break;
					default:
						ret = ERR_HTTP_METHOD_NOT_IMPLEMENTED;
						goto END;
				}
				state = HTTP_MSG_STATE_PARSED_METHOD;
			}
			/*
			 * Let it fall through
			 */
		case HTTP_MSG_STATE_PARSED_METHOD:
			{
				/*
				 * this is first time this callback was invoked
				 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				assert(msg->parsed_url.rurl.buf == NULL);
				assert(g_hint_url_size > 0);
#endif
				char* url = NULL;
				int max_size = 0;
				ret = reallocate_mem((unsigned char**) &url, 0, &max_size, (int) len, g_hint_url_size, true);
				if (ret != 0) {
					goto END;
				}
#if 0
				int max_size = (int) ((int) len + 1 < g_hint_url_size)? nextPowerOf2(g_hint_url_size):nextPowerOf2(len + 1);
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				assert(max_size >= (int) len + 1 && max_size >= g_hint_url_size);
#endif
				char* url = malloc(max_size * sizeof(char));
				if (url == NULL) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
					ret = ERR_HEAP_ALLOC_FAILURE;
					goto END;
				}
#endif
				/*
				 * Copy the data
				 */
				memcpy(url, at, len);
				/*
				 * TODO should I avoid this?
				 * No, this is required
				 * this is safe since max_size >= len+1 and max_size >= g_hint_url_size
				 */
				url[len] = '\0';

				msg->parsed_url.rurl.buf = url;
				msg->parsed_url.rurl.max_size = max_size;
				msg->parsed_url.rurl.size = len;

				state = HTTP_MSG_STATE_PARSING_URL;

				break;
			}

		case HTTP_MSG_STATE_PARSING_URL:
			{
				/*
				 * This is a subsequent call to this callback
				 */
				int max_size = msg->parsed_url.rurl.max_size;
				int size = msg->parsed_url.rurl.size;
				char* url = msg->parsed_url.rurl.buf;
				ret = reallocate_mem((unsigned char**) &url, size, &max_size, (int) len, 0, true);
				if (ret != 0) {
					goto END;
				}
#if 0
				int available_space = max_size - size;
				if ((int) len >= available_space) {
					/*
					 * We need to reallocate memory
					 */

					int space_required = len - available_space + 1;
					int tmp_max_size = max_size * 2;
					int tmp_new_size = max_size + space_required;
					/*
					 * TODO check this logic
					 */
					max_size = (tmp_max_size >= tmp_new_size)?tmp_max_size:(int) nextPowerOf2(tmp_new_size);
					char* temp = realloc(url, max_size * sizeof(char));
					if (temp == NULL) {
						/*
						 * TODO 
						 * check if we need to do this here
						 * I am not free()'ing free(url);
						 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
						fprintf(stderr, "\nERROR realloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
						ret = ERR_HEAP_ALLOC_FAILURE;
						goto END;
					}
					url = temp;
				}
#endif

				/*
				 * Copy data
				 */

				memcpy(url + size, at, len);
				size += len;
				url[size] = '\0';

				/*
				 * TODO next 2 statements can be put in "if"
				 * but I believe it won't save much
				 */
				msg->parsed_url.rurl.buf = url;
				msg->parsed_url.rurl.max_size = max_size;
				msg->parsed_url.rurl.size = size;
				/*
				 * Leave the state intact
				 */
				break;
			}
		default:
			{
				assert(0);
			}
	}
END:
	msg->state = state;
	return ret;
}

/*
 * Handle the fact that this callback can be called multiple times
 * for a single header field
 */
/*
 * This is OPTIONAL callback
 */

int onHTTPReqHeaderField(
		http_parser* p,
		const char* at,
		size_t len
		)
{
#ifdef DEBUG 
	fprintf(stderr, "\nonHTTPReqHeaderField() invoked %.*s *** %s:%d\n", (int) len, at, __FILE__, __LINE__);
#endif
	int ret = 0;
	struct TCPConnInfo* conn = (struct TCPConnInfo*) p->data;
	struct HTTPParser* parser = (struct HTTPParser*) conn->parser;
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->in_data;
	struct HTTPMsg* msg = getHTTPMsgDListTail(list);
	enum HTTPMsgState state = msg->state;

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	/*
	 * TODO check this condition
	 */
	assert(msg != NULL && (state == HTTP_MSG_STATE_PARSED_URL || state == HTTP_MSG_STATE_PARSING_URL || state == HTTP_MSG_STATE_PARSING_HEADER_FIELD || state == HTTP_MSG_STATE_PARSING_HEADER_VALUE || state == HTTP_MSG_STATE_PARSING_BODY || state == HTTP_MSG_STATE_PARSING_FOOTER_FIELD || state == HTTP_MSG_STATE_PARSING_FOOTER_VALUE)); 
#endif


REEXECUTE:
	switch (state) {
		case HTTP_MSG_STATE_PARSING_URL:
			{
				/*
				 * We need to parse the URL now since the entire Request Line is in buffer
				 */

				int size = msg->parsed_url.rurl.size;
				char* url = msg->parsed_url.rurl.buf;

				struct http_parser_url* purl = &(msg->parsed_url.purl);

				ret = http_parser_parse_url(url, size, 0, purl);
				if (ret != 0) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					fprintf(stderr, "\nERROR Url: %s could not be parsed %s:%d\n", url, __FILE__, __LINE__);
#endif
					ret = ERR_HTTP_PARSER;
					goto END;
				}

				uint16_t field_set = purl->field_set;
				if (field_set & (1<<UF_PATH)) {
					/*
					 * The parsed URL has path
					 * TODO Can't remove the indirection since field_data is un-named structure
					 * can I do something?
					 */
					uint16_t off = purl->field_data[UF_PATH].off;
					uint16_t length = purl->field_data[UF_PATH].len;

					/*
					 * What all actions are required
					 * HTTP_PARSE_HEADERS, HTTP_PARSE_COOKIES, HTTP_PARSE_QUERY_PARAMS
					 * & what is the URL handler for this path?
					 */
					struct Reactor* rtr = conn->reactor;
					uint8_t actions = getActionsAndURLHandler(rtr->url_handler_info, rtr->n_url_handlers, url + off, length, &(msg->url_handler), &(msg->app_data));
					msg->actions = actions;
					if ((actions & HTTP_PARSE_QUERY_PARAMS) && (field_set & (1<<UF_QUERY))) {
						/*
						 * The URL has query parameter and we need to parse the query parameters for this
						 * PATH
						 */
						off = purl->field_data[UF_QUERY].off;
						length = purl->field_data[UF_QUERY].len;

						struct KVPParser* qparams = &(msg->parsed_url.qparams);
						qparams->buf = url + off;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
						assert(g_hint_n_qparams > 0);
#endif
						ret = parseKVPBuffer(qparams, '&', '=', false, g_hint_n_qparams);
						if (ret != 0) {
							fprintf(stderr, "\nERROR parsing the query string for Url: %s %s:%d\n", url, __FILE__, __LINE__);
							goto END;
						}
#ifdef DEBUG
						printSortedQueryParms(qparams->buf, qparams->kvparray, 0, qparams->size - 1);
#endif
					}
				} else {
					ret = ERR_HTTP_PARSER;
					fprintf(stderr, "\nERROR Url: %s doesn't have UF_PATH set %s:%d\n", url, __FILE__, __LINE__);
					goto END;
				}
				state = HTTP_MSG_STATE_PARSED_URL;
				goto REEXECUTE;
			}

		case HTTP_MSG_STATE_PARSING_BODY:
			{
				/*
				 * We have got the complete body
				 */
				state = HTTP_MSG_STATE_PARSED_BODY;
				goto REEXECUTE;
			}

		case HTTP_MSG_STATE_PARSING_HEADER_VALUE:
		case HTTP_MSG_STATE_PARSING_FOOTER_VALUE:
			{
				/*
				 * We have got the complete header value
				 * 
				 */
				/*
				 * Reset the parser ctxt
				 */
				parser->ctxt_last_header_max_size = 0;
				parser->ctxt_last_header_copied = 0;
				/*
				 * Increase the size of headers parsed
				 */
				struct KVPArray* headers = &(msg->headers);
				headers->size += 1;

				switch (state) {
					case HTTP_MSG_STATE_PARSING_HEADER_VALUE:
						{
							state = HTTP_MSG_STATE_PARSED_HEADER_VALUE;
							break;
						}
					case HTTP_MSG_STATE_PARSING_FOOTER_VALUE:
						{
							state = HTTP_MSG_STATE_PARSED_FOOTER_VALUE;
							break;
						}
					default:
						{
							assert(0);
						}
				}
				goto REEXECUTE;
			}

		case HTTP_MSG_STATE_PARSED_URL:
		case HTTP_MSG_STATE_PARSED_HEADER_VALUE:
		case HTTP_MSG_STATE_PARSED_BODY:
		case HTTP_MSG_STATE_PARSED_FOOTER_VALUE:
			{
				/*
				 * Do you want to write a comment?
				 * This is a new header
				 */
				if (msg->actions & HTTP_PARSE_HEADERS) {
					struct KVPArray* headers = &(msg->headers);
					struct KeyValuePair* kvparray = headers->kvparray;
					int max_size = headers->max_size;
					int size = headers->size;

					if (size >= max_size) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
						assert(g_hint_n_headers > 0);
#endif
						max_size = (max_size == 0)? (int) nextPowerOf2(g_hint_n_headers):(max_size * 2);
						struct KeyValuePair* temp = NULL;
						temp = (struct KeyValuePair*) realloc(kvparray, max_size * sizeof(struct KeyValuePair));
						if (temp == NULL) {
							/*
							 * TODO 
							 * check if we need to do this here
							 * I am not free()'ing earlier memory
							 */
							fprintf(stderr, "\nERROR realloc() failed %s:%d\n", __FILE__, __LINE__);
							ret = ERR_HEAP_ALLOC_FAILURE;
							goto END;
						}
						kvparray = temp;
						// TODO
						headers->kvparray = kvparray;
						headers->max_size = max_size;
					}

					struct KeyValuePair* kvp = &(kvparray[size]);
					/*
					 * So that free() doesn't cause problem in case of ERROR handling in half baked cases
					 * free(NULL);
					 */
					kvp->key = NULL;
					kvp->value = NULL;
					/*
					 * TODO this is to avoid fragmentation
					 * but will cause memory wastage
					 * lets see how good/bad it performs
					 */
					int key_size = 0;
					ret = reallocate_mem((unsigned char**) &(kvp->key), 0, &key_size, (int) len, 0, true);
					if (ret != 0) {
						goto END;
					}

#if 0
					int key_size = (int) nextPowerOf2(len + 1);
					kvp->key = (char*) malloc(sizeof(char) * key_size);
					if (kvp->key == NULL) {
						fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
						ret = ERR_HEAP_ALLOC_FAILURE;
						goto END;
					}
#endif
					/*
					 * copy the data
					 */
					memcpy(kvp->key, at, len);
					kvp->key[len] = '\0';
					parser->ctxt_last_header_copied = len;
					parser->ctxt_last_header_max_size = key_size;
				} else {
					/*
					 * The last state remains intact
					 */
#ifdef DEBUG
					fprintf(stderr, "\nDEBUG Header Parsing for %.*s is not set %s:%d\n", (int) len, at, __FILE__, __LINE__);
#endif
					goto END;
				}
				switch (state)
				{
					case HTTP_MSG_STATE_PARSED_URL:
					case HTTP_MSG_STATE_PARSED_HEADER_VALUE:
						{
							state = HTTP_MSG_STATE_PARSING_HEADER_FIELD;
							break;
						}
					case HTTP_MSG_STATE_PARSED_BODY:
					case HTTP_MSG_STATE_PARSED_FOOTER_VALUE:
						{
							state = HTTP_MSG_STATE_PARSING_FOOTER_FIELD;
							break;
						}
					default:
						{
							assert(0);
						}
				}
				break;
			}
		case HTTP_MSG_STATE_PARSING_HEADER_FIELD:
		case HTTP_MSG_STATE_PARSING_FOOTER_FIELD:
			{
				/*
				 * Do you want to write a comment?
				 * This is a called when an old header field was incomplete in last
				 * parser_execute() buffer
				 */
				struct KVPArray* headers = &(msg->headers);
				struct KeyValuePair* kvparray = headers->kvparray;
				int size = headers->size;

				struct KeyValuePair* kvp = &(kvparray[size]);

				int key_max_size = parser->ctxt_last_header_max_size;
				int key_size_copied = parser->ctxt_last_header_copied;

				ret = reallocate_mem((unsigned char**) &(kvp->key), key_size_copied, &key_max_size, (int) len, 0, true);
				if (ret != 0) {
					goto END;
				}
#if 0
				int available_space = key_max_size - key_size_copied;

				if ((int) len >= available_space) {
					/*
					 * Reallocate
					 */
					int space_required = len - available_space + 1;
					int tmp_max_size = key_max_size * 2;
					int tmp_new_size = key_max_size + space_required;
					/*
					 * TODO check this logic
					 */
					key_max_size = (tmp_max_size >= tmp_new_size)?tmp_max_size:(int) nextPowerOf2(tmp_new_size);

					char* temp = NULL;
					temp = (char*) realloc(kvp->key, sizeof(char) * key_max_size);
					if (temp == NULL) {
						/*
						 * TODO
						 * kvp->key should be free()'ed in error handling
						 */
						fprintf(stderr, "\nERROR realloc() failed %s:%d\n", __FILE__, __LINE__);
						ret = ERR_HEAP_ALLOC_FAILURE;
						goto END;
					}
					kvp->key = temp;
				}
#endif

				/*
				 * copy the data
				 */

				memcpy(kvp->key + key_size_copied, at, len);

				key_size_copied += len;

				kvp->key[key_size_copied] = '\0';

				/*
				 * key_max_size already modified above(if required)
				 */
				parser->ctxt_last_header_copied = key_size_copied;
				parser->ctxt_last_header_max_size = key_max_size;
				/*
				 * Leave the last state intact
				 */
				break;
			}
		default:
			assert(0);
	}

END:
	msg->state = state;
	return ret;
}

/*
 * This is OPTIONAL callback
 */
/*
 * Handle the fact that this callback can be called multiple times
 * for a single header value
 */

int onHTTPReqHeaderValue(
		http_parser* p,
		const char* at,
		size_t len
		)
{
#ifdef DEBUG 
	fprintf(stderr, "\nonHTTPReqHeaderValue() invoked %.*s *** %s:%d\n", (int) len, at, __FILE__, __LINE__);
#endif
	int ret = 0;
	struct TCPConnInfo* conn = (struct TCPConnInfo*) p->data;
	struct HTTPParser* parser = (struct HTTPParser*) conn->parser;
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->in_data;
	struct HTTPMsg* msg = getHTTPMsgDListTail(list);
	enum HTTPMsgState state = msg->state;

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	/*
	 * TODO check this condition
	 */
	assert(msg != NULL && (state == HTTP_MSG_STATE_PARSED_URL || state == HTTP_MSG_STATE_PARSING_HEADER_FIELD || state == HTTP_MSG_STATE_PARSING_HEADER_VALUE || state == HTTP_MSG_STATE_PARSING_FOOTER_FIELD || state == HTTP_MSG_STATE_PARSING_FOOTER_VALUE)); 
#endif


	switch (state) {

		case HTTP_MSG_STATE_PARSING_HEADER_FIELD:
		case HTTP_MSG_STATE_PARSING_FOOTER_FIELD:
			{
				/*
				 * We have got the complete header/footer field
				 * 
				 */
				/*
				 * Reset the parser ctxt
				 */
				parser->ctxt_last_header_max_size = 0;
				parser->ctxt_last_header_copied = 0;

				switch (state) {
					case HTTP_MSG_STATE_PARSING_HEADER_FIELD:
						{
							state = HTTP_MSG_STATE_PARSED_HEADER_FIELD;
							break;
						}
					case HTTP_MSG_STATE_PARSING_FOOTER_FIELD:
						{
							state = HTTP_MSG_STATE_PARSED_FOOTER_FIELD;
							break;
						}
					default:
						{
							assert(0);
						}
				}
			}
			/*
			 * Let it fall through 
			 */

		case HTTP_MSG_STATE_PARSED_HEADER_FIELD:
		case HTTP_MSG_STATE_PARSED_FOOTER_FIELD:
			{
				/*
				 * Do you want to write a comment?
				 * This is a new header value
				 */
				struct KVPArray* headers = &(msg->headers);
				struct KeyValuePair* kvparray = headers->kvparray;
				int size = headers->size;

				struct KeyValuePair* kvp = &(kvparray[size]);

				/*
				 * TODO this is to avoid fragmentation
				 * but will cause memory wastage
				 * lets see how good/bad it performs
				 */
				int value_size = 0;
				ret = reallocate_mem((unsigned char**) &(kvp->value), 0, &value_size, (int) len, 0, true);
				if (ret != 0) {
					goto END;
				}
#if 0
				int value_size = (int) nextPowerOf2(len + 1);
				kvp->value = (char*) malloc(sizeof(char) * value_size);
				if (kvp->value == NULL) {
					fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
					ret = ERR_HEAP_ALLOC_FAILURE;
					goto END;
				}
#endif
				/*
				 * copy the data
				 */
				memcpy(kvp->value, at, len);
				kvp->value[len] = '\0';
				parser->ctxt_last_header_copied = len;
				parser->ctxt_last_header_max_size = value_size;

				switch (state)
				{
					case HTTP_MSG_STATE_PARSED_HEADER_FIELD:
						{
							state = HTTP_MSG_STATE_PARSING_HEADER_VALUE;
							break;
						}
					case HTTP_MSG_STATE_PARSED_FOOTER_FIELD:
						{
							state = HTTP_MSG_STATE_PARSING_FOOTER_VALUE;
							break;
						}
					default:
						{
							assert(0);
						}
				}
				break;
			}

		case HTTP_MSG_STATE_PARSING_HEADER_VALUE:
		case HTTP_MSG_STATE_PARSING_FOOTER_VALUE:
			{
				/*
				 * Do you want to write a comment?
				 * This is a called when an old header value was incomplete in last
				 * parser_execute() buffer
				 */
				struct KVPArray* headers = &(msg->headers);
				struct KeyValuePair* kvparray = headers->kvparray;
				int size = headers->size;

				struct KeyValuePair* kvp = &(kvparray[size]);

				int value_max_size = parser->ctxt_last_header_max_size;
				int value_size_copied = parser->ctxt_last_header_copied;

				ret = reallocate_mem((unsigned char**) &(kvp->value), value_size_copied, &value_max_size, (int) len, 0, true);
				if (ret != 0) {
					goto END;
				}
#if 0
				int available_space = value_max_size - value_size_copied;

				if ((int) len >= available_space) {
					/*
					 * Reallocate
					 */

					/*
					 * Reallocate
					 */
					int space_required = len - available_space + 1;
					int tmp_max_size = value_max_size * 2;
					int tmp_new_size = value_max_size + space_required;
					/*
					 * TODO check this logic
					 */
					value_max_size = (tmp_max_size >= tmp_new_size)?tmp_max_size:(int) nextPowerOf2(tmp_new_size);

					char* temp = NULL;
					temp = (char*) realloc(kvp->value, sizeof(char) * value_max_size);
					if (temp == NULL) {
						/*
						 * TODO
						 * kvp->value should be free()'ed in error handling
						 */
						fprintf(stderr, "\nERROR realloc() failed %s:%d\n", __FILE__, __LINE__);
						ret = ERR_HEAP_ALLOC_FAILURE;
						goto END;
					}
					kvp->value = temp;
				}
#endif

				/*
				 * copy the data
				 */

				memcpy(kvp->value + value_size_copied, at, len);

				value_size_copied += len;

				kvp->value[value_size_copied] = '\0';

				/*
				 * value_max_size already modified
				 */
				parser->ctxt_last_header_copied = value_size_copied;
				parser->ctxt_last_header_max_size = value_max_size;
				/*
				 * Leave the last state intact
				 */
				break;
			}
		case HTTP_MSG_STATE_PARSED_URL:
			{
				goto END;
				/*
				 * Let the state remain intact
				 */
			}

		default:
			{
				assert(0);
			}
	}

END:
	msg->state = state;
	return ret;
}

/*
 * This is OPTIONAL callback
 */
/*
 * TODO
 * assumption, this will be invoked only once per http message
 */
int onHTTPReqHeadersComplete(
		http_parser* p
		)
{
#ifdef DEBUG 
	fprintf(stderr, "\nonHTTPReqHeadersComplete() invoked *** %s:%d\n", __FILE__, __LINE__);
#endif
	struct TCPConnInfo* conn = (struct TCPConnInfo*) p->data;
	struct HTTPParser* parser = (struct HTTPParser*) conn->parser;

	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->in_data;
	struct HTTPMsg* msg = getHTTPMsgDListTail(list);
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	/*
	 * TODO check this condition
	 */
	assert(msg != NULL && (msg->state == HTTP_MSG_STATE_PARSED_URL || msg->state == HTTP_MSG_STATE_PARSING_HEADER_VALUE || msg->state == HTTP_MSG_STATE_PARSING_URL));
#endif
	if (msg->state == HTTP_MSG_STATE_PARSING_HEADER_VALUE) {
		/*
		 * Increase the size of headers parsed
		 */
		struct KVPArray* headers = &(msg->headers);
		headers->size += 1;
	}

	parser->ctxt_last_header_copied = 0;
	parser->ctxt_last_header_max_size = 0;
	msg->state = HTTP_MSG_STATE_HEADERS_COMPLETE;
	return 0;
}

/*
 * This is OPTIONAL callback
 */
/*
 * Handle the fact that this callback can be called multiple times
 * for a single http message
 */
int onHTTPReqBody(
		http_parser* p,
		const char* at,
		size_t len
		)
{
#ifdef DEBUG 
	fprintf(stderr, "\nonHTTPReqBody() invoked %.*s *** %s:%d\n", (int) len, at, __FILE__, __LINE__);
#endif
	int ret = 0;
	struct TCPConnInfo* conn = (struct TCPConnInfo*) p->data;
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->in_data;
	struct HTTPMsg* msg = getHTTPMsgDListTail(list);
	enum HTTPMsgState state = msg->state;

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	/*
	 * TODO check this condition, the last state will be there only if settings doesn't
	 * contain on_header_field and on_header_value callbacks
	 */
	assert(msg != NULL && (state == HTTP_MSG_STATE_HEADERS_COMPLETE || state == HTTP_MSG_STATE_PARSING_BODY || state == HTTP_MSG_STATE_PARSING_URL));
#endif

	switch (state) {
		case HTTP_MSG_STATE_PARSING_URL:
		case HTTP_MSG_STATE_HEADERS_COMPLETE:
			{
				state = HTTP_MSG_STATE_PARSING_BODY;
			}
			/*
			 * Fall through
			 */
		case HTTP_MSG_STATE_PARSING_BODY:
			{
				struct DBinaryBuff* body = &(msg->body);
				unsigned char* buf = body->buf;
				int size = body->size;
				int max_size = body->max_size;

				ret = reallocate_mem((unsigned char**) &buf, size, &max_size, (int) len, g_hint_req_body_size, true);
				if (ret != 0) {
					goto END;
				}
#if 0
				int available_space = max_size - size;

				if ((int) len >= available_space) {

					/*
					 * Reallocate
					 */
					int space_required = len - available_space + 1;
					int tmp_max_size = max_size * 2;
					int tmp_new_size = max_size + space_required;

					/*
					 * TODO check this logic
					 */
					max_size = (max_size == 0)? (int) nextPowerOf2((int) len + 1 > g_hint_req_body_size?(int) len + 1:g_hint_req_body_size): (tmp_max_size >= tmp_new_size)?tmp_max_size:(int) nextPowerOf2(tmp_new_size);

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					/*
					 * TODO
					 * this is incomplete check???
					 */
					assert(max_size >= (int) len + 1 && max_size >= g_hint_req_body_size);
#endif
					unsigned char* temp = NULL;
					temp = (unsigned char*) realloc(buf, max_size * sizeof(unsigned char));
					if (temp == NULL) {
						/*
						 * TODO 
						 * check if we need to do this here
						 * I am not free()'ing earlier memory
						 */
						fprintf(stderr, "\nERROR realloc() failed %s:%d\n", __FILE__, __LINE__);
						ret = ERR_HEAP_ALLOC_FAILURE;
						goto END;
					}
					buf = temp;
					body->buf = buf;
					body->max_size = max_size;
				}
#endif
				memcpy(buf + size, at, len);
				size += len;
				buf[size] = '\0';

	/*
	 * The next 2 statements can be in "if" condition
	 */
				body->buf = buf;
				body->max_size = max_size;
				body->size = size;
				break;
				/*
				 * Leave the state intact
				 */
			}
		default:
			{
				assert(0);
			}
	}
END:
	return ret;
}

/*
 * This is MANDATORY callback
 */

int onHTTPReqMsgComplete(
		http_parser* p
		)
{
#ifdef DEBUG 
	fprintf(stderr, "\nonHTTPReqMsgComplete() invoked *** %s:%d\n", __FILE__, __LINE__);
#endif
	int ret = 0;
	struct TCPConnInfo* conn = (struct TCPConnInfo*) p->data;
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->in_data;
	struct HTTPMsg* msg = getHTTPMsgDListTail(list);

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	enum HTTPMsgState state = msg->state;
	/*
	 * TODO check this condition, the last state will be there only if settings doesn't
	 * contain on_header_field and on_header_value callbacks
	 */
	assert(msg != NULL && (state == HTTP_MSG_STATE_HEADERS_COMPLETE || state == HTTP_MSG_STATE_PARSING_BODY || state == HTTP_MSG_STATE_PARSING_URL));
#endif

	msg->state = HTTP_MSG_STATE_REQ_COMPLETE;

	uint8_t actions = msg->actions;
	if (actions & HTTP_PARSE_HEADERS) {
		struct KVPArray* headers = &(msg->headers);
		struct KeyValuePair* kvparray = headers->kvparray;
		int size = headers->size;
		if (size > 1) {
			qsort(kvparray, size, sizeof(struct KeyValuePair), sortHTTPHeaders);
#ifdef DEBUG
			printSortedHTTPHeaders(kvparray, 0, size - 1);
#endif
		}
		if (actions & HTTP_PARSE_COOKIES) {
			char* cookie_header_value = searchHeader(kvparray, 0, size - 1, "Cookie");
			if (cookie_header_value != NULL) {
				struct KVPParser* cookies = &(msg->cookies);
				cookies->buf = cookie_header_value;
				ret = parseKVPBuffer(cookies, ';', '=', true, g_hint_n_cookies);
				if (ret != 0) {
					fprintf(stderr, "\nERROR parsing the cookie_header_value for cookies : %s %s:%d\n", cookies->buf, __FILE__, __LINE__);
					goto END;
				}
#ifdef DEBUG
				printCookies(cookies->buf, cookies->kvparray, 0, cookies->size -1);
#endif
			}
		}
	}

	ret = http_should_keep_alive(p);
	if (ret == 0) {
		/*
		 * We need to "pause" the parser here, to ensure that
		 * the client doesn't send another HTTP msg on the same
		 * connnection.
		 * 
		 * If we need to close the connection,
		 * write the "Connection: close"
		 * header to ensure that the client begins the TCP teardown
		 */
		http_parser_pause(p, 1);
		msg->actions |= SEND_CONNECTION_CLOSE_HEADER; 
	} else {
		ret = 0;
	}
END:
	return ret;
}

int initTCPConnBuff(
		struct DBinaryBuff* data,
		int max_size
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(data != NULL && max_size > 0);
#endif

	int ret = 0;

	data->buf = (unsigned char*) malloc(sizeof(unsigned char) * max_size);
	if (data->buf == NULL) {
		ret = ERR_HEAP_ALLOC_FAILURE;
	} else {
		data->max_size = max_size;
		data->size = 0;
	}
	return ret;
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
		struct Reactor* reactor,
		FPTRIOCB io_rcb,
		FPTRIOCB io_wcb,
		FPTRTimeoutCB r_timeout_cb,
		FPTRTimeoutCB w_timeout_cb
		)
{

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(fd >= 0 && r_buf_size > 0 /*&& w_buf_size > 0*/ && r_timeout > 0 && w_timeout > 0 && reactor != NULL && reactor->loop != NULL && io_rcb != NULL && io_wcb != NULL && r_timeout_cb != NULL && w_timeout_cb != NULL && parser != NULL);
#endif

	/*
	 * TODO use a per-thread allocator rather than malloc
	 */
	struct TCPConnInfo* conn = (struct TCPConnInfo*) malloc(sizeof(struct TCPConnInfo));
	if (conn == NULL) {
		fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
		goto END;
	}
#ifdef __cplusplus
	{
#endif
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		errno = 0;
#endif
		conn->fd = fd;
		conn->reactor = reactor;
		/*
		 * conn->todo = 0;
		 * conn->read_timeout = r_timeout;
		 * conn->write_timeout = w_timeout;
		 */

		struct sockaddr_storage addr;
		socklen_t len = sizeof(addr);

#ifdef DEBUG
		char ipstr[INET6_ADDRSTRLEN];
#endif

		if (getpeername(fd, (struct sockaddr*) &addr, &len) != 0) {
			free(conn);
			conn = NULL;
			/*
			 * TODO make this under conditional compilation if we see a lot of genuine errors
			 */
			fprintf(stderr, "\nERROR getpeername() failed with errno = %d %s:%d", errno, __FILE__, __LINE__);
			goto END;
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
			fprintf(stderr, "\nDEBUG Peer IP address: %s and port = %d, %s:%d\n", ipstr, conn->peer_addr.port, __FILE__, __LINE__);
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
			fprintf(stderr, "\nDEBUG Peer IP address: %s and port = %d, %s:%d\n", ipstr, conn->peer_addr.port, __FILE__, __LINE__);
#endif
		}

		/*
		 * initialize the write context
		 * TODO? is there any need for it?
		 * atleast 2 variables needs to be initialized
		 */
		conn->w_ctxt.is_write_blocked = false;
		conn->w_ctxt.ctxt = NULL;

		/*
		 * TODO TODO TODO
		 * 1) Minimize the amount of memory consumed per connection
		 *
		 * Think about a strategy to
		 * 2) Minimize the impact of a DoS attack with minimal impact on run-time efficiency
		 * TODO TODO TODO
		 */

		int ret = 0;

		if ((ret = initTCPConnBuff(&(conn->rbuf), r_buf_size)) != 0) {
			/*
			 * Just crash in case of out-of-memory, 
			 * TODO make this more robust when there is enough time.
			 * Basically to tackle DoS or actual SUPER-SURGE
			 */
			fprintf(stderr, "\ninitTCPConnBuff() failed with ret = %d %s:%d\n", ret, __FILE__, __LINE__);
			free(conn);
			conn = NULL;
			goto END;
		}

		/*
		 * Set the parser
		 */
		conn->parser = parser;

		/*
		 * Set the parser type
		 * TODO this is redundant
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
					setHTTPParserContext((struct HTTPParser*) parser, (void*) conn);

					/*
					 * TODO use per loop allocators instead of malloc()
					 */

					conn->in_data = (void*) malloc(sizeof(struct HTTPMsgDList));
					if (conn->in_data == NULL) {
						fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
						destroyDBinaryBuff(&(conn->rbuf));
						free(conn);
						conn = NULL;
						goto END;
					}
					initHTTPMsgDList((struct HTTPMsgDList*) conn->in_data);
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
		ev_set_priority(&(conn->io_rwatcher), 1);

		/*
		 * Set up the watcher for write I/O on this connection
		 */
		ev_io_init(&(conn->io_wwatcher), io_wcb, fd, EV_WRITE);

		/*
		 * Set I/O callbacks to higher priority so that if timeout and
		 * I/O happens, I/O callback is invoked
		 */
		ev_set_priority(&(conn->io_wwatcher), 1);


		/*
		 * Initialize the read timeout timer for this connection
		 */

		if ((ret = initTimer(reactor, &(conn->r_tmr), r_timeout_cb, (void*) conn, r_timeout)) != 0) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			fprintf(stderr, "\ninitTimer() failed with ret = %d %s:%d\n", ret, __FILE__, __LINE__);
			assert(0);
#endif
			destroyHTTPMsgDList((struct HTTPMsgDList*) conn->in_data);
			destroyDBinaryBuff(&(conn->rbuf));
			free(conn);
			conn = NULL;
			goto END;
		}

		/*
		 * Initialize the write timeout timer for this connection
		 * This will ideally never be started
		 */
		if ((ret = initTimer(reactor, &(conn->w_tmr), w_timeout_cb, (void*) conn, w_timeout)) != 0) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			fprintf(stderr, "\ninitTimer() failed with ret = %d %s:%d\n", ret, __FILE__, __LINE__);
			assert(0);
#endif
			destroyHTTPMsgDList((struct HTTPMsgDList*) conn->in_data);
			destroyDBinaryBuff(&(conn->rbuf));
			free(conn);
			conn = NULL;
			goto END;
		}

		/*
		 * TODO TODO
		 * Always start the I/O watcher before starting the timeout watcher
		 * Start the read I/O watcher
		 */
		ev_io_start(reactor->loop, &(conn->io_rwatcher));

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
#ifdef __cplusplus
	}
#endif
END:
	return conn;
}

void destroyTCPConn(
		struct TCPConnInfo* conn
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	fprintf(stderr, "\nDEBUG destroyTCPConn() called for conn %p, fd %d %s:%d\n", (void*) conn, conn->fd, __FILE__, __LINE__);
#endif

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	errno = 0;
#endif
	/*
	 * Cleanup the parser and msg list
	 */
	switch (conn->parser_type) {
		case APP_HTTP_PARSER:
			{
				destroyHTTPParser((struct HTTPParser*) conn->parser);
				destroyHTTPMsgDList((struct HTTPMsgDList*) conn->in_data);
				break;
			}
		default:
			assert(0);
	}
	/*
	 * destroy the read buffer
	 */
	destroyDBinaryBuff(&(conn->rbuf));
	/*
	 * destroy the write buffer
	 */

	struct ev_loop* loop = conn->reactor->loop;
	/*
	 * Stop the io_rwatcher for this connection
	 */
	ev_io_stop(loop, &(conn->io_rwatcher));
	/*
	 * Stop the io_wwatcher for this connection
	 * TODO will this API cause problem when io_wwatcher is not even started?
	 * I believe it won't be a problem...just checked code
	 */
	ev_io_stop(loop, &(conn->io_wwatcher));
	/*
	 * Stop the read timeout timer
	 */
	stopTimer(&(conn->r_tmr));
	/*
	 * Stop the write timeout timer
	 */
	stopTimer(&(conn->w_tmr));

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
 * It means that we have been waiting for data to arrive on an open connection but it hasn't
 * arrived.
 * Actions :-
 * Stop all the watchers i.e for io and timeout
 * Free the read and write buff
 * Close the connection
 * Free conn_info structure
 */
void readTimeoutCB(
		struct Reactor* reactor,
		struct Timer* timer,
		void* ctxt,
		int revents
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	fprintf(stderr, "\nDEBUG readTimeoutCB() called %s:%d\n", __FILE__, __LINE__);
	assert(revents & EV_TIMER);
#else
	(void) revents;
#endif

	(void) reactor;
	(void) timer;
	destroyTCPConn((struct TCPConnInfo*) ctxt);
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
void writeTimeoutCB(
		struct Reactor* reactor,
		struct Timer* timer,
		void* ctxt,
		int revents
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	fprintf(stderr, "\nDEBUG writeTimeoutCB() called %s:%d\n", __FILE__, __LINE__);
	assert(revents & EV_TIMER);
#else
	(void) revents;
#endif

	(void) reactor;
	(void) timer;
	destroyTCPConn((struct TCPConnInfo*) ctxt);
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
		list->next_msg = msg->next;
		/*
		 * It is possible that msg pointee is no longer
		 * available after call to this handler
		 */
		/*
		 * TODO
		 * get a new Context(Co-routine) from the context-pool 
		 * and execute the handler in that co-routine
		 */
		msg->url_handler(msg->conn->reactor, msg, msg->app_data);
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
#else
	(void) loop;
	(void) revents;
#endif
	/*
	 * Get the TCPConnInfo structure
	 */
	struct TCPConnInfo* conn = (struct TCPConnInfo*) (((char*) w - offsetof(struct TCPConnInfo, io_rwatcher)));
#ifdef DEBUG
	fprintf(stderr, "\nDEBUG, some data availaible on fd = %d %s:%d\n", conn->fd, __FILE__, __LINE__);
#endif
	int ret = 0;

	/*
	 * stop the read timer
	 */

	stopTimer(&(conn->r_tmr));

	/*
	 * Read data from socket
	 */

	int nbytes = recvNetwData(conn->fd, &(conn->rbuf));

	int should_parse = 0;

	//bool start_read_timeout_watcher = true;

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
		case -1:
			{
				/*
				 * read()/readv() is blocking which means there is false read "readiness"
				 * Which means there is some problem with event mechanism/library
				 * TODO TODO TODO 
				 * TODO this WILL cause the READ/WRITE timeout to FIRE LATE or NEVER FIRE AT ALL
				 * Implementing this is some real trouble as it would affect the O(1) efficiency
				 * of Timers
				 * FRR = False Read Readiness Alert
				 * Should be removed in case of extra logs
				 */
				fprintf(stderr, "\nERROR FRR %s:%d\n", __FILE__, __LINE__);
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
				/*
				 * TODO TODO
				 * Can a message be sent and then connection closed from client
				 * before the reply is written?
				 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				fprintf(stderr, "\nDEBUG Client closed connection, destroying the connection conn %p, fd = %d %s:%d\n", (void*) conn, conn->fd, __FILE__, __LINE__);
#endif
			}
			/*
			 * Let it fall through
			 */
		case -2:
			{
				/*
				 * recv()/readv() failed. This is OS error and IMHO, it should manifest in
				 * application crash...No, it shouldn't cause a crash & you're stupid
				 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			fprintf(stderr, "\nERROR destroying the TCP connection since recv() failed for connection %p, fd = %d %s:%d\n", (void*) conn, conn->fd, __FILE__, __LINE__);
#endif
				destroyTCPConn(conn);
				goto END;
			}
		default:
			{
				should_parse = 1;
			}
	}

	if (should_parse == 1) {

		const char* ptr = (const char*) conn->rbuf.buf;

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		assert(nbytes > 0);
#endif
#ifdef DEBUG
		fprintf(stderr, "\nDEBUG data read before calling executeHTTPParser() = %.*s %s:%d\n", (int) nbytes, ptr, __FILE__, __LINE__);
#endif

		struct HTTPParser* parser = (struct HTTPParser*) conn->parser;
		ret = executeHTTPParser(parser, ptr, nbytes, conn);
		if (ret != 0) {
			/*
			 * In case of parsing failure, destroy the TCP connection
			 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			fprintf(stderr, "\nERROR executeHTTPParser() failed %s:%d\n", __FILE__, __LINE__);
#endif
			destroyTCPConn(conn);
			goto END;
		} else {
			/*
			 * reset the rbuf
			 * TODO redundant...IMO ...if assert() in recvNetwData() is removed
			 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			resetDBinaryBuff(&(conn->rbuf));
#endif
			/*
			 * Process the HTTPMsgDList
			 */
			struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->in_data;
			processHTTPMsgDList(list);
		}
	}
	/*
	 * TODO this can't be here
	 * It should be called after writing a response
	 */

#if 0
	if (start_read_timeout_watcher) {
		/*
		 * Start the Read Timer again
		 */
		startTimer(&(conn->r_tmr));
	}
#endif
END:
	return;
}

void processWriteReadyCB(
		struct ev_loop* loop,
		ev_io* w,
		int revents
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(revents & EV_WRITE);
	assert(loop != NULL && w != NULL);
#else
	(void) revents;
#endif
	/*
	 * Get the TCPConnInfo structure
	 */
	struct TCPConnInfo* conn = (struct TCPConnInfo*) (((char*) w - offsetof(struct TCPConnInfo, io_rwatcher)));

	/*
	 * stop the write timer
	 */

	stopTimer(&(conn->w_tmr));

	/*
	 * Write data to socket
	 */
	struct WriteCtxt* w_ctxt = &(conn->w_ctxt);

	int index = w_ctxt->index;
	/*
	 * TODO verify this
	 */
	struct iovec* vio = w_ctxt->vio + index;

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(w_ctxt->is_write_blocked == true && (index == 0 || index == 1));
#endif

	int vcount = 2 - index;
	unsigned char* l_base = NULL;
	int l_len = 0;
	unsigned char* r_base = NULL;
	int r_len = 0;
	if (vcount == 2) {
		l_base = (unsigned char*) vio[0].iov_base;
		l_len = (int )vio[0].iov_len;
		r_base = (unsigned char*) vio[1].iov_base;
		r_len = (int )vio[1].iov_len;
	} else {
		r_base = (unsigned char*) vio[1].iov_base;
		r_len = (int )vio[1].iov_len;
	}
	int bytes_to_send = l_len + r_len;
	int nbytes = sendNetwData(conn->fd, vio, vcount);
	bool stop_write_io_watcher = true;
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
				 * writev() failed. This is OS error and IMHO, it should manifest in
				 * application crash...No it shouldn't...and you're stupid
				 */
				perror("\nERROR writev() failed");
				/*
				 * TODO remove this assertion
				 */
				assert(0);
				break;
			}
		case -1:
			{
				/*
				 * writev() is blocking which means there is false write "readiness"
				 * TODO TODO TODO 
				 * this WILL cause the READ/WRITE timeout to FIRE LATE or NEVER FIRE ATALL
				 * Implementing this is some real trouble as it would affect the O(1) efficiency
				 * of Timers
				 * TODO TODO
				 * Which means there is some problem with event mechanism/library
				 * FWR = False Write Readiness Alert
				 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				fprintf(stderr, "\nERROR FWR %s:%d\n", __FILE__, __LINE__);
#endif
				/*
				 * Let it fall through
				 */
			}
		case 0:
			{
				/*
				 * Don't know in which condition this will occur
				 * I think the current decision would lead to 
				 * busy polling.
				 * this is being done in case a connection sends only 1 HTTPMsg
				 * and never sends a message again
				 */
				stop_write_io_watcher = false;
				break;
			}
		default:
			{
				if (nbytes == bytes_to_send) {
					/*
					 * Get the TCPConnInfo structure
					 */
					struct HTTPMsgDList* msg_list = (struct HTTPMsgDList*) conn->in_data;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					assert(msg_list != NULL);
#endif
					struct HTTPMsg* msg = (struct HTTPMsg*) w_ctxt->ctxt;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					assert(msg != NULL);
#endif
					removeHTTPMsg(msg_list, msg);
					destroyHTTPMsg(msg);
				} else {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					assert(nbytes < bytes_to_send);
#endif
					if (vcount == 2) {
						if (nbytes >= l_len) {
							w_ctxt->index = 1;
							vio[1].iov_base = l_base + nbytes - l_len;
							vio[1].iov_len -= (nbytes - l_len);
						} else {
							w_ctxt->index = 0;
							vio[0].iov_base = l_base + nbytes;
							vio[0].iov_len -= nbytes;
						}
					} else if (vcount == 1) {
						w_ctxt->index = 1;
						vio[1].iov_base = r_base + nbytes;
						vio[1].iov_len -= nbytes;
					}  else {
						assert(0);
					}
					stop_write_io_watcher = false;
				}
			}
	}

	if (stop_write_io_watcher) {
		/*
		 * Stop the connection's write readiness watcher
		 */
		ev_io_stop(loop, &(conn->io_wwatcher));
		w_ctxt->is_write_blocked = false;
	} else {
		/*
		 * Start the write timeout watcher
		 */
		startTimer(&(conn->w_tmr));
		w_ctxt->is_write_blocked = true;
	}
}


/*
 * Public HTTPMsg API
 */


const char* getHTTPMsgQParam(
		struct HTTPMsg* msg,
		const char* param
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL && param != NULL && param[0] != '\0');
#endif
	struct KVPParser* qparams = &(msg->parsed_url.qparams);
	struct OffsetPair* kvparray = qparams->kvparray;
	const char* result = searchQParam(qparams->buf, kvparray, 0, qparams->size - 1, param);
	return result;
}

const char* getHTTPMsgHeader(
		struct HTTPMsg* msg,
		const char* header_name
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL && header_name != NULL && header_name[0] != '\0');
#endif
	struct KVPArray* headers = &(msg->headers);
	struct KeyValuePair* kvparray = headers->kvparray;
	int size = headers->size;
	char* result = searchHeader(kvparray, 0, size - 1, header_name);
	return result;
}

const char* getHTTPMsgCookie(
		struct HTTPMsg* msg,
		const char* cookie_name
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL && cookie_name != NULL && cookie_name[0] != '\0');
#endif
	struct KVPParser* cookies = &(msg->cookies);
	struct OffsetPair* kvparray = cookies->kvparray;
	char* buf = cookies->buf;
	int size = cookies->size;
	char* result = searchCookie(buf, kvparray, 0, size - 1, cookie_name);
	return result;
}
/*
 * Allow the caller to modify the body
 */
unsigned char* getHTTPMsgBody(
		struct HTTPMsg* msg,
		int* len
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL);
#endif
	struct DBinaryBuff* body = &(msg->body);
	*len = body->size;
	return body->buf;
}

/*
 * Write HTTPMsg API
 * Sorry for the bad name
 */
static int writeHTTPHdrInternal(
		struct HTTPMsg* msg,
		const char* src,
		int len
		)
{
	int ret = 0;
	struct HTTPResponse* response = &(msg->response);
	struct DTextBuff* header = &(response->header);
	char* buf = header->buf;
	int size = header->size;
	int max_size = header->max_size;

	ret = reallocate_mem((unsigned char**) &buf, size, &max_size, (int) len, g_hint_res_header_size, true);
	if (ret != 0) {
		goto END;
	}

	memcpy(buf + size, src, len);
	size += len;
	/*
	 * The next 2 statements can be in "if" condition
	 */
	header->buf = buf;
	header->max_size = max_size;
	header->size = size;
END:
	return ret;
}

#if 0
int writeHTTPStatus(
		struct HTTPMsg* msg,
		uint16_t status
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL && (msg->state == HTTP_MSG_STATE_HANDLER_INVOKED || msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED || msg->state == HTTP_MSG_STATE_ERR));
#endif
	int ret = 0;
	if (msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED) {
		ret = ERR_HTTP_MSG_WRITE_REDUNDANT;
	} else {
		msg->response.status = status;
		switch (status) {
			case 200:
				{
					ret = writeHTTPHdrInternal(msg, HTTP_200_OK, sizeof(HTTP_200_OK) - 1);
					if (ret != 0) {
						msg->state = HTTP_MSG_STATE_ERR_NON_RECOVERABLE;
					}
					break;
				}
			case 500:
				{
					ret = writeHTTPHdrInternal(msg, HTTP_500_INTERNAL_ERROR, sizeof(HTTP_500_INTERNAL_ERROR) - 1);
					if (ret != 0) {
						msg->state = HTTP_MSG_STATE_ERR_NON_RECOVERABLE;
					}
					break;
				}
			default:
				{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					fprintf(stderr, "\nERROR Unknown HTTP Response Code %d %s:%d\n", status, __FILE__, __LINE__);
#endif
					assert(0);
				}
		}
	}
	return ret;
}
#endif


int sprintfHTTPHdr(
		struct HTTPMsg* msg,
		const char* fmt,
		...
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL && (msg->state == HTTP_MSG_STATE_HANDLER_INVOKED || msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED || msg->state == HTTP_MSG_STATE_ERR) && fmt != NULL);
#endif
	int ret = 0;

	va_list ap;

	if (msg->state == HTTP_MSG_STATE_ERR || msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED) {
		ret = ERR_HTTP_MSG_WRITE_REDUNDANT;
	} else {
		struct HTTPResponse* response = &(msg->response);
		struct DTextBuff* header = &(response->header);
		char* buf = header->buf;
		int size = header->size;
		int max_size = header->max_size;

		int space_left = max_size - size;
		/*
		 * This ensures that we don't end up allocating memory again and again
		 * for multiple calls of HTTPHdrSprintf() by the client code
		 */
		int len = (space_left == 0)? g_hint_res_header_size - 1 : space_left - 1;

		while (1) {
			ret = reallocate_mem((unsigned char**) &buf, size, &max_size, len, g_hint_res_header_size, true);
			if (ret != 0) {
				break;
			}

			/*
			 * NOTE
			 * One can find the buffer size required by vsnprintf() by using
			 * len = vsnprintf(NULL, 0, fmt, ap) * and then allocate buf of 'len' and 
			 * call vsnprintf again.
			 * But I am assuming that it would be more efficient to call vsnprintf once
			 * and in case more memory is required...just run it again..
			 * Assuming g_hint_res_header_size is a sufficient is MOST of cases
			 *
			 * The above assumption could be completely wrong but the code below assumes it to
			 * be correct.
			 */
			space_left = max_size - size;
			va_start(ap, fmt);
			len = vsnprintf(buf + size, space_left, fmt, ap);
			va_end(ap);
			if (len < space_left) {
				/*
				 * Buffer allocated was sufficient
				 */
				size += len;
				break;
			}
		}
		/*
		 * The next 2 statements can be in "if" condition
		 */
		header->buf = buf;
		header->max_size = max_size;
		header->size = size;
	}
	return ret;
}



int sprintfHTTPBody(
		struct HTTPMsg* msg,
		const char* fmt,
		...
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL && (msg->state == HTTP_MSG_STATE_HANDLER_INVOKED || msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED || msg->state == HTTP_MSG_STATE_ERR) && fmt != NULL);
#endif
	int ret = 0;
	va_list ap;

	if (msg->state == HTTP_MSG_STATE_ERR || msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED) {
		ret = ERR_HTTP_MSG_WRITE_REDUNDANT;
	} else {
		struct HTTPResponse* response = &(msg->response);
		struct DBinaryBuff* body = &(response->body);
		char* buf = (char*) body->buf;
		int size = body->size;
		int max_size = body->max_size;
		int space_left = max_size - size;

		/*
		 * This ensures that we don't end up allocating memory again and again
		 * for multiple calls of HTTPHdrSprintf() by the client code
		 */
		int len = (space_left == 0)? g_hint_res_body_size - 1 : space_left - 1;

		while (1) {
			ret = reallocate_mem((unsigned char**) &buf, size, &max_size, len, g_hint_res_body_size, true);
			if (ret != 0) {
				break;
			}

			/*
			 * NOTE
			 * One can find the buffer size required by vsnprintf() by using
			 * len = vsnprintf(NULL, 0, fmt, ap) * and then allocate buf of 'len' and 
			 * call vsnprintf again.
			 * But I am assuming that it would be more efficient to call vsnprintf once
			 * and in case more memory is required...just run it again..
			 * Assuming g_hint_res_body_size is a sufficient is MOST of cases
			 *
			 * The above assumption could be completely wrong but the code below assumes it to
			 * be correct.
			 */
			//memcpy(buf + size, src, len);
			space_left = max_size - size;
			va_start(ap, fmt);
			len = vsnprintf(buf + size, space_left, fmt, ap);
			va_end(ap);
			if (len < space_left) {
				/*
				 * Buffer allocated was sufficient
				 */
				size += len;
				break;
			}
		}
		/*
		 * The next 2 statements can be in "if" condition
		 */
		body->buf = (unsigned char*) buf;
		body->max_size = max_size;
		body->size = size;
	}
	return ret;
}


int writeHTTPHdr(
		struct HTTPMsg* msg,
		const char* src,
		int len
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL && (msg->state == HTTP_MSG_STATE_HANDLER_INVOKED || msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED || msg->state == HTTP_MSG_STATE_ERR) && src != NULL && len > 0);
#endif
	int ret = 0;
	if (msg->state == HTTP_MSG_STATE_ERR || msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED) {
		ret = ERR_HTTP_MSG_WRITE_REDUNDANT;
	} else {
		ret = writeHTTPHdrInternal(msg, src, len);
	}
	return ret;
}

int writeHTTPBody(
		struct HTTPMsg* msg,
		const char* src,
		int len
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL && (msg->state == HTTP_MSG_STATE_HANDLER_INVOKED || msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED || msg->state == HTTP_MSG_STATE_ERR) && src != NULL && len > 0);
#endif
	int ret = 0;
	if (msg->state == HTTP_MSG_STATE_ERR || msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED) {
		ret = ERR_HTTP_MSG_WRITE_REDUNDANT;
		goto END;
	}
#ifdef __cplusplus
	{
#endif
		struct HTTPResponse* response = &(msg->response);
		struct DBinaryBuff* body = &(response->body);
		unsigned char* buf = body->buf;
		int size = body->size;
		int max_size = body->max_size;
		ret = reallocate_mem((unsigned char**) &buf, size, &max_size, (int) len, g_hint_res_body_size, false);
		if (ret != 0) {
			goto END;
		}
		memcpy(buf + size, src, len);
		size += len;
		/*
		 * The next 2 statements can be in "if" condition
		 */
		body->buf = buf;
		body->max_size = max_size;
		body->size = size;
#ifdef __cplusplus
	}
#endif
END:
	return ret;
}

static int endHTTPHeader(
		struct HTTPMsg* msg
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL);
#endif
#define TEMP_BUF_SIZE 512
	int ret = 0;
	int b_size = msg->response.body.size;
	if (b_size > 0) {
		char buf[TEMP_BUF_SIZE + 1];
		int bytes = 0;
		if (msg->actions & SEND_CONNECTION_CLOSE_HEADER) {
			bytes = snprintf(buf, TEMP_BUF_SIZE + 1, "%s: %d\r\nConnection: close\r\n\r\n", CONTENT_LENGTH, b_size);
		} else {
			bytes = snprintf(buf, TEMP_BUF_SIZE + 1, "%s: %d\r\nConnection: keep-alive\r\n\r\n", CONTENT_LENGTH, b_size);
		}
		/*
		 * NO ERROR CHECKING
		 */
		ret = writeHTTPHdrInternal(msg, buf, bytes);
		if (ret != 0) {
			msg->state = HTTP_MSG_STATE_ERR;
		}
	} else {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		assert(b_size == 0);
#endif
		ret = writeHTTPHdrInternal(msg, CRLF, sizeof(CRLF));
		if (ret != 0) {
			msg->state = HTTP_MSG_STATE_ERR;
		}
	}
	return ret;
}

void finishHTTPMsg(
		struct HTTPMsg* msg
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL && (msg->state == HTTP_MSG_STATE_HANDLER_INVOKED || msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED));
#endif
	int ret = 0;
REEXECUTE:
	switch (msg->state) {
		case HTTP_MSG_STATE_ERR:
			{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				fprintf(stderr, "\nERROR the msg in finishHTTPMsg() is in HTTP_MSG_STATE_ERR state %s:%d\n", __FILE__, __LINE__); 
#endif
				removeHTTPMsg((struct HTTPMsgDList*)msg->conn->in_data, msg);
				destroyHTTPMsg(msg);
				destroyTCPConn(msg->conn);
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				assert(0);
#endif
				break;
			}
		case HTTP_MSG_STATE_HANDLER_INVOKED:
			{
				ret = endHTTPHeader(msg);
				if (ret != 0) {
					goto REEXECUTE;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					assert(0);
#endif
				} else {
					msg->state = HTTP_MSG_STATE_RESP_COMPLETE;
					sendHTTPMsgs(msg->conn, (struct HTTPMsgDList*) msg->conn->in_data);
				}
				break;
			}
		case HTTP_MSG_STATE_TCP_CONN_CLOSED:
			{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				fprintf(stderr, "\nERROR the msg in finishHTTPMsg() is in HTTP_MSG_STATE_TCP_CONN_CLOSED state %s:%d\n", __FILE__, __LINE__); 
#endif
				destroyHTTPMsg(msg);
				break;
			}
		default:
			{
				fprintf(stderr, "\nERROR Invalid state of HTTPMsg %s:%d\n", __FILE__, __LINE__);
				assert(0);
			}
	}
}
