#include "HTTPParser.h"
#include "Utils.h"
#include <stdbool.h>

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
extern int g_hint_body_size;

#ifdef DEBUG
void printSortedQueryParms(
		const char* buf,
		const struct OffsetPair* kvparray,
		int left,
		int right
		)
{
	while (left <= right) {
		fprintf(stderr, "\n%s:%s", buf + kvparray[left].key, buf + kvparray[left].value);
		left++;
	}
	fprintf(stderr, "\n");
}
void printSortedHTTPHeaders(
		const struct KeyValuePair* kvparray,
		int left,
		int right
		)
{
	while (left <= right) {
		fprintf(stderr, "\n%s:%s", kvparray[left].key, kvparray[left].value);
		left++;
	}
	fprintf(stderr, "\n");
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
		enum http_parser_type type,
		http_parser_settings* settings,
		bool parse_headers
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(type == HTTP_REQUEST || type == HTTP_RESPONSE);
	assert(settings != NULL);
#endif
	/*
	 * TODO use allocators instead of malloc
	 */
	struct HTTPParser* p = (struct HTTPParser*) malloc(sizeof(struct HTTPParser));
	if (p != NULL) {
		http_parser_init(&(p->parser), type);
		p->settings = settings;
		p->ctxt_last_header_max_size = 0;
		p->ctxt_last_header_copied = 0;
	}
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	else {
		fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
		assert(0);
	}
#endif
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
		int bytes
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(parser != NULL && ptr != NULL && bytes > 0);
#endif
	http_parser* p = &(parser->parser);
	http_parser_settings* settings = parser->settings;
	int ret = 0;
	//HTTPParserLastState state = parser->state;
	//bool parse_headers = parser->parse_headers;
	size_t nparsed = http_parser_execute(parser, settings, ptr, bytes);
	if (nparsed != (size_t) bytes) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		fprintf(stderr, "\nERROR: %s (%s) %s:%d\n", http_errno_description(HTTP_PARSER_ERRNO(parser)), http_errno_name(HTTP_PARSER_ERRNO(parser)), __FILE__, __LINE__);
#endif
		ret = ERR_HTTP_PARSER;
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
		list->next_msg = msg;
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

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		msg->headers.kvparray = NULL;
#endif

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
		if (msg->state == HTTP_MSG_STATE_HANDLER_INVOKED) {
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
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	list->head = NULL;
	list->tail = NULL;
	list->size = 0;
#endif
	free(list);
}


/*
 * returns -1 in case of writev() failure
 * -2 in case writev() blocks
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
	errno = 0;

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

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			perror("\nERROR writev() failed");
			assert(0);
#endif
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
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			fprintf(stderr, "\nERROR false write readiness: write blocks %s:%d\n", __FILE__, __LINE__);
#endif
			nbytes = -1;
		}
	} else if (nbytes == 0) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
		fprintf(stderr, "\nERROR writev() returned 0 %s:%d\n", __FILE__, __LINE__);
#endif
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
	bool is_write_blocked = ctxt->is_write_blocked;
	struct HTTPMsg* msg = NULL;
	//while (!is_write_blocked && (msg = removeHTTPMsgDListHead(msg_list)))
	while (!is_write_blocked && (msg = getHTTPMsgDListHead(msg_list))) {
		if (msg->state == HTTP_MSG_STATE_RESP_COMPLETE) {
			removeHTTPMsg(msg_list, msg);
			int h_size = msg->response.header.size;
			int b_size = msg->response.body.size;
			int bytes_to_send = h_size + b_size;
			bool register_write_watcher = false;

			ctxt->index = 0;
			struct iovec* vio = ctxt->vio;
			vio[0].iov_base = msg->response.header.buf;
			vio[0].iov_len = h_size;
			vio[1].iov_base = msg->response.body.buf;
			vio[1].iov_len = b_size;
			int nbytes = sendNetwData(conn->fd, vio, 2);
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
						perror("\nERROR writev() failed");
						assert(0);
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
							destroyHTTPMsg(msg);
						} else {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
							assert(nbytes < bytes_to_send);
#endif
							if (nbytes > h_size) {
								ctxt->index = 1;
								vio[1].iov_base = msg->response.body.buf + nbytes;
							} else {
								ctxt->index = 0;
								vio[0].iov_base = msg->response.header.buf + nbytes;
							}
							register_write_watcher = true;
						}
					}
			}
			if (register_write_watcher) {
				/*
				 * Start the connection's write readiness watcher and the write-readiness timeout
				 */
				ev_io_start(conn->loop, &(conn->io_wwatcher));
				startTimer(&(conn->w_tmr));
				ctxt->is_write_blocked = true;
			}
		} else {
			break;
		}
	}
}

void finishHTTPMsg(
		struct HTTPMsg* msg
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(msg != NULL && (msg->state == HTTP_MSG_STATE_HANDLER_INVOKED || msg->state == HTTP_MSG_STATE_TCP_CONN_CLOSED));
#endif
	switch (msg->state) {
		case HTTP_MSG_STATE_HANDLER_INVOKED:
			{
				msg->state = HTTP_MSG_STATE_RESP_COMPLETE;
				sendHTTPMsgs(msg->conn, (struct HTTPMsgDList*) msg->conn->msg_list);
				break;
			}
		case HTTP_MSG_STATE_TCP_CONN_CLOSED:
			{
				destroyHTTPMsg(msg);
				break;
			}
		default:
			{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				fprintf(stderr, "\nERROR Invalid state of HTTPMsg %s:%d\n", __FILE__, __LINE__);
#endif
				assert(0);
			}
	}
}


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
		memset(msg->parsed_url.rurl, 0, sizeof(struct DTextBuff));
		memset(msg->parsed_url.qparams, 0, sizeof(struct KVPParser));
		memset(msg->headers, 0, sizeof(struct KVPArray));
		memset(msg->body, 0, sizeof(struct DBinaryBuff));
		memset(msg->cookies, 0, sizeof(struct KVPParser));
		memset(msg->response, 0, sizeof(struct HTTPResponse));

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
	if (list->head == msg) {
		list->tail = msg->prev;
	} else {
		msg->next->prev = msg->prev;
	}
	/*
	 * This is un-necessary but...lets keep it
	 */
	msg->next = NULL;
	msg->prev = NULL;
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
	struct HTTPMsg* result = NULL;
	/*
	 * msg CAN be NULL
	 */
	if (msg != NULL && msg->state == HTTP_MSG_STATE_REQ_COMPLETE) {
		result = msg;
	}
	return result;
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
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->msg_list;
	struct HTTPMsgState state = HTTP_MSG_STATE_INIT;
#if 0
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(state == HTTP_MSG_STATE_NONE || state == HTTP_MSG_STATE_MSG_COMPLETE);
#endif

	/*
	 * TODO VERIFY if this callback can be invoked multiple times EVER?
	 */
	if (state != HTTP_MSG_STATE_NONE && state != HTTP_MSG_STATE_MSG_COMPLETE) {
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
		ret = ERR_HEAP_ALLOC_FAILURE;
	}
	/*
	 * TODO remove this code duplication
	 */
	insertHTTPMsgAtTail(list, msg);
	state == HTTP_MSG_STATE_PARSING_METHOD;
END:
	msg->state = state;
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
	(void)_;
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
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->msg_list;
	struct HTTPMsg* msg = getHTTPMsgDListTail(list);
	struct HTTPMsgState state = msg->state;
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
				struct DTextBuff* rurl = &(msg->parsed_url.rurl);
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				assert(rurl->url == NULL);
				assert(g_hint_url_size > 0);
#endif
				int max_size = (int) (len + 1 < g_hint_url_size)? nextPowerOf2(g_hint_url_size):nextPowerOf2(len + 1);
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
				assert(max_size >= len + 1 && max_size >= g_hint_url_size);
#endif
				char* url = malloc(max_size * sizeof(char));
				if (url == NULL) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
					ret = ERR_HEAP_ALLOC_FAILURE;
					goto END;
				}
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

				msg->parsed_url.rurl.url = url;
				msg->parsed_url.rurl.max_size = max_size;
				msg->parsed_url.rurl.size = len;

				state == HTTP_MSG_STATE_PARSING_URL;

				break;
			}

		case HTTP_MSG_STATE_PARSING_URL:
			{
				/*
				 * This is a subsequent call to this callback
				 */
				int max_size = msg->parsed_url.rurl.max_size;
				int size = msg->parsed_url.rurl.size;
				char* url = msg->parsed_url.rurl.url;
				if (max_size - size - len <= 0) {
					/*
					 * We need to reallocate memory
					 */
					max_size *= 2;
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
				msg->parsed_url.rurl.url = url;
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
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->msg_list;
	struct HTTPMsg* msg = getHTTPMsgDListTail(list);
	struct HTTPMsgState state = msg->state;

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	/*
	 * TODO check this condition
	 */
	assert(msg != NULL && (state == HTTP_MSG_STATE_PARSING_URL || state == HTTP_MSG_STATE_PARSING_HEADER_FIELD || state == HTTP_MSG_STATE_PARSING_HEADER_VALUE || state = HTTP_MSG_STATE_PARSING_BODY || state = HTTP_MSG_STATE_PARSING_FOOTER_FIELD || state = HTTP_MSG_STATE_PARSING_FOOTER_VALUE)); 
#endif

	uint8_t actions = 0;

REEXECUTE:
	switch (state) {
		case HTTP_MSG_STATE_PARSING_URL:
			{
				/*
				 * We need to parse the URL now since the entire Request Line is in buffer
				 */

				int size = msg->parsed_url.rurl.size;
				char* url = msg->parsed_url.rurl.url;

				struct http_parser_url* purl = &(msg->parsed_url.purl);

				int ret = http_parser_parse_url(url, size, 0, purl);
				if (ret != 0) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					fprintf(stderr, "\nERROR Url: %s could not be parsed %s:%d\n", url, __FILE__, __LINE__);
#endif
					ret = ERR_HTTP_PARSER;
					goto END;
				}

				uint16_t field_set = purl->field_set;
				if (field_set & UF_PATH) {
					/*
					 * The parsed URL has path
					 * TODO Can't remove the indirection since field_data is un-named structure
					 * can I do something?
					 */
					uint16_t off = purl->field_data[UF_PATH].off;
					uint16_t len = purl->field_data[UF_PATH].len;

					/*
					 * What all actions are required
					 * HTTP_PARSE_HEADERS, HTTP_PARSE_COOKIES, HTTP_PARSE_QUERY_PARAMS
					 * & what is the URL handler for this path?
					 */
					actions = getActionsAndURLHandler(url, off, len, &(msg->url_handler));
					msg->actions = actions;
					if ((actions & HTTP_PARSE_QUERY_PARAMS) && (field_set & UF_QUERY)) {
						/*
						 * The URL has query parameter and we need to parse the query parameters for this
						 * PATH
						 */
						off = purl->field_data[UF_QUERY].off;
						len = purl->field_data[UF_QUERY].len;

						struct KVPParser* qparams = &(msg->qparams);
						qparams->buf = url + off;
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
						assert(g_hint_n_qparams > 0);
#endif
						ret = parseKVPBuffer(qparams, '&', '=', false, g_hint_n_qparams);
						if (ret != 0) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
							fprintf(stderr, "\nERROR parsing the query string for Url: %s %s:%d\n", url, __FILE__, __LINE__);
#endif
							goto END;
						}
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
						printSortedQueryParms(qparams->buf, qparams->kvparray, 0, qparams->size - 1);
#endif
					}
				} else {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					fprintf(stderr, "\nERROR Url: %s doesn't have UF_PATH set %s:%d\n", url, __FILE__, __LINE__);
#endif
					ret = ERR_HTTP_PARSER;
					goto END;
				}
				state == HTTP_MSG_STATE_PARSED_URL;
				goto REEXECUTE;
			}

		case HTTP_MSG_STATE_PARSING_BODY:
			{
				/*
				 * We have got the complete body
				 */
				state == HTTP_MSG_STATE_PARSED_BODY;
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
							state == HTTP_MSG_STATE_PARSED_HEADER_VALUE;
							break;
						}
					case HTTP_MSG_STATE_PARSING_FOOTER_VALUE:
						{
							state == HTTP_MSG_STATE_PARSED_FOOTER_VALUE;
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
				if (actions & HTTP_PARSE_HEADERS) {
					struct KVPArray* headers = &(msg->headers);
					struct KeyValuePair* kvparray = headers->kvparray;
					int max_size = headers->max_size;
					int size = headers->size;

					if (size >= max_size) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
						assert(g_hint_n_headers > 0);
#endif
						max_size = (int) (max_size == 0)? nextPowerOf2(g_hint_n_headers):(max_size * 2);
						struct KeyValuePair* temp = NULL;
						temp = (KeyValuePair*) realloc(kvparray, max_size * sizeof(struct KeyValuePair));
						if (temp == NULL) {
							/*
							 * TODO 
							 * check if we need to do this here
							 * I am not free()'ing earlier memory
							 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
							fprintf(stderr, "\nERROR realloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
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
					int key_size = (int) nextPowerOf2(len + 1);
					kvp->key = (char*) malloc(sizeof(char) * key_size);
					if (kvp->key == NULL) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
						fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
						ret = ERR_HEAP_ALLOC_FAILURE;
						goto END;
					}
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
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					fprintf(stderr, "\nDEBUG Header Parsing for %.*s is not set %s:%d\n", (int) size, at, __FILE__, __LINE__);
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
				if (key_max_size - key_size_copied - len <= 0) {
					/*
					 * Reallocate
					 */
					key_max_size *= 2;
					char* temp = NULL;
					temp = (char*) realloc(kvp->key, sizeof(char) * key_max_size);
					if (temp == NULL) {
						/*
						 * TODO
						 * kvp->key should be free()'ed in error handling
						 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
						fprintf(stderr, "\nERROR realloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
						ret = ERR_HEAP_ALLOC_FAILURE;
						goto END;
					}
					kvp->key = temp;
				}

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
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->msg_list;
	struct HTTPMsg* msg = getHTTPMsgDListTail(list);
	struct HTTPMsgState state = msg->state;

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	/*
	 * TODO check this condition
	 */
	assert(msg != NULL && (state == HTTP_MSG_STATE_PARSING_HEADER_FIELD || state == HTTP_MSG_STATE_PARSING_HEADER_VALUE || state = HTTP_MSG_STATE_PARSING_FOOTER_FIELD || state = HTTP_MSG_STATE_PARSING_FOOTER_VALUE)); 
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
							state == HTTP_MSG_STATE_PARSED_HEADER_FIELD;
							break;
						}
					case HTTP_MSG_STATE_PARSING_FOOTER_FIELD:
						{
							state == HTTP_MSG_STATE_PARSED_FOOTER_FIELD;
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
				int value_size = (int) nextPowerOf2(len + 1);
				kvp->value = (char*) malloc(sizeof(char) * value_size);
				if (kvp->value == NULL) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
					ret = ERR_HEAP_ALLOC_FAILURE;
					goto END;
				}
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
				if (value_max_size - value_size_copied - len <= 0) {
					/*
					 * Reallocate
					 */
					value_max_size *= 2;
					char* temp = NULL;
					temp = (char*) realloc(kvp->value, sizeof(char) * value_max_size);
					if (temp == NULL) {
						/*
						 * TODO
						 * kvp->value should be free()'ed in error handling
						 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
						fprintf(stderr, "\nERROR realloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
						ret = ERR_HEAP_ALLOC_FAILURE;
						goto END;
					}
					kvp->value = temp;
				}

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
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	/*
	 * TODO check this condition
	 */
	assert(msg->state == HTTP_MSG_STATE_PARSING_HEADER_VALUE);
#endif

	parser->ctxt_last_header_copied = 0
	parser->ctxt_last_header_max_size = 0
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
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->msg_list;
	struct HTTPMsg* msg = getHTTPMsgDListTail(list);
	struct HTTPMsgState state = msg->state;

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
				if (size >= max_size) {
					max_size = (int) (max_size == 0)? ((len + 1 < g_hint_body_size)? nextPowerOf2(g_hint_body_size):nextPowerOf2(len + 1)):(max_size * 2);
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					/*
					 * TODO
					 * this is incomplete check???
					 */
					assert(max_size >= len + 1 && max_size >= g_hint_body_size);
#endif
					struct unsigned char* temp = NULL;
					temp = (unsigned char*) realloc(buf, max_size * sizeof(unsigned char));
					if (temp == NULL) {
						/*
						 * TODO 
						 * check if we need to do this here
						 * I am not free()'ing earlier memory
						 */
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
						fprintf(stderr, "\nERROR realloc() failed %s:%d\n", __FILE__, __LINE__);
#endif
						ret = ERR_HEAP_ALLOC_FAILURE;
						goto END;
					}
					buf = temp;
					body->buf = buf;
					body->max_size = max_size;
				}
				memcpy(buf + size, at, len);
				size += len;
				buf[size] = '\0';
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
	struct HTTPMsgDList* list = (struct HTTPMsgDList*) conn->msg_list;
	struct HTTPMsg* msg = getHTTPMsgDListTail(list);
	struct HTTPMsgState state = msg->state;

#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	/*
	 * TODO check this condition, the last state will be there only if settings doesn't
	 * contain on_header_field and on_header_value callbacks
	 */
	assert(msg != NULL && (state == HTTP_MSG_STATE_HEADERS_COMPLETE || state == HTTP_MSG_STATE_PARSING_BODY || state == HTTP_MSG_STATE_PARSING_URL));
#endif

	msg->state = HTTP_MSG_STATE_MSG_COMPLETE;

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
				struct KVPParser* cookies = msg->cookies;
				cookies->buf = cookie_header_value;
				ret = parseKVPBuffer(cookies, ';', '=', true, g_hint_n_cookies);
				if (ret != 0) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
					fprintf(stderr, "\nERROR parsing the cookie_header_value for cookies : %s %s:%d\n", cookies->buf, __FILE__, __LINE__);
#endif
				}
			}
		}
	}
	return ret;
}

/*
 * Public HTTPMsg API
 */

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

#if 0
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
#if 0
	fprintf(stderr,
			"Error: %s (%s)\n",
			http_errno_description(HTTP_PARSER_ERRNO(&parser)),
			http_errno_name(HTTP_PARSER_ERRNO(&parser)));
	return EXIT_FAILURE;
#endif
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
#endif
