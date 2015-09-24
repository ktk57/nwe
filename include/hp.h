#ifndef __HP_H__
#define __HP_H__

#include <stdint.h>
#include <sys/uio.h>
#include "ev.h"
#include "http_parser.h"
#include "Timer.h"
#include "Utils.h"
#include <netinet/in.h>

#define MAX_URL_HANDLERS 3

struct Reactor;
struct HTTPMsg;

typedef void (*FPTRURLHandler) (struct Reactor*, struct HTTPMsg*, void*);

struct URLActionsAndHandler {
	const char* url;
	uint8_t actions;
	FPTRURLHandler handler;
	/*
	 * Per thread data for the application
	 * Usually initialized at the start of the worker thread
	 */
	void* app_data;
#ifdef DEBUG
	const char* fptr_name;
#endif
};
/*
 * This is a per thread structure containing information for a single thread
 * I am not a good expositor, will try to improve the documentation with every
 * phase of this project
 */
struct Reactor {

	struct ev_loop* loop;
	/*
	 * To pass an incoming connection to the worker thread
	 * OR
	 * to signal the thread to break the ev_run() loop even if there are pending watchers
	 * To signal shutdown, the main thread simply sends the "fd_new_conn_or_shutdown"
	 * to the worker thread, else it sends the accept()'ed fd
	 */
	//int fd_new_conn_or_shutdown;
	int r_w_pipe[2];
	/*
	 * An array of struct TimerList*
	 */
	struct TimerListMap timers;
	struct URLActionsAndHandler url_handler_info[MAX_URL_HANDLERS];
	/*
	 * # of url_handler_info INSTALLED
	 */
	int n_url_handlers;

	/*
	 * TODO write memory allocator to get rid of mallocs
	 */
};

struct TCPConnInfo;

struct HTTPMsg;

/*
 * the application parser for the tcp connection
 */


enum HTTPMsgState {
	HTTP_MSG_STATE_INIT = 1,
	HTTP_MSG_STATE_PARSING_METHOD = 2,
	HTTP_MSG_STATE_PARSED_METHOD = 3,
	HTTP_MSG_STATE_PARSED_STATUS = 4,
	HTTP_MSG_STATE_PARSING_URL = 5,
	HTTP_MSG_STATE_PARSED_URL = 6,
	HTTP_MSG_STATE_PARSING_HEADER_FIELD = 7,
	HTTP_MSG_STATE_PARSED_HEADER_FIELD = 8,
	HTTP_MSG_STATE_PARSING_HEADER_VALUE = 9,
	HTTP_MSG_STATE_PARSED_HEADER_VALUE = 10,
	HTTP_MSG_STATE_HEADERS_COMPLETE = 11,
	HTTP_MSG_STATE_PARSING_BODY = 12,
	HTTP_MSG_STATE_PARSED_BODY = 13,
	HTTP_MSG_STATE_PARSING_FOOTER_FIELD =14,
	HTTP_MSG_STATE_PARSED_FOOTER_FIELD = 15,
	HTTP_MSG_STATE_PARSING_FOOTER_VALUE = 16,
	HTTP_MSG_STATE_PARSED_FOOTER_VALUE = 17,
	HTTP_MSG_STATE_REQ_COMPLETE = 18,
	HTTP_MSG_STATE_HANDLER_INVOKED = 19,
	HTTP_MSG_STATE_RESP_COMPLETE = 20,
	/*
	 * This state indicates that the TCP conn
	 * has been close()'ed
	 * Don't refer to the msg->conn;
	 */
	HTTP_MSG_STATE_TCP_CONN_CLOSED = 21,
	/*
	 * This indicates that msg has some
	 * error, don't write it over the wire
	 */
	HTTP_MSG_STATE_ERR = 22
};

enum HTTPURLHandlerFlags {
	HTTP_PARSE_QUERY_PARAMS = 1,
	HTTP_PARSE_HEADERS = 2,
	HTTP_PARSE_COOKIES = 4,
	SEND_CONNECTION_CLOSE_HEADER = 8
	//HTTP_PARSE_POST_DATA = 4
};
#if 0
	/*
	 * HTTP_PARSE_QUERY
	 * HTTP_PARSE_HEADERS
	 */
	uint8_t actions;
#endif

struct HTTPParser {

	http_parser parser;
	/*
	 * this contains the length of the header-field/value already copied
	 * to avoid strcat
	 */
	uint16_t ctxt_last_header_copied;

	/*
	 * this contains the max_size of the header-field/value
	 */
	uint16_t ctxt_last_header_max_size;
};
/*
enum HTTPMethod {
	HTTP_UNKNOWN,
	HTTP_GET,
	HTTP_HEAD,
	HTTP_POST
};
*/


/*struct QueryParams {
	struct OffsetPair* params;
	int size;
	int max_size;
};
*/

/*
struct HTTPHeaders {
	struct KeyValuePair* kvparray;
	int size;
	int max_size;
};
*/


struct HTTPParsedURL {
	struct DTextBuff rurl;
	struct KVPParser qparams;
	struct http_parser_url purl;
};

struct HTTPResponse {
	uint16_t status;
	struct DTextBuff header;
	struct DBinaryBuff body;
};


struct HTTPMsg {

	/*
	 * Type of Message
	 * HTTP_REQUEST or HTTP_RESPONSE
	 */
	enum http_parser_type type;

	struct TCPConnInfo* conn;
	/*
	 * For requests
	 */
	enum http_method method;
	uint8_t actions;
	FPTRURLHandler url_handler;
	void* app_data;
	/*
	 * For responses
	 */
	uint8_t status_code;
	enum HTTPMsgState state;
	/*
	 * This shall contain what it shall contain
	 * Parsed URL
	 */
	struct HTTPParsedURL parsed_url;

	/*
	 * Parsed headers
	 */
	struct KVPArray headers;
	/*
	 * Parsed Cookies
	 */
	struct KVPParser cookies;

	/*
	 * TODO what about the "parsed_body"?
	 * Yeh kya hai? bhool gyaa
	 *
	 */
	struct DBinaryBuff body;

	/*
	 * Response to this HTTP message
	 */
	struct HTTPResponse response;

	/*
	 * TODO Is a DList required?
	 */
	struct HTTPMsg* next;

	struct HTTPMsg* prev;
};


struct HTTPMsgDList {
	struct HTTPMsg* head;
	struct HTTPMsg* tail;
	/*
	 * next HTTPMsg whose URL handler needs to be called
	 * this should be updated when the list is empty
	 * AND
	 * after a URL HANDLER for a msg is invoked
	 */
	struct HTTPMsg* next_msg;
	int size;
};
struct TCPConnInfo;

typedef void (*FPTRIOCB) (struct ev_loop*, ev_io*, int);
//typedef void (*FPTRTimeoutCB) (struct ev_loop*, ev_timer*, int);

/*
 * Type of network buffer i.e whether this is a read buffer or write buffer of a
 * connection(TCP)
 */
#if 0
enum NetwBuffType {
	NETW_BUFF_UNDEFINED,
	NETW_BUFF_READ,
	NETW_BUFF_WRITE
};
#endif

enum ConnDataParserType {
	APP_UNKNOWN = 0,
 /* 
	* This is HTTP/1.1 parser
	* I will never ever support a request for HTTP/1.0 support
	*/
	APP_HTTP_PARSER,
 /*
	* This is HTTP/2.0 i.e Spdy parser
	*/
	APP_HTTP2_PARSER,
	/*
	 * This is memcached protocol parser
	 * Protocol defined as in version 1.4.15
	 */
	APP_MEMCACHED_PARSER
};

/*
 * List of TODO things for the HTTPMsg
 */


/*
 * This is an application-level-connection buffer. There are 2 buffers i.e read and write
 * for each TCP connection. The application writes to this buffer by the API provided by
 * netw_buff_* (and never directly).
 * This API does the actual send()/recv()/readv()/writev() on the connect()'ed socket
 */
#if 0
struct NetwBuff {
	unsigned char* data;
	int start_index;
	// [start_index, end_index) i.e end_index is not to be referenced i.e left inclusive & right exclusive
	int end_index;
	int max_len;
	/*
	 * We can't determine if the buffer is completely full or completely empty using start_index and end_index alone
	 */
	int empty_space;
	enum NetwBuffType type;
	// the connection to which this NetwBuff belongs
	struct TCPConnInfo* conn;
};
#endif

/*
 * TCP Connection Read Buffer
 */
/*
typedef int (*app_parser_init)(void*, int args, ...);
typedef int (*app_parser_execute)(void*, int args, ...);
typedef int (*app_parser_error)(void*, int args, ...);
typedef int (*app_parser_destroy)(void*, int args, ...);
*/


/*
 * An opaque ConnDataParserInfo structure
 * After accept(), the caller must create an ConnDataParserInfo and initialize it with actual
 * function pointers and parser object and then pass it to the conn_init() function
 * these functions and parser object would then be used to parse the application data
 * received on the tcp connection socket
 */

/*
struct ConnDataParserInfo {
	ConnDataParserType type;
	void* parser_obj;
	app_parser_init init_fp;
	app_parser_execute execute_fp;
	app_parser_error error_fp;
	app_parser_destroy destroy_fp;
};
*/

/*
struct ConnDataParser {
	ConnDataParserType type;
	union {
		//HTTPParser h_parser;
		http_parser h_parser;
	}p;
}
*/


/*
 * A structure which stores all the timers which have "same-timeout" & "same-callback" in
 * case timeout occurs
 */

struct WriteCtxt {
	struct iovec vio[2];
	bool is_write_blocked;
	uint8_t index;
	void* ctxt;
};

struct TCPConnInfo {

	int fd;

	/*
	 * peer address
	 */
	struct {
		union {
			struct in_addr ipv4_addr;
			struct in6_addr ipv6_addr;
		}ip;
		uint16_t port;
	}peer_addr;
	/*
	 * The event loop to which this connection belongs
	 */
	//struct ev_loop* loop;
	struct Reactor* reactor;

	/*
	 * TODO How to make a connection application protocol independent?
	 * Ideally parser should be generic OR not part of connection
	 */

	/*
	 * Parser type
	 */
	enum ConnDataParserType parser_type; 

	/*
	 * This is a generic parser
	 */
	void* parser;


	/*
	 * This is generic data read from the socket
	 */
	/*
	 * This is a pointer to DList structure allocated on heap
	 * for Application message received
	 * For eg HTTPMsgDList = (HTTPMsgDList*) conn->msg_list
	 */

	void* in_data;

	/*
	 * read I/O watcher
	 */
	ev_io io_rwatcher;
	/*
	 * write I/O watcher
	 */
	ev_io io_wwatcher;

	/*
	 * watcher for read_timeout
	 */
	//ev_timer read_timeout_watcher;
	/*
	 * Pointer to the read timeout structure in a d-linked-list of read-timeout-timers
	 */
	struct Timer r_tmr;

	/*
	 * Pointer to the write timeout structure in a d-linked-list of write-timeout-timers
	 */
	struct Timer w_tmr;
	/*
	 * watcher for write_timeout
	 */
	//ev_timer write_timeout_watcher;
	/*
	 * Read buffer
	 */
	//struct NetwBuff rbuf;
	struct DBinaryBuff rbuf;
	/*
	 * Context of data written
	 */
	struct WriteCtxt w_ctxt;
	/*
	 * Write buffer
	 */
	/*
	 *
	 struct NetwBuff wbuf;
	 *
	 */
};

struct HTTPMsg* getHTTPMsgDListHead(
		struct HTTPMsgDList* list
		);

/*
	 http_cb      on_Msg_begin;
	 http_data_cb on_url;
	 http_data_cb on_status;
	 http_data_cb on_header_field;
	 http_data_cb on_header_value;
	 http_cb      on_headers_complete;
	 http_data_cb on_body;
	 http_cb      on_Msg_complete;

*/

/*
 * Function Signatures
 */
struct HTTPParser* createHTTPParser(
		enum http_parser_type type
		);

/*
 * Deallocates and destroys an HTTPParser
 */
void destroyHTTPParser(
		struct HTTPParser* parser
		);

/*
 * Sets the context for an HTTPParser
 */
void setHTTPParserContext(
		struct HTTPParser* parser,
		void* ctxt
		);

int executeHTTPParser(
		struct HTTPParser* parser,
		const char* ptr,
		int bytes,
		struct TCPConnInfo* conn
		);

void initHTTPMsgDList(
		struct HTTPMsgDList* list
		);

/*
 * This is duplicate code...sighh
 */
void insertHTTPMsgAtTail(
		struct HTTPMsgDList* list,
		struct HTTPMsg* msg
		);

/*
 * free() memory of an HTTPMsg
 */
void destroyHTTPMsg(
		struct HTTPMsg* msg
		);

void destroyHTTPMsgDList(
		struct HTTPMsgDList* list
		);

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
		);

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
		);

void sendHTTPMsgs(
		struct TCPConnInfo* conn,
		struct HTTPMsgDList* msg_list
		);

void finishHTTPMsg(
		struct HTTPMsg* msg
		);

struct HTTPMsg* getHTTPMsg(
		enum http_parser_type type,
		struct TCPConnInfo* conn
		);

/*
 * This is duplicate code
 */
void removeHTTPMsg(
		struct HTTPMsgDList* list,
		struct HTTPMsg* msg
		);


struct HTTPMsg* removeHTTPMsgDListHead(
		struct HTTPMsgDList* list
		);

struct HTTPMsg* getHTTPMsgDListTail(
		struct HTTPMsgDList* list
		);

/*
 * Returns the next HTTPMsg whose URL handler
 * needs to be invoked
 */
struct HTTPMsg* getNextHTTPMsg(
		struct HTTPMsgDList* list
		);

/*
 * This is MANDATORY callback
 */
int onHTTPReqMsgBegin(
	http_parser* p
	);

/*
 * This is MANDATORY callback for HTTP Response
 */
#if 0
int onHTTPResStatus(
		http_parser* p,
		const char* at,
		size_t length
		);
#endif

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
		);

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
		);

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
		);

/*
 * This is OPTIONAL callback
 */
/*
 * TODO
 * assumption, this will be invoked only once per http message
 */
int onHTTPReqHeadersComplete(
		http_parser* p
		);

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
		);

/*
 * This is MANDATORY callback
 */

int onHTTPReqMsgComplete(
		http_parser* p
		);

int initTCPConnBuff(
		struct DBinaryBuff* buf,
		int max_size
		);


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
		//struct ev_loop* loop,
		struct Reactor* reactor,
		FPTRIOCB io_rcb,
		FPTRIOCB io_wcb,
		FPTRTimeoutCB r_timeout_cb,
		FPTRTimeoutCB w_timeout_cb
		);

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
		);

void destroyTCPConn(
		struct TCPConnInfo* conn
		);
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
		);

void processHTTPReqCB(
		struct ev_loop* loop,
		ev_io* w,
		int revents
		);

void processWriteReadyCB(
		struct ev_loop* loop,
		ev_io* w,
		int revents
		);

/*
 * Public HTTPMsg API
 */
const char* getHTTPMsgQParam(
		struct HTTPMsg* msg,
		const char* param
		);

const char* getHTTPMsgHeader(
		struct HTTPMsg* msg,
		const char* header_name
		);

const char* getHTTPMsgCookie(
		struct HTTPMsg* msg,
		const char* cookie_name
		);
/*
 * Allow the caller to modify the body
 */
unsigned char* getHTTPMsgBody(
		struct HTTPMsg* msg,
		int* len
		);

/*
int writeHTTPStatus(
		struct HTTPMsg* msg,
		uint16_t status
		);
		*/

int writeHTTPHdr(
		struct HTTPMsg* msg,
		const char* src,
		int len
		);

int writeHTTPBody(
		struct HTTPMsg* msg,
		const char* src,
		int len
		);

void finishHTTPMsg(
		struct HTTPMsg* msg
		);

int sprintfHTTPBody(
		struct HTTPMsg* msg,
		const char* fmt,
		...
		);
int sprintfHTTPHdr(
		struct HTTPMsg* msg,
		const char* fmt,
		...
		);
#endif
