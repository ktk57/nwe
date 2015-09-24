#ifndef __NET_UTILS_H__
#define __NET_UTILS_H__

#include "ev.h"
#include "Timer.h"
#include "Utils.h"

struct TCPConnInfo;

typedef void (*FPTRIOCB) (struct ev_loop*, ev_io*, int);
//typedef void (*FPTRTimeoutCB) (struct ev_loop*, ev_timer*, int);

/*
 * Type of network buffer i.e whether this is a read buffer or write buffer of a
 * connection(TCP)
 */
enum NetwBuffType {
	NETW_BUFF_UNDEFINED,
	NETW_BUFF_READ,
	NETW_BUFF_WRITE
};

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
 * This is an application-level-connection buffer. There are 2 buffers i.e read and write
 * for each TCP connection. The application writes to this buffer by the API provided by
 * netw_buff_* (and never directly).
 * This API does the actual send()/recv()/readv()/writev() on the connect()'ed socket
 */
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

/*
 * TCP Connection Read Buffer
 */
struct TCPConnBuff {
	struct DBinaryBuff data;
	struct TCPConnInfo* conn;
};

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

struct node {
	/*
	 * t indicates the "absolute value"
	 * I don't know how to explain this
	 */
	ev_tstamp t;
	// To enable loose coupling
	void* ctxt;
	//fptr_timeout_cb cb;
	struct node* next;
	struct node* prev;
};

struct dlist {
	struct node* head;
	struct node* tail;
	int size;
};


/*
 * A structure which stores all the timers which have "same-timeout" & "same-callback" in
 * case timeout occurs
 */
struct timer_list {
	/*
	 * each of the timers have the same timeout
	 * timeout is simply a relative +ve number
	 */
	ev_tstamp timeout;
	struct dlist list;
	ev_timer tmr;
	FPTRCustomTimeoutCB cb;
};

void incrementHead(
		struct dlist* l
		);

void init_timer_list(
		struct timer_list* l,
		ev_tstamp timeout,
		FPTRCustomTimeoutCB cb
		);

int insertAtTail(
		struct dlist* list,
		ev_tstamp timeout,
		//fptr_timeout_cb cb
		);

void moveToTail(
		struct dlist* list,
		struct node* element
		);

void changeNodeTimestamp(
		struct node* element,
		ev_tstamp timeout
		);


struct WriteCtxt {
	struct iovec vio[2];
	bool is_write_blocked;
	uint8_t index;
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
	struct ev_loop* loop;

	/*
	 * Time in ms to wait for data to arrive on this connection, if the application is
	 * "waiting"
	 */
	int read_timeout;
	/*
	 * Time in ms to wait for the application to write data to kernel's send connection
	 * buffer
	 */
	int write_timeout;
	/*
	 * Set of events i.e EV_READ/EV_WRITE etc
	 */
	//int revents;

	/*
	 * TODO How to make a connection application protocol independent?
	 * Ideally parser should be generic OR not part of connection
	 */
	//struct ConnDataParser parser;

	/*
	 * Parser type
	 */
	enum ConnDataParserType parser_type; 

	/*
	 * This is a generic parser
	 */
	void* parser;


	/*
	 * This is a pointer to DList structure allocated on heap
	 * for Application message received
	 * For eg HTTPMsgDList = (HTTPMsgDList*) conn->msg_list
	 */

	void* msg_list;

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
	struct TCPConnBuff rbuf;
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
		);

void processHTTPReqCB(
		struct ev_loop* loop,
		ev_io* w,
		int revents
		);

int netwBuffInit(
		struct TCPConnInfo* conn,
		struct NetwBuff* buf,
		int max_size,
		enum NetwBuffType type
		);
#endif
