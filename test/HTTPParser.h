#ifndef __HTTP_PARSER_H__
#define __HTTP_PARSER_H__

#include "http_parser.h"
#include <stdint.h>

struct TCPConnInfo;

struct HTTPMsg;

typedef void (*FPTRURLHandler) (struct HTTPMsg*);
/*
 * the application parser for the tcp connection
 */


enum HTTPMsgState {
	HTTP_MSG_STATE_INIT,
	HTTP_MSG_STATE_PARSING_METHOD,
	HTTP_MSG_STATE_PARSED_METHOD,
	HTTP_MSG_STATE_PARSED_STATUS,
	HTTP_MSG_STATE_PARSING_URL,
	HTTP_MSG_STATE_PARSED_URL,
	HTTP_MSG_STATE_PARSING_HEADER_FIELD,
	HTTP_MSG_STATE_PARSED_HEADER_FIELD,
	HTTP_MSG_STATE_PARSING_HEADER_VALUE,
	HTTP_MSG_STATE_PARSED_HEADER_VALUE,
	HTTP_MSG_STATE_HEADERS_COMPLETE,
	HTTP_MSG_STATE_PARSING_BODY,
	HTTP_MSG_STATE_PARSED_BODY,
	HTTP_MSG_STATE_PARSING_FOOTER_FIELD,
	HTTP_MSG_STATE_PARSED_FOOTER_FIELD,
	HTTP_MSG_STATE_PARSING_FOOTER_VALUE,
	HTTP_MSG_STATE_PARSED_FOOTER_VALUE,
	HTTP_MSG_STATE_REQ_COMPLETE,
	HTTP_MSG_STATE_HANDLER_INVOKED,
	HTTP_MSG_STATE_RESPONSE_WRITTEN,
	/*
	 * This state indicates that the TCP conn
	 * has been close()'ed
	 * Don't refer to the msg->conn;
	 */
	HTTP_MSG_STATE_TCP_CONN_CLOSED
};

enum HTTPURLHandlerFlags {
	HTTP_PARSE_QUERY_PARAMS = 1,
	HTTP_PARSE_HEADERS = 2
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
	 * Don't know if this is required..lets just keep it for now
	 */
	http_parser_settings* settings;
	/*
	 * Last state of the Parser
	 */
	//enum HTTPParserState state;
	/*
	 * this contains the length of the header-field/value already copied
	 * to avoid strcat
	 */
	int ctxt_last_header_copied;

	/*
	 * this contains the max_size of the header-field/value
	 */
	int ctxt_last_header_max_size;
#if 0
	/*
	 * this contains the length of the body already copied
	 * to avoid strcat
	 */
	int ctxt_msg_body_copied;

	int ctxt_msg_body_copied;
#endif
	/*
	// i.e request/response/both
	http_parser_type type;
	*/
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
	/*
	 * For responses
	 */
	int status_code;
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

	enum HTTPMsgState state;
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
int onHTTPReqMsgBegin(http_parser*);
int onHTTPReqURL(http_parser*, const char*, size_t);
int onHTTPReqHeadersComplete(http_parser*);
int onHTTPReqMsgComplete(http_parser*);
int onHTTPReqHeaderField(http_parser*, const char*, size_t);
int onHTTPReqHeaderValue(http_parser*, const char*, size_t);
int onHTTPReqBody(http_parser*, const char*, size_t);

int onStatus(http_parser*, const char*, size_t);

struct HTTPParser* createHTTPParser(enum http_parser_type type, http_parser_settings* settings, bool parse_headers);
void setHTTPParserContext(struct HTTPParser* parser, void* ctxt);
#endif
