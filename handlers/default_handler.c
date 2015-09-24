#include <stdio.h>
#include "hp.h"
#include "ev.h"
#include "Handlers.h"
const char DEFAULT_RESPONSE_HEADER[] =
"HTTP/1.1 404 Not Found\r\n"
"Date: Tue, 09 Oct 2012 16:36:18 GMT\r\n"
"Server: jugnu\r\n"
"Last-Modified: Mon, 09 Jul 2012 03:42:33 GMT\r\n"
"Content-Type: text/html\r\n";

int DEFAULT_RESP_HEADER_SIZE = sizeof(DEFAULT_RESPONSE_HEADER) - 1;

void defaultHandler(
		struct Reactor* reactor,
		struct HTTPMsg* msg,
		void* app_data
		)
{

	(void) reactor;
	(void) app_data;
	int ret = 0;
#if 0
	ret = writeHTTPStatus(msg, HTTP_200_OK);
	if (ret != 0) {
		fprintf(stderr, "\nERROR writeHTTPStatus() failed\n");
	}
#endif
	ret = writeHTTPHdr(msg, DEFAULT_RESPONSE_HEADER, DEFAULT_RESP_HEADER_SIZE);
	if (ret != 0) {
		fprintf(stderr, "\nERROR writeHTTPHeader() failed\n");
		goto END;
	}
END:
	finishHTTPMsg(msg);
}
