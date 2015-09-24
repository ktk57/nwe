//gcc -D_GNU_SOURCE -Wall -Werror -Wfatal-errors -I./http-parser-master/ parser_http_test.c ./http-parser-master/http_parser.c
/* Based on src/http/ngx_http_parse.c from NGINX copyright Igor Sysoev
 *
 * Additional changes are licensed under the same terms as NGINX and
 * copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/* Dump what the parser finds to stdout as it happen */

#include "http_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Fill this in with the http request that your
// weighttp client sends to the server. This is the
// request that I get.
char EXPECTED_HTTP_REQUEST[] =
"POST /AdServer/AdServerServlet?operId=5&segid=7#abc HTTP/1.1\r\n"
"Host: 192.168.1.58:8080\r\n"
"User-Agent: weighttp/0.3\r\nConnection: keep-alive\r\n"
"Transfer-Encoding: chunked\r\n\r\n"
"3E8; ignore this comment \r\n"
"ajdhfjkahskjdfhhskjkkfsjjflkdasjlkfjaslkjdkfjasdkjfalksjdflkakflkdsjksfadjflkflkjasfjiowueoiuriiqews ajdhfjkahskjdfhhskjkkfsjjflkdasjlkfjaslkjdkfjasdkjfalksjdflkakflkdsjksfadjflkflkjasfjiowueoiuriiqews ajdhfjkahskjdfhhskjkkfsjjflkdasjlkfjaslkjdkfjasdkjfalksjdflkakflkdsjksfadjflkflkjasfjiowueoiuriiqews ajdhfjkahskjdfhhskjkkfsjjflkdasjlkfjaslkjdkfjasdkjfalksjdflkakflkdsjksfadjflkflkjasfjiowueoiuriiqews ajdhfjkahskjdfhhskjkkfsjjflkdasjlkfjaslkjdkfjasdkjfalksjdflkakflkdsjksfadjflkflkjasfjiowueoiuriiqews ajdhfjkahskjdfhhskjkkfsjjflkdasjlkfjaslkjdkfjasdkjfalksjdflkakflkdsjksfadjflkflkjasfjiowueoiuriiqews ajdhfjkahskjdfhhskjkkfsjjflkdasjlkfjaslkjdkfjasdkjfalksjdflkakflkdsjksfadjflkflkjasfjiowueoiuriiqews ajdhfjkahskjdfhhskjkkfsjjflkdasjlkfjaslkjdkfjasdkjfalksjdflkakflkdsjksfadjflkflkjasfjiowueoiuriiqews ajdhfjkahskjdfhhskjkkfsjjflkdasjlkfjaslkjdkfjasdkjfalksjdflkakflkdsjksfadjflkflkjasfjiowueoiuriiqews ajdhfjkahskjdfhhskjkkfsjjflkdasjlkfjaslkjdkfjasdkjfalksjdflkakflkdsjksfadjflkflkjasfjiowueo\r\n"
"5\r\n"
"hello\r\n"
"0\r\n"
"footer1: vf1\r\n"
"footer2: vf2\r\n"
"\r\n"
"GET /This/is/path?a=b&c=d&e";


char msg2[] = 
"=f HTTP/1.1\r\nHost"
": 192.168.1.58:8080\r\n"
"k1:\r\n"
"k2: \r\n"
"User-Agent: ktk57/0.3\r\nConnection: keep-alive\r\n\r\n";
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

int on_message_begin(http_parser* _) {
  (void)_;
  fprintf(stderr, "\n***MESSAGE BEGIN***\n\n");
  return 0;
}

int on_headers_complete(http_parser* _) {
  (void)_;
  fprintf(stderr, "\n***HEADERS COMPLETE***\n\n");
  return 0;
}

int on_message_complete(http_parser* p) {
  fprintf(stderr, "\n***MESSAGE COMPLETE***\n\n");
	http_parser_pause(p, 1);
  return 0;
}

int on_url(http_parser* _, const char* at, size_t length) {
  (void)_;
  fprintf(stderr, "Url: %.*s\n", (int)length, at);
  return 0;
}

int on_status(http_parser* _, const char* at, size_t length) {
  (void)_;
  fprintf(stderr, "Status: %.*s\n", (int)length, at);
  return 0;
}

int on_header_field(http_parser* _, const char* at, size_t length) {
  (void)_;
  fprintf(stderr, "Header field: %.*s\n", (int)length, at);
  return 0;
}

int on_header_value(http_parser* _, const char* at, size_t length) {
  (void)_;
  fprintf(stderr, "Header value: %.*s\n", (int)length, at);
  return 0;
}

int on_body(http_parser* _, const char* at, size_t length) {
  (void)_;
  fprintf(stderr, "Body: %.*s\n", (int)length, at);
  return 0;
}


int main(int argc, char* argv[]) {

	http_parser_settings settings;
	memset(&settings, 0, sizeof(settings));

	settings.on_message_begin = on_message_begin;
	settings.on_url = on_url;
	settings.on_status = on_status;
	settings.on_header_field = on_header_field;
	settings.on_header_value = on_header_value;
	settings.on_headers_complete = on_headers_complete;
	settings.on_body = on_body;
	settings.on_message_complete = on_message_complete;

	http_parser parser;
	http_parser_init(&parser, HTTP_REQUEST);
	EXPECTED_RECV_LEN = sizeof(EXPECTED_HTTP_REQUEST) - 1;
	int msg2_len = sizeof(msg2) - 1;

	size_t nparsed = http_parser_execute(&parser, &settings, EXPECTED_HTTP_REQUEST, EXPECTED_RECV_LEN);
	if (parser.upgrade) {
		fprintf(stderr, "\nUpgrade is set\n");
		assert(0);
	} else if (nparsed != (size_t)EXPECTED_RECV_LEN) {
		fprintf(stderr,
				"Error: nparsed = %lu, %s (%s)\n", nparsed,
				http_errno_description(HTTP_PARSER_ERRNO(&parser)),
				http_errno_name(HTTP_PARSER_ERRNO(&parser)));
		if (HTTP_PARSER_ERRNO(&parser) == HPE_PAUSED) {
			fprintf(stderr, "\nThe parser is paused\n");
		}
		return EXIT_FAILURE;
	}

	nparsed = http_parser_execute(&parser, &settings, msg2, msg2_len);

	if (nparsed != (size_t)msg2_len) {
		fprintf(stderr,
				"Error: %s (%s)\n",
				http_errno_description(HTTP_PARSER_ERRNO(&parser)),
				http_errno_name(HTTP_PARSER_ERRNO(&parser)));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
