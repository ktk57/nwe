#include <stdio.h>
#include <stdlib.h>
#include "hp.h"
#include "ev.h"
#include "Handlers.h"
#include "Timer.h"

const char RESPONSE_HEADER[] =
"HTTP/1.1 200 OK\r\n"
"Server: NaMo\r\n"
"Content-Type: text/html\r\n";

int RESP_HEADER_SIZE = sizeof(RESPONSE_HEADER) - 1;

/*
const char RESPONSE_BODY[] =
"<html>\n<head>\n<title>Welcome to ModiWS!</title>\n</head>\n"
"<body bgcolor=\"white\" text=\"black\">\n"
"<center><h1>Welcome to Modi WebServer...Abki baar Modi Sarkar!</h1></center>\n</body>\n</html>\n";
*/

const char RESPONSE_BODY[] = "{\"PubMatic_Bid\":{\"ecpm\":373.000000,\"creative_tag\":\"<span class=\\\"PubAPIAd\\\"><script type=\\\"text/javascript\\\"> document.writeln('<iframe width=\\\"728\\\" scrolling=\\\"no\\\" height=\\\"90\\\" frameborder=\\\"0\\\" name=\\\"iframe0\\\" allowtransparency=\\\"true\\\" marginheight=\\\"0\\\" marginwidth=\\\"0\\\" vspace=\\\"0\\\" hspace=\\\"0\\\" src=\\\"http://172.16.4.74/a/1xx.html\\\"></iframe>');</script></span> <!-- PubMatic Ad Ends -->\",\"tracking_url\":\"http://172.16.4.74/AdServer/AdDisplayTrackerServlet?operId=1&pubId=36476&siteId=44046&adId=72299&adServerId=243&kefact=373.000000&kaxefact=373.000000&kadNetFrequecy=0&kadwidth=728&kadheight=90&kadsizeid=7&kltstamp=1402987798&indirectAdId=0&adServerOptimizerId=2&ranreq=0.9347751946852118&kpbmtpfact=373.000000&dcId=1&tldId=0&passback=0&imprId=40BB9EEA-352B-44DC-A63D-5AA85AC47D28&campaignId=10694&creativeId=0&pctr=0.000000&wDSPByrId=1498&pageURL=http%3A%2F%2F172.16.4.79%2FAggregator%2Fcurse.html\",\"landing_page\":\"abc.com\",\"autorefresh_time\":0,\"prefetch_data\":0}}";

int RESP_BODY_SIZE = sizeof(RESPONSE_BODY) - 1;

const char SMALL_RESPONSE_HEADER[] =
"HTTP/1.1 200 OK\r\n"
"Server: NaMo\r\n"
"Content-Type: text/html\r\n";

int SMALL_RESP_HEADER_SIZE = sizeof(SMALL_RESPONSE_HEADER) - 1;

const char SMALL_RESPONSE_BODY[] =
"NaMo NaMo";

int SMALL_RESP_BODY_SIZE = sizeof(SMALL_RESPONSE_BODY) - 1;

/*
static void writeSmallResponse(
		struct HTTPMsg* msg
		)
{
	int ret = 0;
	ret = writeHTTPHdr(msg, SMALL_RESPONSE_HEADER, SMALL_RESP_HEADER_SIZE);
	if (ret != 0) {
		fprintf(stderr, "\nERROR writeHTTPHeader() failed\n");
		goto END;
	}
	ret = writeHTTPBody(msg, SMALL_RESPONSE_BODY, SMALL_RESP_BODY_SIZE);
	if (ret != 0) {
		fprintf(stderr, "\nERROR writeHTTPBody() failed\n");
		goto END;
	}
END:
	finishHTTPMsg(msg);
}
*/
static void writeResponse(
		struct HTTPMsg* msg
		)
{
	int ret = 0;
	ret = writeHTTPHdr(msg, RESPONSE_HEADER, RESP_HEADER_SIZE);
	if (ret != 0) {
		fprintf(stderr, "\nERROR writeHTTPHeader() failed\n");
		goto END;
	}
	ret = writeHTTPBody(msg, RESPONSE_BODY, RESP_BODY_SIZE);
	if (ret != 0) {
		fprintf(stderr, "\nERROR writeHTTPBody() failed\n");
		goto END;
	}
END:
	finishHTTPMsg(msg);
}
/*
static void sprintfResponse(
		struct HTTPMsg* msg
		)
{
	int ret = 0;
	ret = sprintfHTTPHdr(msg, "%s", RESPONSE_HEADER);
	if (ret != 0) {
		fprintf(stderr, "\nERROR sprintfHTTPHdr() failed\n");
		goto END;
	}
	ret = sprintfHTTPBody(msg, "%s", RESPONSE_BODY);
	if (ret != 0) {
		fprintf(stderr, "\nERROR sprintfHTTPBody() failed\n");
		goto END;
	}
END:
	finishHTTPMsg(msg);
}
*/

static void sprintfSmallResponse(
		struct HTTPMsg* msg
		)
{
	int ret = 0;
	ret = sprintfHTTPHdr(msg, "%s", SMALL_RESPONSE_HEADER);
	if (ret != 0) {
		fprintf(stderr, "\nERROR sprintfHTTPHdr() failed\n");
		goto END;
	}
	ret = sprintfHTTPBody(msg, "%s", SMALL_RESPONSE_BODY);
	if (ret != 0) {
		fprintf(stderr, "\nERROR sprintfHTTPBody() failed\n");
		goto END;
	}
END:
	finishHTTPMsg(msg);
}

void helloWorld(
		//struct ev_loop* loop,
		struct Reactor* reactor,
		struct HTTPMsg* msg,
		void* app_data
		)
{
	(void) reactor;
	(void) app_data;
	//writeResponse(msg);
	//sprintfResponse(msg);
	sprintfSmallResponse(msg);
}

static void cb(
		struct Reactor* reactor,
		struct Timer* tmr,
		void* ctxt,
		int revents
		)
{
	(void) reactor;
	(void) revents;
	free(tmr);
	writeResponse((struct HTTPMsg*) ctxt);
}
void dspSim(
		struct Reactor* reactor,
		struct HTTPMsg* msg,
		void* app_data
		)
{
	(void) app_data;
	int ret = 0;
	const char* tmout = getHTTPMsgQParam(msg, "tMt");
	if (tmout != NULL) {
		int value = atoi(tmout);
		struct Timer* tmr = (struct Timer*) malloc(sizeof(struct Timer));
		if (tmr != NULL) {
			ret = initTimer(reactor, tmr, cb, (void*) msg, value);
			if (ret == 0) {
				startTimer(tmr);
				goto END;
			} else {
				fprintf(stderr, "\nERROR timer couldn't be init()'ed %s:%d\n", __FILE__, __LINE__);
			}
		} 
	}
	//writeSmallResponse(msg);
	//	writeResponse(msg);
	sprintfSmallResponse(msg);
END:
	return;
}
