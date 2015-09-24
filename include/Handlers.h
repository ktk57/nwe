#ifndef __HANDLERS_H__
#define __HANDLERS_H__

struct Reactor;
struct HTTPMsg;

void helloWorld(
		struct Reactor* reactor,
		struct HTTPMsg* msg,
		void* app_data
		);
void defaultHandler(
		struct Reactor* reactor,
		struct HTTPMsg* msg,
		void* app_data
		);
void dspSim(
		struct Reactor* reactor,
		struct HTTPMsg* msg,
		void* app_data
		);
void getSP(
		struct Reactor* reactor,
		struct HTTPMsg* msg,
		void* app_data
		);
#endif
