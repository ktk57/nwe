#ifndef __CORO_CTX_H__
#define __CORO_CTX_H__
#include "coro.h"

struct CoroCtx {
	coro_context ctx;
	struct CoroCtx* next;
};

#endif
