#ifndef __CORO_CONTEXT_POOL_H__
#define __CORO_CONTEXT_POOL_H__


struct CoroCtx;
struct CoroCtxPool {
    size_t grow_by;
    size_t stack_size;
    //size_t reserved_size;
		/*
		 * free list
		 */
    struct CoroCtx* flist;
};

int initCoroCtxPool(struct CoroCtxPool*, size_t, size_t, size_t);
int createCoroCtxStacks(struct CoroCtxPool*, size_t, size_t);
struct CoroCtx* ctx_pool_get(struct CoroCtxPool*);
void ctx_pool_put(struct CoroCtxPool*, struct CoroCtx*);

#endif
