#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include "CoroCtxPool.h"
#include "Err.h"

int createCoroCtxStacks(
		struct CoroCtxPool* cp,
		size_t num_stacks,
		size_t stack_size,
		long page_size
		)
{
	struct CoroCtx* list = (struct CoroCtx*) malloc(num_stacks * sizeof(struct CoroCtx));

	if (list == NULL) {
		fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
		return ERR_HEAP_ALLOC_FAILURE;
	}

	/*
	 * Guard pages for stack
	 */
	stack_size += page_size;
	==================
    /* mmap supposedly does allocate-on-write for us */
    void* base = mmap (0, num_stacks * stack_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (base == MAP_FAILED) {
		/* some systems don't let us have executable heap */
		/* we assume they won't need executable stack in that case */
		base = mmap (0, num_stacks * stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (base == MAP_FAILED) {
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
			fprintf(stderr, "\nERROR mmap() failed with errno = %d %s:%d\n", errno, __FILE__, __LINE__);
#endif
			return ERR_SYSCALL_FAILED; 

		}
	}

	int ret = mprotect (base, CORO_GUARDPAGES * PAGESIZE, PROT_NONE);

    base = (void*)((char *)base + CORO_GUARDPAGES * PAGESIZE);
		=================
	size_t ctx_offset = stack_size - sizeof(struct ribs_context) - reserved_size;
	size_t i;
	int ret = 0;
	for (i = 0; i < num_stacks; ++i, mem += stack_size) {
	ret = mprotect (base, page_size, PROT_NONE);
		if (MAP_FAILED == mmap(mem, 4096, PROT_NONE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))
			return LOGGER_PERROR("mmap, ctx_pool_init, PROT_NONE"), -1;
		struct ribs_context *rc = (struct ribs_context *)(mem + ctx_offset);
		rc->next_free = cp->freelist;
		cp->freelist = rc;
	}
	return 0;
}

int initCoroCtxPool(
		struct CoroCtxPool* cp,
		size_t init_size,
		size_t grow_by,
		size_t stack_size
		)
{
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		fprintf(stderr, "\nERROR sysconf() failed with errno = %d %s:%d\n", errno, __FILE__, __LINE__);
		return ERR_INTERNAL;
	}
	/*
	 * Find the next multiple of page_size
	 */
	stack_size += page_size;
	stack_size &= ~(unsigned long) page_size;
	cp->grow_by = grow_by;
	cp->stack_size = stack_size;
	cp->freelist = NULL;
	fprintf(stderr, "\nINFO: page_size = %ld, creating stacks of size %d %s:%d\n", page_size, stack_size, __FILE__, __LINE__);
	return createCoroCtxStacks(cp, init_size, stack_size, page_size);
}

struct ribs_context *ctx_pool_get(struct ctx_pool *cp) {
   if (NULL == cp->freelist && 0 != ctx_pool_createstacks(cp, cp->grow_by, cp->stack_size, cp->reserved_size))
      return NULL;
   struct ribs_context *ctx = cp->freelist;
   cp->freelist = ctx->next_free;
   return ctx;
}

void ctx_pool_put(struct ctx_pool *cp, struct ribs_context *ctx) {
   ctx->next_free = cp->freelist;
   cp->freelist = ctx;
}
