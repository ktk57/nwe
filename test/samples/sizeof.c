#include <stdint.h>
#include <stdio.h>
#define NUM_ADDITIONAL_REGS 10
struct ribs_context {
#if 0
#if defined(__x86_64__) || defined (__i386__)
    uintptr_t stack_pointer_reg;
    uintptr_t parent_context_reg;
    uintptr_t additional_reg[NUM_ADDITIONAL_REGS];
    struct ribs_context *next_free;
#endif
    //struct memalloc memalloc;
    uint32_t ribify_memalloc_refcount;
#endif
    char reserved[];
};
int main()
{
	fprintf(stderr, "\nsizeof(struct ribs_context) = %lu\n", sizeof(struct ribs_context));
	return 0;
}
