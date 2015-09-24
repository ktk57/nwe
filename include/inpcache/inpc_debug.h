#ifndef __INPDEBUG__
#define __INPDEBUG__


#ifdef INPDEBUG 
#define inpc_debug(format, ...) fprintf(stdout, "D:%s:" format "\n", __FUNCTION__, ##__VA_ARGS__);
#else
#define inpc_debug(format, ...)
#endif

#define inpc_error_print(format, ...) fprintf(stdout, "E:%s:" format "\n", __FUNCTION__, ##__VA_ARGS__);
#define inpc_error_log(format, ...) fprintf(stdout, "E:%s:" format "\n", __FUNCTION__, ##__VA_ARGS__);
#define inpc_log(format, ...) fprintf(stdout, "L:%s:" format "\n", __FUNCTION__, ##__VA_ARGS__);

#define aprint(format, ...) fprintf(stdout, "A:%s:" format "\n", __FUNCTION__, ##__VA_ARGS__);

#endif
