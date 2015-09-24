#ifndef __ERR_H__
#define __ERR_H__

/*
 * Success of a non-void function is determined by a return code 0
 */

/*
 * malloc()/realloc() failed
 */
#define ERR_HEAP_ALLOC_FAILURE (-1)
/*
 * Buffer overflow
 */
#define ERR_BUFF_OVERFLOW (-2)
/*
 * Buffer underflow
 */
#define ERR_BUFF_UNDERFLOW (-3)
/*
 * HTTP Parsing error
 */
#define ERR_HTTP_PARSER (-4)

#define ERR_INTERNAL (-5)

#define ERR_HTTP_METHOD_NOT_IMPLEMENTED (-6)

#define ERR_HTTP_PARSER_PAUSED (-7)

#define ERR_HTTP_MSG_WRITE_REDUNDANT (-8)

#define ERR_SYSCALL_FAILED (-9)
#endif
