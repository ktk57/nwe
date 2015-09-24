/*
 * compile with
 * gcc -std=c99 -D_GNU_SOURCE -Wall -Wextra -I../../ -I. ../../Utils.c token.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Utils.h"
void print(const struct KVPParser* qparams)
{
	int size = qparams->size;
	struct OffsetPair* kvparray = qparams->kvparray;
	int i = 0;
	char* buf = qparams->buf;
	for (i = 0; i < size; i++) {
		struct OffsetPair* kvp = &(kvparray[i]);
		fprintf(stderr, "\n%s:%s\n", buf + kvp->key, buf + kvp->value);
	}
}
int main()
{
	char buf1[] = "";
	char buf2[] = "z=b & 		c= def & g = hakjdkjsk&a =b&c=def&g=hakjdkjska=b&c=def&g=hakjdkjska=b&c=def&g=hakjdkjsk&&&";
	char buf3[] = " a=b&c=";
	struct KVPParser qparams;
	memset(&qparams, 0, sizeof(struct KVPParser));
	qparams.buf = buf2;
	int ret = parseKVPBuffer(&qparams, '&', '=', true, 1);
	if (ret != 0) {
		fprintf(stderr, "\nparseKVPBuffer() failed\n");
	} else {
		print(&qparams);
	}
	qparams.buf = buf3;
	ret = parseKVPBuffer(&qparams, '&', '=', true, 1);
	if (ret != 0) {
		fprintf(stderr, "\nparseKVPBuffer() failed\n");
	} else {
		print(&qparams);
	}
	return 0;
}
