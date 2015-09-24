#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include "Utils.h"
#include "Err.h"

static int sortKVP(
		const void* l,
		const void* r,
		void* arg
		)
{
	const struct OffsetPair* left = (const struct OffsetPair*) l;
	const struct OffsetPair* right = (const struct OffsetPair*) r;
	const char* buf = (const char*) arg;
	return strcmp(buf + left->key, buf + right->key);
}

uint32_t nextPowerOf2(uint32_t n)
{
	uint32_t result = n - 1;
	result |= (result >> 1);
	result |= (result >> 2);
	result |= (result >> 4);
	result |= (result >> 8);
	result |= (result >> 16);
	result++;
	return (result == 0)?1:result;
}

void resetDTextBuff(
		struct DTextBuff* p
		)
{
	p->size = 0;
}
void resetDBinaryBuff(
		struct DBinaryBuff* p
		)
{
	p->size = 0;
}
void destroyDBinaryBuff(
		struct DBinaryBuff* p
		)
{
	free(p->buf);
}

void destroyDTextBuff(
		struct DTextBuff* p
		)
{
	free(p->buf);
}

void destroyKVPArray(
		struct KVPArray* p
		)
{
	struct KeyValuePair* kvparray = p->kvparray;
	int size = p->size;
	for (int i = 0; i < size; i++) {
		free(kvparray[i].key);
		free(kvparray[i].value);
	}
	free(kvparray);
}

void destroyKVPBuffer(
		struct KVPParser* p
		)
{
	free(p->kvparray);
}
/*
 * Pre-requisites :-
 * buf != NULL && buf[0] != '\0'
 * n_hint > 0
 * p->kvparray = NULL;
 */
int parseKVPBuffer(
		struct KVPParser* p,
		char delimiter1,
		char delimiter2,
		bool remove_wspace,
		int n_hint
		)
{
	char delim[] = {delimiter1, '\0'};
	char* buf = p->buf;

	struct OffsetPair* kvparray = p->kvparray;

	int max_size = nextPowerOf2(n_hint);

	kvparray = (struct OffsetPair*) malloc(max_size * sizeof(struct OffsetPair));
	if (kvparray == NULL) {
		fprintf(stderr, "\nERROR malloc() failed %s:%d\n", __FILE__, __LINE__);
		return ERR_HEAP_ALLOC_FAILURE;
	}
	int size = 0;
	char* ctxt = NULL;
	char* token = NULL;
	token = strtok_r(buf, delim, &ctxt);
	while (token != NULL) {
		struct OffsetPair* kvp = &(kvparray[size]);
		if (remove_wspace) {
			/*
			 * Remove the spaces on left for key
			 */
			while (isspace(*token)) {
				token++;
			}
		}
		/*
		 * Got the key offset
		 */
		kvp->key = token - buf;
		char* temp = strchr(token, delimiter2);
		if (temp != NULL) {
			/*
			 * We have a key-value pair
			 */
			*temp = '\0';
			if (remove_wspace) {
				char* tmp = temp - 1;
				/*
				 * Remove spaces on right for key
				 */
				while (tmp > token && isspace(*tmp)) {
					*tmp = '\0';
					tmp--;
				}
				/*
				 * Remove spaces on right for value
				 */
				tmp = (*ctxt)?ctxt - 2:ctxt - 1;
				while (tmp > temp && isspace(*tmp)) {
					*tmp = '\0';
					tmp--;
				}
				/*
				 * Remove spaces on left for value
				 */
				tmp = temp + 1;
				while (*tmp && isspace(*tmp)) {
					*tmp = '\0';
					tmp++;
				}
				temp = tmp - 1;
			}
			kvp->value = temp - buf + 1;
			size++;
			if (size >= max_size) {
				max_size *= 2;
				struct OffsetPair* tmp = (struct OffsetPair*) realloc(kvparray, max_size * sizeof(struct OffsetPair));
				if (tmp == NULL) {
					/*
					 * TODO No need to return error code
					 * Is this correct behaviour?
					 */
					fprintf(stderr, "\nERROR realloc() failed %s:%d\n", __FILE__, __LINE__);
					break;
				}
				kvparray = tmp;
			}
		}
		token = strtok_r(NULL, delim, &ctxt);
	}
	if (size > 1) {
		qsort_r(kvparray, size, sizeof(struct OffsetPair), sortKVP, buf);
	}
	p->kvparray = kvparray;
	p->size = size;
	//p->max_size = max_size;
	return 0;
}
/*
 * returns 0 in case of success
 * ERR_HEAP_ALLOC_FAILURE in case of failure
 *
 * Changes *max_size and *buf if required
 */
int reallocate_mem(
		unsigned char** buf,
		int size,
		int* max_size,
		int len,
		int hint_size,
		bool nul_char_required
		)
{
#if defined (DEBUG) || defined (STRINGENT_ERROR_CHECKING)
	assert(size >= 0 && *max_size >= 0 && len >= 0 && hint_size >= 0);
#endif
	int ret = 0;
	int allocated_size = *max_size;
	/*
	 * For NUL character
	 */
	len += (nul_char_required == true)?1:0;
	int available_space = allocated_size - size;
	if (len > available_space) {
		/*
		 * We need to reallocate memory
		 */
		int space_required = len - available_space;
		int tmp_max_size = allocated_size * 2;
		int tmp_new_size = allocated_size + space_required;
		/*
		 * TODO check this logic
		 */
		allocated_size = (allocated_size == 0)? (int) nextPowerOf2(len  > hint_size ? len : hint_size) : (tmp_max_size >= tmp_new_size) ? tmp_max_size:(int) nextPowerOf2(tmp_new_size);
		unsigned char* temp = (unsigned char*) realloc(*buf, allocated_size * sizeof(unsigned char));
		if (temp == NULL) {
			/*
			 * TODO 
			 * check if we need to do this here
			 * I am not free()'ing free(buf);
			 */
			fprintf(stderr, "\nERROR realloc() failed for size = %d %s:%d\n", allocated_size, __FILE__, __LINE__);
			ret = ERR_HEAP_ALLOC_FAILURE;
		} else {
			*buf = temp;
			*max_size = allocated_size;
		}
	}
	return ret;
}
/*
 * returns the current time in double
 */
double timeNowD()
{
	errno = 0;
	int ret = 0;
	struct timespec now;
	now.tv_sec = 0;
	now.tv_nsec = 0;
	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &now);
	if (ret < 0) {
		perror("\nclock_gettime() failed");
		assert(0);
	}
	return now.tv_sec + now.tv_nsec * 1e-9;
}
