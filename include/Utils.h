#ifndef __UTILS_H__
#define __UTILS_H__
#include <stdint.h>
#include <stdbool.h>

/*
 * D stands for Dynamic
 * Dobara mat poochna !
 */
struct DTextBuff {
	char* buf;
	int size;
	int max_size;
};

struct DBinaryBuff {
	unsigned char* buf;
	int size;
	int max_size;
};

struct OffsetPair {
	uint16_t key;
	uint16_t value;
};

struct KeyValuePair {
	char* key;
	char* value;
};

struct KVPArray {
	struct KeyValuePair* kvparray;
	int size;
	int max_size;
};

struct KVPParser {
	struct OffsetPair* kvparray;
	char* buf;
	int size;
};

uint32_t nextPowerOf2(uint32_t);

int parseKVPBuffer(
		struct KVPParser* p,
		char delimiter1,
		char delimiter2,
		bool remove_wspace,
		int n_hint
		);
/*
 * returns the current time in double
 */
double timeNowD();

void destroyDTextBuff(
		struct DTextBuff* p
		);

void destroyDBinaryBuff(
		struct DBinaryBuff* p
		);

void destroyKVPBuffer(
		struct KVPParser* p
		);

void destroyKVPArray(
		struct KVPArray* p
		);
void resetDTextBuff(
		struct DTextBuff* p
		);
void resetDBinaryBuff(
		struct DBinaryBuff* p
		);
int reallocate_mem(
		unsigned char** buf,
		int size,
		int* max_size,
		int len,
		int hint_size,
		bool nul_char_required
		);
#endif
