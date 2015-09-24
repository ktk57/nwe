#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include "hp.h"
#include "ev.h"
#include "Handlers.h"
#include "mtwist.h"
#include "math.h"

static const char SP_RESPONSE_BODY[] =
"<html>\n<head>\n<title>Second Price Calculator</title>\n</head>\n"
"<body bgcolor=\"white\" text=\"black\">\n";

static const char SP_RESPONSE_HDR[] =
"HTTP/1.1 200 OK\r\n"
"Server: nwe-0.1\r\n"
"Content-Type: text/html\r\n";



#define RAND_RANGE 1000000000

#define R_IDX (2)
#define S_IDX (1)
#define T_IDX (0)

static double GET_MAX(
		double a,
		double b
		)
{
	return (a > b)?a:b;
}

static double GET_MIN(
		uint32_t a,
		uint32_t b,
		uint32_t c
		)
{
	if (a < b) {
		return (a < c)?a:c;
	} else {
		return (b < c)?b:c;
	}
}

static int get_idx(
		uint32_t r,
		uint32_t s,
		uint32_t t,
		int64_t n
		)
{
	uint32_t min;
	min = GET_MIN(r, s, t);
	if (min == r) {
		n -= r;
		if (n <= 0) {
			return R_IDX;
		}
		if (s < t) {
			/*
			 * RST
			 */
			n -= s;
			if (n <= 0) {
				return S_IDX;
			}
			return T_IDX;

		} else {
			/*
			 * RTS
			 */
			n -= t;
			if (n <= 0) {
				return T_IDX;
			}
			return S_IDX;
		} 
	} else if (min == s) {
		n -= s;
		if (n <= 0) {
			return S_IDX;
		}
		if (r < t) {
			/*
			 * SRT
			 */
			n -= r;
			if (n <= 0) {
				return R_IDX;
			}
			return T_IDX;

		} else {
			/*
			 * STR
			 */
			n -= t;
			if (n <= 0) {
				return T_IDX;
			}
			return R_IDX;
		}
	} else if (min == t) {
		n -= t;
		if (n <= 0) {
			return T_IDX;
		}
		if (r < s) {
			/*
			 * TRS
			 */
			n -= r;
			if (n <= 0) {
				return R_IDX;
			}
			return S_IDX;

		} else {
			/*
			 * TSR
			 */
			n -= s;
			if (n <= 0) {
				return S_IDX;
			}
			return R_IDX;
		}
	} else {
		assert(0);
	}
}

static double calculate_sp_O_1(
		double fp,
		double shv,
		double var_A,
		double var_B,
		double var_D,
		double r,
		double s,
		double t,
		mt_state* state,
		int* lcounter
		)
{
	/*
	 * Will there be a problem in case of equality?
	 */
#if 0
	assert((shv <= fp) && (r <= 1.0 && s <= 1.0 && t <= 1.0) && (r + s + t) <= 1.0);
#endif
	//double p_i[4] = {shv, shv, shv, shv};
	/*
	 * This shouldn't happen but I can't put an assertion here
	 */
	if (shv <= 0.0 || shv >= fp) {
		return fp;
	}
	double max;
	int i;
	uint32_t rand_n;
	int idx;
	/*
	 * loop counter
	 */
	*lcounter = 0;
	max = GET_MAX(shv + var_A, shv * (1.0 + (var_B/100.0)));
	if (max < fp) {
		return max;
	}

	/*
	 * max >= fp
	 */

	double result_i[3] = {shv, shv, shv};
	double step = 1 + var_D;

	int32_t exponent = (int32_t) ceil(log(fp/shv)/log(step)) - 1;
	double p_n;
	if (exponent > 0) {
		fprintf(stderr, "\nexponent = %d, formula_output = %lf\n", exponent, log(fp/shv)/log(step));
		p_n = shv * pow(step, exponent);
	} else {
		return shv;
	}
	fprintf(stderr, "\np_n = %lf\n", p_n);
#if 0
	while (p_n >= fp) {
		fprintf(stderr, "\nHi");
		p_n /= step;
		(*lcounter)++;
	}
#endif
	/*
	 * Now p_n should be < fp
	 */
	i = 0;
	do {
		result_i[i] = p_n;
		p_n /= step;
		i++;
	} while (p_n > result_i[i] && i < 3);
	fprintf(stderr, "\nfinal2\n");
	for (i = 0; i < 3; i ++) {
		fprintf(stderr, "%lf:", result_i[i]);
	}
	/*
	 * result_i[0] contains the value closest to fp, and result_i[2] contains the value
	 * farthest from fp
	 */
	rand_n = mts_lrand(state);
	rand_n %= RAND_RANGE;
	/*
	 * r corresponds to result_i[2] i.e the one farthest from fp
	 * s corresponds to result_i[1]
	 * t corresponds to result_i[0] i.e the one closest to fp
	 */
	r *= RAND_RANGE;
	s *= RAND_RANGE;
	t *= RAND_RANGE;

	fprintf(stderr, "\nRand n = %u\n", rand_n);
	idx = get_idx(r, s, t, rand_n);
	//idx = get_idx(r, s, t, 109283442);
	return result_i[idx];
}

static double calculate_sp(
		double fp,
		double shv,
		double var_A,
		double var_B,
		double var_D,
		double r,
		double s,
		double t,
		mt_state* state,
		int* lcounter
		)
{
	/*
	 * Will there be a problem in case of equality?
	 */
#if 0
	assert((shv <= fp) && (r <= 1.0 && s <= 1.0 && t <= 1.0) && (r + s + t) <= 1.0);
#endif
	double p_i[4] = {shv, shv, shv, shv};
	double result_i[3];
	double max;
	int index = 0;
	int old_index = 0;
	int i;
	uint32_t rand_n;
	int idx;
	/*
	 * loop counter
	 */
	*lcounter = 0;
	max = GET_MAX(shv + var_A, shv * (1.0 + (var_B/100.0)));
	if (max < fp) {
		return max;
	}
	/*
	 * max >= fp
	 */
	while (p_i[index] < fp) {
		old_index = index;
		index = (index + 1) % 4;
		p_i[index] = p_i[old_index] * (1.0 + var_D);
		(*lcounter)++;
	}
#if 0
	assert(p_i[index] >= fp);
#endif

	/*
	 * Fill the result_i array
	 */
	fprintf(stderr, "\nindex = %d\n", index);
	for (i = 0; i < 4; i ++) {
		fprintf(stderr, "%lf:", p_i[i]);
	}
	for (i = 0; i < 3; i++)
	{
		index = (index - 1 + 4) % 4;
		result_i[i] = p_i[index];
	}
	fprintf(stderr, "\nfinal\n");
	for (i = 0; i < 3; i ++) {
		fprintf(stderr, "%lf:", result_i[i]);
	}
	/*
	 * result_i[0] contains the value closest to fp, and result_i[2] contains the value
	 * farthest from fp
	 */
	rand_n = mts_lrand(state);
	rand_n %= RAND_RANGE;
	/*
	 * r corresponds to result_i[2] i.e the one farthest from fp
	 * s corresponds to result_i[1]
	 * t corresponds to result_i[0] i.e the one closest to fp
	 */
	r *= RAND_RANGE;
	s *= RAND_RANGE;
	t *= RAND_RANGE;

	fprintf(stderr, "\nRand n = %u\n", rand_n);
	idx = get_idx(r, s, t, rand_n);
	//idx = get_idx(r, s, t, 109283442);
	return result_i[idx];
}

void getSP(
		struct Reactor* reactor,
		struct HTTPMsg* msg,
		void* app_data
		)
{
	(void) reactor;
	int ret = 0;
	mt_state* rand_state = (mt_state*) app_data;
	const char* FP = getHTTPMsgQParam(msg, "fp");
	const char* SHV = getHTTPMsgQParam(msg, "shv");
	const char* A = getHTTPMsgQParam(msg, "a");
	const char* B = getHTTPMsgQParam(msg, "b");
	const char* D = getHTTPMsgQParam(msg, "d");
	const char* R = getHTTPMsgQParam(msg, "r");
	const char* S = getHTTPMsgQParam(msg, "s");
	const char* T = getHTTPMsgQParam(msg, "t");
	double fp, shv, var_A, var_B, var_D, r, s, t;
	ret = sprintfHTTPHdr(msg, "%s", SP_RESPONSE_HDR);
	if (ret != 0) {
		fprintf(stderr, "\nERROR sprintfHTTPHdr() failed\n");
		goto END;
	}
	if (FP == NULL || SHV == NULL || A == NULL || B == NULL || D == NULL || R == NULL || S == NULL || T == NULL) {
		ret = sprintfHTTPBody(msg, "%s%s %s %s %s %s %s %s %s %s %s", SP_RESPONSE_BODY, "<center><h1> Incorrect/insufficient query params : Query Params = ", FP, SHV, A, B, D, R, S, T, "</h1></center>\n</body>\n</html>\n");
		goto END;
	}
	sscanf(FP, "%lf", &fp);
	sscanf(SHV, "%lf", &shv);
	sscanf(A, "%lf", &var_A);
	sscanf(B, "%lf", &var_B);
	sscanf(D, "%lf", &var_D);
	sscanf(R, "%lf", &r);
	sscanf(S, "%lf", &s);
	sscanf(T, "%lf", &t);
	int lcounter = 0;
	double result = calculate_sp(fp, shv, var_A, var_B, var_D, r, s, t, rand_state, &lcounter);
	int ecounter = 0;
	double result2 = calculate_sp_O_1(fp, shv, var_A, var_B, var_D, r, s, t, rand_state, &ecounter);
	fprintf(stderr, "\n result = %lf\n", result);
	fprintf(stderr, "\n result2 = %lf\n", result2);
	sprintfHTTPBody(msg, "%s%s fp = %lf shv = %lf A = %lf B = %lf D = %lf r = %lf s = %lf t = %lf loopcounter = %d second_price = %lf, second_price2 = %lf, ecounter = %d%s", SP_RESPONSE_BODY, "<center><h1> Query params : ", fp, shv, var_A, var_B, var_D, r, s, t, lcounter, result, result2, ecounter, "</h1></center>\n</body>\n</html>\n");
END:
	finishHTTPMsg(msg);
}
