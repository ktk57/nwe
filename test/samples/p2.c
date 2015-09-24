#include <stdint.h>
#include <stdio.h>
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
int main()
{
	printf("\n%d\n", nextPowerOf2(5));
	printf("\n%d\n", nextPowerOf2(2));
	printf("\n%d\n", nextPowerOf2(19));
	printf("\n%d\n", nextPowerOf2(33));
	printf("\n%d\n", nextPowerOf2(0));
	return 0;
}
