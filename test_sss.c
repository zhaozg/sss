#include "sss.h"
#include <assert.h>
#include <string.h>

#define sss_MLEN 32
int main(void)
{
	unsigned char data[sss_MLEN] = { 42 }, restored[sss_MLEN];
	int tmp;
	sss_Share *shares = sss_new_shares(sss_MLEN, 255);

	/* Normal operation */
	sss_create_shares(shares, data, sss_MLEN, 1, 1);
	tmp = sss_combine_shares(restored, (const sss_Share*) shares, 1);
	assert(tmp == 0);
	assert(memcmp(restored, data, sss_MLEN) == 0);

	/* A lot of shares */
	sss_create_shares(shares, data, sss_MLEN, 255, 255);
	tmp = sss_combine_shares(restored, (const sss_Share*) shares, 255);
	assert(tmp == 0);
	assert(memcmp(restored, data, sss_MLEN) == 0);

	/* Not enough shares to restore secret */
	sss_create_shares(shares, data, sss_MLEN, 100, 100);
	tmp = sss_combine_shares(restored, (const sss_Share*) shares, 99);
	assert(tmp == -1);

	/* Too many secrets should also restore the secret */
	sss_create_shares(shares, data, sss_MLEN, 200, 100);
	tmp = sss_combine_shares(restored, (const sss_Share*) shares, 200);
	assert(tmp == 0);
	assert(memcmp(restored, data, sss_MLEN) == 0);



	sss_free_shares(shares, 255);
	return 0;
}
