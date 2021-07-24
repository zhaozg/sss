/*
 * Intermediate level API for Daan Sprenkels' Shamir secret sharing library
 * Copyright (c) 2017 Daan Sprenkels <hello@dsprenkels.com>
 */


#ifndef sss_SSS_H_
#define sss_SSS_H_

#include "hazmat.h"
#include "tweetnacl.h"
#include <inttypes.h>
#include <stdlib.h>
#include <assert.h>

/*
 * One share of a secret which is shared using Shamir's
 * the `sss_create_shares` function.
 */
typedef struct {
	size_t size;
	uint8_t *share;
}sss_Share;

/*
get length of the ciphertext including the message authentication by message len
*/
static
inline uint8_t sss_get_CLEN(uint8_t mlen)
{
	return mlen + 16;
}

/*
get length of the message by ciphertext including the message authenticatio
*/
static
inline uint8_t sss_get_MLEN(uint8_t clen)
{
	return clen - 16;
}

/*
 * get length of a SSS share
 */
static
inline uint8_t sss_get_SHARE_LEN(uint8_t clen)
{
	assert(clen<255-sss_KEYSHARE_LEN);
	if (clen>255-sss_KEYSHARE_LEN)
		return 0;
	return clen + sss_KEYSHARE_LEN;
}


sss_Share* sss_new_shares(uint8_t share_len, uint8_t n);
void sss_free_shares(sss_Share *share, uint8_t n);

/*
 * Create `n` shares of the secret data `data`. Share such that `k` or more
 * shares will be able to restore the secret.
 *
 * This function will put the resulting shares in the array pointed to by
 * `out`. The caller has to guarantee that this array will fit at least `n`
 * instances of `sss_Share`.
 */
void sss_create_shares(sss_Share *out,
                       const uint8_t *data, uint8_t MLEN,
                       uint8_t n,
                       uint8_t k);


/*
 * Combine the `k` shares pointed to by `shares` and put the resulting secret
 * data in `data`. The caller has to ensure that the `data` array will fit
 * at least `sss_MLEN` (default: 64) bytes.
 *
 * On success, this function will return 0. If combining the secret fails,
 * this function will return a nonzero return code. On failure, the value
 * in `data` may have been altered, but must still be considered secret.
 */
int sss_combine_shares(uint8_t *data,
                       const sss_Share *shares,
                       uint8_t k);


#endif /* sss_SSS_H_ */
