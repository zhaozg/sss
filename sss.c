/*
 * AEAD wrapper around the Secret shared data
 *
 * Author: Daan Sprenkels <hello@dsprenkels.com>
 *
 * This module implements a AEAD wrapper around some secret shared data,
 * allowing the data to be in any format. (Directly secret-sharing requires the
 * message to be picked uniformly in the message space.)
 *
 * The NaCl cryptographic library is used for the encryption. The encryption
 * scheme that is used for wrapping the message is salsa20/poly1305. Because
 * we are using an ephemeral key, we are using a zero'd nonce.
 */


#include "randombytes.h"
#include "tweetnacl.h"
#include "sss.h"
#include "tweetnacl.h"
#include <assert.h>
#include <string.h>


/*
 * These assertions may be considered overkill, but would if the tweetnacl API
 * ever change we *really* want to prevent buffer overflow vulnerabilities.
 */
#if crypto_secretbox_KEYBYTES != 32
# error "crypto_secretbox_KEYBYTES size is invalid"
#endif


/*
 * Nonce for the `crypto_secretbox` authenticated encryption.
 * The nonce is constant (zero), because we are using an ephemeral key.
 */
static const unsigned char nonce[crypto_secretbox_NONCEBYTES] = { 0 };

sss_Share* sss_new_shares(uint8_t share_len, uint8_t n)
{
	int i;
	uint8_t len;

	sss_Share *s = malloc(sizeof(sss_Share)*n);
	if (s==NULL)
		goto err;

	memset(s, 0, sizeof(sss_Share)*n);
	if (share_len==0)
		return s;

	len = sss_get_SHARE_LEN(sss_get_CLEN(share_len));
	for(i=0; i<n; i++)
	{
		s[i].size = len;
		s[i].share = malloc(len);
		if(s[i].share==NULL)
			goto err;
	}
	return s;
err:
	if (s)
	{
		for(i=0; i<n; i++)
		{
			if(s[i].share) free(s[i].share);
		}
		free(s);
		s = NULL;
	}
	return s;
}

void sss_free_shares(sss_Share *share, uint8_t n)
{
	if(n>0)
	{
		int i;
		for (i=0; i<n; i++)
		{
			free(share[i].share);
		}
	}
	free(share);
}

/*
 * Return a mutable pointer to the ciphertext part of this Share
 */
static uint8_t* get_ciphertext(sss_Share *share)
{
	return &share->share[sss_KEYSHARE_LEN];
}


/*
 * Return a mutable pointer to the Keyshare part of this Share
 */
static sss_Keyshare* get_keyshare(sss_Share *share)
{
	return (sss_Keyshare*) share->share;
}


/*
 * Return a const pointer to the ciphertext part of this Share
 */
static const uint8_t* get_ciphertext_const(const sss_Share *share)
{
	return &((const uint8_t*) share->share)[sss_KEYSHARE_LEN];
}


/*
 * Return a const pointer to the Keyshare part of this Share
 */
static const sss_Keyshare* get_keyshare_const(const sss_Share *share)
{
	return (const sss_Keyshare*) share->share;
}


/*
 * Create `n` shares with theshold `k` and write them to `out`
 */
void sss_create_shares(sss_Share *out,
		       const unsigned char *data, uint8_t MLEN,
		       uint8_t n, uint8_t k)
{
	unsigned char key[32];
	unsigned long long mlen = crypto_secretbox_ZEROBYTES + MLEN;
	uint8_t sss_CLEN = sss_get_CLEN(MLEN);
	int tmp;
	size_t idx;

	uint8_t *m = calloc(1, mlen);
	uint8_t *c = calloc(1, mlen);

	sss_Keyshare keyshares[n];

	/* Generate a random encryption key */
	randombytes(key, sizeof(key));

	/* AEAD encrypt the data with the key */
	memcpy(&m[crypto_secretbox_ZEROBYTES], data, MLEN);
	tmp = crypto_secretbox(c, m, mlen, nonce, key);
	assert(tmp == 0); /* should always happen */

	/* Generate KeyShares */
	sss_create_keyshares(keyshares, key, n, k);

	/* Build regular shares */
	for (idx = 0; idx < n; idx++) {
		memcpy(get_keyshare((sss_Share*) &out[idx]), &keyshares[idx][0],
		sss_KEYSHARE_LEN);
		memcpy(get_ciphertext((sss_Share*) &out[idx]),
			   &c[crypto_secretbox_BOXZEROBYTES], sss_CLEN);
	}
	free(m);
	free(c);
}


/*
 * Combine `k` shares pointed to by `shares` and write the result to `data`
 *
 * This function returns -1 if any of the shares were corrupted or if the number
 * of shares was too low. It is not possible to detect which of these errors
 * did occur.
 */
int sss_combine_shares(uint8_t *data, const sss_Share *shares, uint8_t k)
{
	unsigned char key[crypto_secretbox_KEYBYTES];
	uint8_t sss_CLEN = shares[0].size - sss_KEYSHARE_LEN;
	uint8_t clen = crypto_secretbox_BOXZEROBYTES + sss_CLEN;
	uint8_t sss_MLEN = sss_get_MLEN(sss_CLEN);
	uint8_t *m;
	uint8_t *c;

	sss_Keyshare keyshares[k];
	size_t idx;
	int ret = 0;

	/* Check if all ciphertexts are the same */
	if (k < 1) return -1;

	for (idx = 1; idx < k; idx++) {
		if (memcmp(get_ciphertext_const(&shares[0]),
				   get_ciphertext_const(&shares[idx]), sss_CLEN) != 0) {
			return -1;
		}
	}

	/* Restore the key */
	for (idx = 0; idx < k; idx++) {
		memcpy(&keyshares[idx], get_keyshare_const(&shares[idx]),
			   sss_KEYSHARE_LEN);
	}
	sss_combine_keyshares(key, (const sss_Keyshare*) keyshares, k);

	m = calloc(1, clen);
	c = calloc(1, clen);

	/* Decrypt the ciphertext */
	memcpy(&c[crypto_secretbox_BOXZEROBYTES],
		   &shares->share[sss_KEYSHARE_LEN], sss_CLEN);
	ret |= crypto_secretbox_open(m, c, clen, nonce, key);
	memcpy(data, &m[crypto_secretbox_ZEROBYTES], sss_MLEN);

	free(m);
	free(c);

	return ret;
}
