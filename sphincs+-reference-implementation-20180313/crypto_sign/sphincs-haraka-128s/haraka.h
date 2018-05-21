#ifndef SPX_HARAKA_H
#define SPX_HARAKA_H

/* Tweak constants with seed */
void tweak_constants(const unsigned char *pk_seed, const unsigned char *sk_seed, 
	                 unsigned long long seed_length);

/* Haraka Sponge */
void haraka_S(unsigned char *out, unsigned long long outlen,
              const unsigned char *in, unsigned long long inlen);

/* Applies the 512-bit Haraka permutation to in. */
void haraka512_perm(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-512 */
void haraka512(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-256 */
void haraka256(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-256 using sk.seed constants */
void haraka256_sk(unsigned char *out, const unsigned char *in);

#endif
