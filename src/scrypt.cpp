/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2013 Marco Tessarotto
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#define __STDC_LIMIT_MACROS

#include "scrypt.h"
#include <stdlib.h>


#include <stdint.h>

#include "uint256.h"
#include "bignum.h"
#include "hash.h"

#include <string.h>
#include <openssl/sha.h>
#include <errno.h>

static void blkcpy(uint8_t *, uint8_t *, size_t);
static void blkxor(uint8_t *, uint8_t *, size_t);
static void salsa20_8(uint8_t[64]);
static void blockmix_salsa8(uint8_t *, uint8_t *, size_t);
static uint64_t integerify(uint8_t *, size_t);
static void smix(uint8_t *, size_t, uint64_t, uint8_t *, uint8_t *);



static double dataFinal [][4] = {
		{ 1 , 8 , 7 , 0.063 },
		{ 8 , 7 , 1 , 0.063 },
		{ 2 , 4 , 7 , 0.061 },
		{ 1 , 4 , 14 , 0.06 },
		{ 1 , 14 , 4 , 0.062 },
		{ 4 , 2 , 7 , 0.061 },
		{ 8 , 1 , 7 , 0.062 },
		{ 1 , 5 , 11 , 0.059 },
		{ 2 , 7 , 4 , 0.065 },
		{ 2 , 14 , 2 , 0.062 },
		{ 4 , 7 , 2 , 0.061 },
		{ 4 , 1 , 14 , 0.063 },
		{ 4 , 14 , 1 , 0.063 },
		{ 2 , 2 , 14 , 0.062 },
		{ 1 , 10 , 6 , 0.066 },
		{ 1 , 12 , 5 , 0.066 },
		{ 2 , 3 , 10 , 0.069 },
		{ 2 , 5 , 6 , 0.066 },
		{ 2 , 6 , 5 , 0.068 },
		{ 2 , 10 , 3 , 0.065 },
		{ 2 , 15 , 2 , 0.067 },
		{ 1 , 4 , 15 , 0.066 },
		{ 1 , 15 , 4 , 0.071 },
		{ 4 , 1 , 15 , 0.067 },
		{ 4 , 3 , 5 , 0.068 },
		{ 2 , 2 , 15 , 0.066 },
		{ 4 , 5 , 3 , 0.066 },
		{ 1 , 6 , 10 , 0.067 },
		{ 1 , 7 , 9 , 0.073 },
		{ 1 , 9 , 7 , 0.068 },
		{ 1 , 5 , 12 , 0.066 },
		{ 4 , 15 , 1 , 0.067 },
		{ 1 , 8 , 8 , 0.07 },
		{ 4 , 8 , 2 , 0.071 },
		{ 2 , 4 , 8 , 0.072 },
		{ 2 , 8 , 4 , 0.07 },
		{ 4 , 2 , 8 , 0.071 },
		{ 4 , 4 , 4 , 0.072 },
		{ 1 , 6 , 11 , 0.072 },
		{ 8 , 4 , 2 , 0.071 },
		{ 1 , 11 , 6 , 0.073 },
		{ 1 , 13 , 5 , 0.071 },
		{ 2 , 11 , 3 , 0.074 },
		{ 8 , 1 , 8 , 0.073 },
		{ 32 , 1 , 2 , 0.073 },
		{ 32 , 2 , 1 , 0.076 },
		{ 2 , 3 , 11 , 0.073 },
		{ 16 , 1 , 4 , 0.072 },
		{ 8 , 8 , 1 , 0.071 },
		{ 16 , 2 , 2 , 0.074 },
		{ 16 , 4 , 1 , 0.071 },
		{ 1 , 5 , 13 , 0.071 },
		{ 1 , 10 , 7 , 0.077 },
		{ 1 , 14 , 5 , 0.079 },
		{ 2 , 7 , 5 , 0.082 },
		{ 8 , 2 , 4 , 0.071 },
		{ 1 , 9 , 8 , 0.079 },
		{ 2 , 3 , 12 , 0.079 },
		{ 2 , 4 , 9 , 0.081 },
		{ 2 , 5 , 7 , 0.08 },
		{ 2 , 9 , 4 , 0.078 },
		{ 2 , 12 , 3 , 0.079 },
		{ 1 , 5 , 14 , 0.083 },
		{ 1 , 6 , 12 , 0.079 },
		{ 2 , 6 , 6 , 0.079 },
		{ 4 , 2 , 9 , 0.08 },
		{ 4 , 6 , 3 , 0.078 },
		{ 64 , 1 , 1 , 0.075 },
		{ 1 , 8 , 9 , 0.083 },
		{ 1 , 12 , 6 , 0.082 },
		{ 4 , 9 , 2 , 0.087 },
		{ 8 , 1 , 9 , 0.1 },
		{ 8 , 3 , 3 , 0.082 },
		{ 4 , 3 , 6 , 0.079 },
		{ 8 , 9 , 1 , 0.08 },
		{ 1 , 7 , 10 , 0.078 },
		{ 1 , 5 , 15 , 0.084 },
		{ 1 , 15 , 5 , 0.084 },
		{ 1 , 11 , 7 , 0.088 },
		{ 1 , 6 , 13 , 0.085 },
		{ 1 , 7 , 11 , 0.085 },
		{ 1 , 8 , 10 , 0.09 },
		{ 1 , 13 , 6 , 0.086 },
		{ 2 , 3 , 13 , 0.096 },
		{ 2 , 13 , 3 , 0.086 },
		{ 8 , 5 , 2 , 0.088 },
		{ 1 , 10 , 8 , 0.087 },
		{ 2 , 5 , 8 , 0.087 },
		{ 2 , 8 , 5 , 0.089 },
		{ 2 , 4 , 10 , 0.093 },
		{ 4 , 4 , 5 , 0.087 },
		{ 8 , 2 , 5 , 0.088 },
		{ 1 , 9 , 9 , 0.09 },
		{ 2 , 10 , 4 , 0.089 },
		{ 4 , 2 , 10 , 0.089 },
		{ 4 , 5 , 4 , 0.089 },
		{ 4 , 10 , 2 , 0.086 },
		{ 8 , 1 , 10 , 0.09 },
		{ 8 , 10 , 1 , 0.088 },
		{ 16 , 1 , 5 , 0.091 },
		{ 1 , 7 , 12 , 0.113 },
		{ 2 , 14 , 3 , 0.102 },
		{ 1 , 6 , 14 , 0.119 },
		{ 1 , 14 , 6 , 0.098 },
		{ 4 , 7 , 3 , 0.116 },
		{ 16 , 5 , 1 , 0.099 },
		{ 4 , 3 , 7 , 0.108 },
		{ 1 , 12 , 7 , 0.111 },
		{ 2 , 3 , 14 , 0.112 },
		{ 2 , 7 , 6 , 0.096 },
		{ 1 , 8 , 11 , 0.104 },
		{ 4 , 11 , 2 , 0.108 },
		{ 1 , 11 , 8 , 0.104 },
		{ 2 , 6 , 7 , 0.092 },
		{ 2 , 11 , 4 , 0.099 },
		{ 2 , 15 , 3 , 0.097 },
		{ 1 , 6 , 15 , 0.098 },
		{ 1 , 9 , 10 , 0.098 },
		{ 1 , 7 , 13 , 0.102 },
		{ 1 , 15 , 6 , 0.104 },
		{ 2 , 4 , 11 , 0.102 },
		{ 2 , 5 , 9 , 0.102 },
		{ 4 , 2 , 11 , 0.096 },
		{ 1 , 10 , 9 , 0.101 },
		{ 2 , 3 , 15 , 0.1 },
		{ 2 , 9 , 5 , 0.095 },
		{ 8 , 1 , 11 , 0.1 },
		{ 1 , 13 , 7 , 0.098 },
		{ 2 , 12 , 4 , 0.107 },
		{ 4 , 12 , 2 , 0.106 },
		{ 8 , 11 , 1 , 0.128 },
		{ 8 , 4 , 3 , 0.11 },
		{ 2 , 6 , 8 , 0.119 },
		{ 2 , 8 , 6 , 0.108 },
		{ 2 , 4 , 12 , 0.123 },
		{ 4 , 8 , 3 , 0.118 },
		{ 1 , 12 , 8 , 0.117 },
		{ 4 , 2 , 12 , 0.116 },
		{ 8 , 2 , 6 , 0.127 },
		{ 8 , 6 , 2 , 0.114 },
		{ 16 , 3 , 2 , 0.124 },
		{ 4 , 6 , 4 , 0.119 },
		{ 8 , 1 , 12 , 0.128 },
		{ 1 , 9 , 11 , 0.118 },
		{ 2 , 10 , 5 , 0.126 },
		{ 8 , 3 , 4 , 0.119 },
		{ 1 , 7 , 14 , 0.114 },
		{ 1 , 8 , 12 , 0.113 },
		{ 4 , 3 , 8 , 0.118 },
		{ 4 , 4 , 6 , 0.124 },
		{ 16 , 1 , 6 , 0.124 },
		{ 1 , 10 , 10 , 0.114 },
		{ 1 , 11 , 9 , 0.113 },
		{ 2 , 5 , 10 , 0.114 },
		{ 16 , 2 , 3 , 0.115 },
		{ 16 , 6 , 1 , 0.122 },
		{ 2 , 7 , 7 , 0.13 },
		{ 32 , 1 , 3 , 0.123 },
		{ 1 , 8 , 13 , 0.131 },
		{ 2 , 13 , 4 , 0.118 },
		{ 4 , 5 , 5 , 0.113 },
		{ 4 , 13 , 2 , 0.118 },
		{ 32 , 3 , 1 , 0.129 },
		{ 1 , 14 , 7 , 0.112 },
		{ 1 , 7 , 15 , 0.124 },
		{ 8 , 12 , 1 , 0.127 },
		{ 1 , 15 , 7 , 0.131 },
		{ 1 , 13 , 8 , 0.121 },
		{ 4 , 2 , 13 , 0.134 },
		{ 8 , 1 , 13 , 0.131 },
		{ 1 , 9 , 12 , 0.142 },
		{ 4 , 3 , 9 , 0.145 },
		{ 4 , 9 , 3 , 0.188 },
		{ 2 , 4 , 13 , 0.145 },
		{ 1 , 10 , 11 , 0.128 },
		{ 1 , 12 , 9 , 0.126 },
		{ 2 , 11 , 5 , 0.146 },
		{ 8 , 13 , 1 , 0.138 },
		{ 1 , 11 , 10 , 0.13 },
		{ 2 , 5 , 11 , 0.128 },
		{ 1 , 8 , 14 , 0.142 },
		{ 2 , 4 , 14 , 0.127 },
		{ 2 , 14 , 4 , 0.131 },
		{ 1 , 14 , 8 , 0.153 },
		{ 2 , 6 , 9 , 0.129 },
		{ 2 , 8 , 7 , 0.147 },
		{ 2 , 9 , 6 , 0.14 },
		{ 4 , 4 , 7 , 0.136 },
		{ 8 , 7 , 2 , 0.138 },
		{ 8 , 2 , 7 , 0.163 },
		{ 2 , 7 , 8 , 0.137 },
		{ 8 , 1 , 14 , 0.138 },
		{ 4 , 7 , 4 , 0.136 },
		{ 4 , 14 , 2 , 0.138 },
		{ 16 , 1 , 7 , 0.158 },
		{ 1 , 9 , 13 , 0.142 },
		{ 4 , 2 , 14 , 0.133 },
		{ 1 , 13 , 9 , 0.14 },
		{ 4 , 10 , 3 , 0.141 },
		{ 1 , 8 , 15 , 0.147 },
		{ 2 , 15 , 4 , 0.148 },
		{ 1 , 10 , 12 , 0.138 },
		{ 2 , 5 , 12 , 0.141 },
		{ 2 , 10 , 6 , 0.142 },
		{ 4 , 6 , 5 , 0.134 },
		{ 8 , 14 , 1 , 0.14 },
		{ 1 , 12 , 10 , 0.135 },
		{ 1 , 15 , 8 , 0.14 },
		{ 2 , 12 , 5 , 0.144 },
		{ 2 , 6 , 10 , 0.145 },
		{ 1 , 11 , 11 , 0.141 },
		{ 16 , 7 , 1 , 0.131 },
		{ 2 , 4 , 15 , 0.143 },
		{ 4 , 2 , 15 , 0.137 },
		{ 4 , 3 , 10 , 0.144 },
		{ 4 , 5 , 6 , 0.14 },
		{ 8 , 1 , 15 , 0.144 },
		{ 8 , 5 , 3 , 0.142 },
		{ 4 , 15 , 2 , 0.142 },
		{ 2 , 7 , 9 , 0.141 },
		{ 1 , 9 , 14 , 0.164 },
		{ 2 , 9 , 7 , 0.175 },
		{ 1 , 14 , 9 , 0.165 },
		{ 2 , 8 , 8 , 0.181 },
		{ 2 , 13 , 5 , 0.148 },
		{ 4 , 4 , 8 , 0.168 },
		{ 8 , 4 , 4 , 0.155 },
		{ 1 , 10 , 13 , 0.142 },
		{ 1 , 13 , 10 , 0.144 },
		{ 2 , 5 , 13 , 0.14 },
		{ 8 , 15 , 1 , 0.133 },
		{ 8 , 2 , 8 , 0.152 },
		{ 8 , 3 , 5 , 0.146 },
		{ 1 , 12 , 11 , 0.144 },
		{ 2 , 11 , 6 , 0.157 },
		{ 4 , 8 , 4 , 0.141 },
		{ 4 , 3 , 11 , 0.154 },
		{ 8 , 8 , 2 , 0.142 },
		{ 16 , 4 , 2 , 0.164 },
		{ 1 , 11 , 12 , 0.148 },
		{ 16 , 1 , 8 , 0.159 },
		{ 16 , 2 , 4 , 0.146 },
		{ 4 , 11 , 3 , 0.146 },
		{ 2 , 6 , 11 , 0.141 },
		{ 1 , 9 , 15 , 0.147 },
		{ 32 , 2 , 2 , 0.141 },
		{ 1 , 15 , 9 , 0.148 },
		{ 16 , 8 , 1 , 0.144 },
		{ 32 , 1 , 4 , 0.161 },
		{ 64 , 2 , 1 , 0.163 },
		{ 32 , 4 , 1 , 0.145 },
		{ 1 , 10 , 14 , 0.154 },
		{ 4 , 7 , 5 , 0.163 },
		{ 1 , 14 , 10 , 0.17 },
		{ 2 , 5 , 14 , 0.162 },
		{ 4 , 5 , 7 , 0.159 },
		{ 64 , 1 , 2 , 0.16 },
		{ 2 , 7 , 10 , 0.158 },
		{ 2 , 14 , 5 , 0.154 },
		{ 4 , 9 , 4 , 0.161 },
		{ 1 , 11 , 13 , 0.155 },
		{ 1 , 12 , 12 , 0.162 },
		{ 2 , 8 , 9 , 0.155 },
		{ 2 , 10 , 7 , 0.153 },
		{ 4 , 4 , 9 , 0.166 },
		{ 2 , 6 , 12 , 0.157 },
		{ 2 , 12 , 6 , 0.167 },
		{ 4 , 12 , 3 , 0.165 },
		{ 2 , 9 , 8 , 0.166 },
		{ 1 , 13 , 11 , 0.159 },
		{ 4 , 3 , 12 , 0.171 }

   };



static inline uint32_t be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
	    ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static inline void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}

static inline uint32_t le32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
	    ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void le32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
}


static inline uint64_t
le64dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;

	return ((uint64_t)(p[0]) + ((uint64_t)(p[1]) << 8) +
	    ((uint64_t)(p[2]) << 16) + ((uint64_t)(p[3]) << 24) +
	    ((uint64_t)(p[4]) << 32) + ((uint64_t)(p[5]) << 40) +
	    ((uint64_t)(p[6]) << 48) + ((uint64_t)(p[7]) << 56));
}

static inline void
le64enc(void *pp, uint64_t x)
{
	uint8_t * p = (uint8_t *)pp;

	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
	p[4] = (x >> 32) & 0xff;
	p[5] = (x >> 40) & 0xff;
	p[6] = (x >> 48) & 0xff;
	p[7] = (x >> 56) & 0xff;
}


typedef struct HMAC_SHA256Context {
	SHA256_CTX ictx;
	SHA256_CTX octx;
} HMAC_SHA256_CTX;

/* Initialize an HMAC-SHA256 operation with the given key. */
static void
HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *_K, size_t Klen)
{
	unsigned char pad[64];
	unsigned char khash[32];
	const unsigned char *K = (const unsigned char *)_K;
	size_t i;

	/* If Klen > 64, the key is really SHA256(K). */
	if (Klen > 64) {
		SHA256_Init(&ctx->ictx);
		SHA256_Update(&ctx->ictx, K, Klen);
		SHA256_Final(khash, &ctx->ictx);
		K = khash;
		Klen = 32;
	}

	/* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
	SHA256_Init(&ctx->ictx);
	memset(pad, 0x36, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	SHA256_Update(&ctx->ictx, pad, 64);

	/* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
	SHA256_Init(&ctx->octx);
	memset(pad, 0x5c, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	SHA256_Update(&ctx->octx, pad, 64);

	/* Clean the stack. */
	memset(khash, 0, 32);
}

/* Add bytes to the HMAC-SHA256 operation. */
static void
HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *in, size_t len)
{
	/* Feed data to the inner SHA256 operation. */
	SHA256_Update(&ctx->ictx, in, len);
}

/* Finish an HMAC-SHA256 operation. */
static void
HMAC_SHA256_Final(unsigned char digest[32], HMAC_SHA256_CTX *ctx)
{
	unsigned char ihash[32];

	/* Finish the inner SHA256 operation. */
	SHA256_Final(ihash, &ctx->ictx);

	/* Feed the inner hash to the outer SHA256 operation. */
	SHA256_Update(&ctx->octx, ihash, 32);

	/* Finish the outer SHA256 operation. */
	SHA256_Final(digest, &ctx->octx);

	/* Clean the stack. */
	memset(ihash, 0, 32);
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
static void
PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen, const uint8_t *salt,
    size_t saltlen, uint64_t c, uint8_t *buf, size_t dkLen)
{
	HMAC_SHA256_CTX PShctx, hctx;
	size_t i;
	uint8_t ivec[4];
	uint8_t U[32];
	uint8_t T[32];
	uint64_t j;
	int k;
	size_t clen;

	/* Compute HMAC state after processing P and S. */
	HMAC_SHA256_Init(&PShctx, passwd, passwdlen);
	HMAC_SHA256_Update(&PShctx, salt, saltlen);

	/* Iterate through the blocks. */
	for (i = 0; i * 32 < dkLen; i++) {
		/* Generate INT(i + 1). */
		be32enc(ivec, (uint32_t)(i + 1));

		/* Compute U_1 = PRF(P, S || INT(i)). */
		memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
		HMAC_SHA256_Update(&hctx, ivec, 4);
		HMAC_SHA256_Final(U, &hctx);

		/* T_i = U_1 ... */
		memcpy(T, U, 32);

		for (j = 2; j <= c; j++) {
			/* Compute U_j. */
			HMAC_SHA256_Init(&hctx, passwd, passwdlen);
			HMAC_SHA256_Update(&hctx, U, 32);
			HMAC_SHA256_Final(U, &hctx);

			/* ... xor U_j ... */
			for (k = 0; k < 32; k++)
				T[k] ^= U[k];
		}

		/* Copy as many bytes as necessary into buf. */
		clen = dkLen - i * 32;
		if (clen > 32)
			clen = 32;
		memcpy(&buf[i * 32], T, clen);
	}

	/* Clean PShctx, since we never called _Final on it. */
	memset(&PShctx, 0, sizeof(HMAC_SHA256_CTX));
}


#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
		/* Operate on columns. */
		x04 ^= ROTL(x00 + x12,  7);  x09 ^= ROTL(x05 + x01,  7);
		x14 ^= ROTL(x10 + x06,  7);  x03 ^= ROTL(x15 + x11,  7);

		x08 ^= ROTL(x04 + x00,  9);  x13 ^= ROTL(x09 + x05,  9);
		x02 ^= ROTL(x14 + x10,  9);  x07 ^= ROTL(x03 + x15,  9);

		x12 ^= ROTL(x08 + x04, 13);  x01 ^= ROTL(x13 + x09, 13);
		x06 ^= ROTL(x02 + x14, 13);  x11 ^= ROTL(x07 + x03, 13);

		x00 ^= ROTL(x12 + x08, 18);  x05 ^= ROTL(x01 + x13, 18);
		x10 ^= ROTL(x06 + x02, 18);  x15 ^= ROTL(x11 + x07, 18);

		/* Operate on rows. */
		x01 ^= ROTL(x00 + x03,  7);  x06 ^= ROTL(x05 + x04,  7);
		x11 ^= ROTL(x10 + x09,  7);  x12 ^= ROTL(x15 + x14,  7);

		x02 ^= ROTL(x01 + x00,  9);  x07 ^= ROTL(x06 + x05,  9);
		x08 ^= ROTL(x11 + x10,  9);  x13 ^= ROTL(x12 + x15,  9);

		x03 ^= ROTL(x02 + x01, 13);  x04 ^= ROTL(x07 + x06, 13);
		x09 ^= ROTL(x08 + x11, 13);  x14 ^= ROTL(x13 + x12, 13);

		x00 ^= ROTL(x03 + x02, 18);  x05 ^= ROTL(x04 + x07, 18);
		x10 ^= ROTL(x09 + x08, 18);  x15 ^= ROTL(x14 + x13, 18);
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

void scrypt_1024_1_1_256_sp(const char *input, char *output, char *scratchpad)
{
	uint8_t B[128];
	uint32_t X[32];
	uint32_t *V;
	uint32_t i, j, k;

	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	PBKDF2_SHA256((const uint8_t *)input, 80, (const uint8_t *)input, 80, 1, B, 128);

	for (k = 0; k < 32; k++)
		X[k] = le32dec(&B[4 * k]);

	for (i = 0; i < 1024; i++) {
		memcpy(&V[i * 32], X, 128);
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
	for (i = 0; i < 1024; i++) {
		j = 32 * (X[16] & 1023);
		for (k = 0; k < 32; k++)
			X[k] ^= V[j + k];
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}

	for (k = 0; k < 32; k++)
		le32enc(&B[4 * k], X[k]);

	PBKDF2_SHA256((const uint8_t *)input, 80, B, 128, 1, (uint8_t *)output, 32);
}

void scrypt_1024_1_1_256(const char *input, char *output)
{
	char scratchpad[SCRYPT_SCRATCHPAD_SIZE];
	scrypt_1024_1_1_256_sp(input, output, scratchpad);
}

//////

static unsigned int cachedNBits;
static char cachedInput[80];
static char cachedOutput[32];

#define DEBUG_POWALGO 0

/*
void hybridScryptHash256Test() {

	for (int nSize = 0; nSize <= 255; nSize++) {
		int pos = 271 - 1 - nSize;

		int multiplier = dataFinal[pos][0];
		int rParam = dataFinal[pos][1];
		int pParam = dataFinal[pos][2];

		uint8_t H68[68];
		uint8_t S68[80];

		printf("%i - %i %i %i\n", nSize, multiplier, rParam, pParam);

		// S68 = scrypt (H68, H68, ...., 68) (len=68)
		crypto_scrypt(H68, 68, H68, 68,
				1024 * multiplier, rParam, pParam, &S68[0], 68);

	}


}
*/

void hybridScryptHash256(const char *input, char *output, unsigned int nBits) {

	if (cachedNBits == nBits && !memcmp(input, cachedInput, 80 * sizeof(char))) {
		if (DEBUG_POWALGO) {
			printf("hybridScryptHash256: cached result returned!\n");
		}

		memcpy(output, cachedOutput, 32 * sizeof(char));

		return;
	}

	cachedNBits = nBits;
	memcpy(cachedInput, input, 80 * sizeof(char));

	//

	int nSize = nBits >> 24;

	int pos = /*sizeof(dataFinal)*/ 271 - 1 - nSize;

	int multiplier = dataFinal[pos][0];
	int rParam = dataFinal[pos][1];
	int pParam = dataFinal[pos][2];

	if (DEBUG_POWALGO) {
		printf("multiplier: %i, rParam: %i, pParam: %i\nsize: %i", multiplier, rParam, pParam, nSize);
	}

	//uint256 hashTarget = CBigNum().SetCompact(/*pblock->*/nBits).getuint256();

	// H68=header[0..68] (len=68)

	// get first 68 bytes of array, out of 80
	uint8_t * H68 = (uint8_t *) input;

	if (DEBUG_POWALGO) {
		printf("H68: ");
		for (int i = 0; i < 80; i++) {
			printf("%2x ", (unsigned) H68[i] & 0xFF);
		}
		printf("\n");
	}

	uint8_t S68[80];

	// S68 = scrypt (H68, H68, ...., 68) (len=68)
	crypto_scrypt(H68, 68, H68, 68,
			1024 * multiplier, rParam, pParam, &S68[0], 68);

	if (DEBUG_POWALGO) {
		printf("scrypt(1): ");
		for (int i = 0; i < sizeof(S68); i++) {
			printf("%2x ", (unsigned) S68[i] & 0xFF);
		}
		printf("\n");
	}

	// S68 = xor(H68, S68)
	blkxor(&S68[0], &H68[0], 68);

	memcpy(&S68[68],&H68[68], 12 * sizeof(char));

	if (DEBUG_POWALGO) {
		printf("xor: ");
		for (int i = 0; i < sizeof(S68); i++) {
			printf("%2x ", (unsigned) S68[i] & 0xFF);
		}
		printf("\n");
	}

	// S68nonce = S68

	// s256 = hash256(s68nonce)
	uint256 s256 = Hash(S68, &S68[80]);
			//Hash(BEGIN(S76[0]),END(S76[79]));

	if (DEBUG_POWALGO) {
		printf("Hash256: ");
		//printf("%s\n",s256.GetHex().c_str());

		for (int i = 0; i < 32; i++) {
			printf("%2x ", (unsigned) (s256.begin()[i]) & 0xFF);
		}
		printf("\n");
	}


	uint256 mask;

	int topmostZeroBits = s256.countTopmostZeroBits(mask);

	if (DEBUG_POWALGO) {
		printf("topmostZeroBits: %i\n", topmostZeroBits);

		printf("mask: ");
		//printf("%s\n",s256.GetHex().c_str());

		for (int i = 0; i < 32; i++) {
			printf("%2x ", (unsigned) (mask.begin()[i]) & 0xFF);
		}
		printf("\n");
	}


	// byte [] sc256 = SCrypt.scryptJ(s256, s256, ....,  32);
	uint8_t sc256[32];

	crypto_scrypt((uint8_t * ) s256.begin(), 32, (uint8_t * ) s256.begin(), 32,
			1024 * multiplier, rParam, pParam, &sc256[0], 32);

	if (DEBUG_POWALGO) {
		printf("scrypt(2): ");
		for (int i = 0; i < sizeof(sc256); i++) {
			printf("%2x ", (unsigned) sc256[i] & 0xFF);
		}
		printf("\n");
	}


	// prepare mask

	// byte [] maskedSc256 = and(sc256, mask)
	uint8_t maskedSc256[32];

	for (size_t i = 0; i < 32; i++)
		maskedSc256[i] = sc256[i] & mask.begin()[i];

	if (DEBUG_POWALGO) {
		printf("maskedSc256: ");
		for (int i = 0; i < sizeof(maskedSc256); i++) {
			printf("%2x ", (unsigned) maskedSc256[i] & 0xFF);
		}
		printf("\n");
	}

	// byte [] finalHash = xor(s256, maskedSc256 )
	for (size_t i = 0; i < 32; i++)
		output[i] = s256.begin()[i] ^ maskedSc256[i];

	if (DEBUG_POWALGO) {
		printf("hash: %s\n", ((uint256 * ) output)->GetHex().c_str());
	}

	memcpy(cachedOutput , output , 32 * sizeof(char));
}

//////////////////////////////////////////////////////////////////////




static void
blkcpy(uint8_t * dest, uint8_t * src, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dest[i] = src[i];
}

static void
blkxor(uint8_t * dest, uint8_t * src, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dest[i] ^= src[i];
}

/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
static void
salsa20_8(uint8_t B[64])
{
	uint32_t B32[16];
	uint32_t x[16];
	size_t i;

	/* Convert little-endian values in. */
	for (i = 0; i < 16; i++)
		B32[i] = le32dec(&B[i * 4]);

	/* Compute x = doubleround^4(B32). */
	for (i = 0; i < 16; i++)
		x[i] = B32[i];
	for (i = 0; i < 8; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
		x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);

		x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
		x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);

		x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
		x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);

		x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
		x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);

		/* Operate on rows. */
		x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
		x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);

		x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
		x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);

		x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
		x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);

		x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
		x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
#undef R
	}

	/* Compute B32 = B32 + x. */
	for (i = 0; i < 16; i++)
		B32[i] += x[i];

	/* Convert little-endian values out. */
	for (i = 0; i < 16; i++)
		le32enc(&B[4 * i], B32[i]);
}

/**
 * blockmix_salsa8(B, Y, r):
 * Compute B = BlockMix_{salsa20/8, r}(B).  The input B must be 128r bytes in
 * length; the temporary space Y must also be the same size.
 */
static void
blockmix_salsa8(uint8_t * B, uint8_t * Y, size_t r)
{
	uint8_t X[64];
	size_t i;

	/* 1: X <-- B_{2r - 1} */
	blkcpy(X, &B[(2 * r - 1) * 64], 64);

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < 2 * r; i++) {
		/* 3: X <-- H(X \xor B_i) */
		blkxor(X, &B[i * 64], 64);
		salsa20_8(X);

		/* 4: Y_i <-- X */
		blkcpy(&Y[i * 64], X, 64);
	}

	/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
	for (i = 0; i < r; i++)
		blkcpy(&B[i * 64], &Y[(i * 2) * 64], 64);
	for (i = 0; i < r; i++)
		blkcpy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
}

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static uint64_t
integerify(uint8_t * B, size_t r)
{
	uint8_t * X = &B[(2 * r - 1) * 64];

	return (le64dec(X));
}

/**
 * smix(B, r, N, V, XY):
 * Compute B = SMix_r(B, N).  The input B must be 128r bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  The value N must be a power of 2.
 */
static void
smix(uint8_t * B, size_t r, uint64_t N, uint8_t * V, uint8_t * XY)
{
	uint8_t * X = XY;
	uint8_t * Y = &XY[128 * r];
	uint64_t i;
	uint64_t j;

	/* 1: X <-- B */
	blkcpy(X, B, 128 * r);

	/* 2: for i = 0 to N - 1 do */
	for (i = 0; i < N; i++) {
		/* 3: V_i <-- X */
		blkcpy(&V[i * (128 * r)], X, 128 * r);

		/* 4: X <-- H(X) */
		blockmix_salsa8(X, Y, r);
	}

	/* 6: for i = 0 to N - 1 do */
	for (i = 0; i < N; i++) {
		/* 7: j <-- Integerify(X) mod N */
		j = integerify(X, r) & (N - 1);

		/* 8: X <-- H(X \xor V_j) */
		blkxor(X, &V[j * (128 * r)], 128 * r);
		blockmix_salsa8(X, Y, r);
	}

	/* 10: B' <-- X */
	blkcpy(B, X, 128 * r);
}

/**
 * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2.
 *
 * Return 0 on success; or -1 on error.
 */
int
crypto_scrypt(const uint8_t * passwd, size_t passwdlen,
    const uint8_t * salt, size_t saltlen, uint64_t N, uint32_t r, uint32_t p,
    uint8_t * buf, size_t buflen)
{
	uint8_t * B;
	uint8_t * V;
	uint8_t * XY;
	uint32_t i;

	/* Sanity-check parameters. */
#if SIZE_MAX > UINT32_MAX
	if (buflen > (((uint64_t)(1) << 32) - 1) * 32) {
		errno = EFBIG;
		goto err0;
	}
#endif
	if ((uint64_t)(r) * (uint64_t)(p) >= (1 << 30)) {
		errno = EFBIG;
		goto err0;
	}
	if (((N & (N - 1)) != 0) || (N == 0)) {
		errno = EINVAL;
		goto err0;
	}
	if ((r > SIZE_MAX / 128 / p) ||
#if SIZE_MAX / 256 <= UINT32_MAX
	    (r > SIZE_MAX / 256) ||
#endif
	    (N > SIZE_MAX / 128 / r)) {
		errno = ENOMEM;
		goto err0;
	}

	/* Allocate memory. */
	if ((B = (uint8_t *) malloc(128 * r * p)) == NULL)
		goto err0;
	if ((XY = (uint8_t *) malloc(256 * r)) == NULL)
		goto err1;
	if ((V = (uint8_t *) malloc(128 * r * N)) == NULL)
		goto err2;

	/* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
	PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, 1, B, p * 128 * r);

	/* 2: for i = 0 to p - 1 do */
	for (i = 0; i < p; i++) {
		/* 3: B_i <-- MF(B_i, N) */
		smix(&B[i * 128 * r], r, N, V, XY);
	}

	/* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
	PBKDF2_SHA256(passwd, passwdlen, B, p * 128 * r, 1, buf, buflen);

	/* Free memory. */
	free(V);
	free(XY);
	free(B);

	/* Success! */
	return (0);

err2:
	free(XY);
err1:
	free(B);
err0:
	/* Failure! */
	return (-1);
}





