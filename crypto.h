/**
 * Copyright (c) 2016, David J. Wu, Kevin Lewi
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "errors.h"
#include "flags.h"

#include <openssl/evp.h>
#include <stdint.h>

#ifdef USE_AES
#include "aes.h"
#endif

typedef unsigned char byte;

// Structure representing a PRF key and output size of PRF.
#ifdef USE_AES

typedef struct {
  AES_KEY key;
} prf_key[1];

static const int PRF_INPUT_BYTES  = 16;
static const int PRF_OUTPUT_BYTES = 16;

#else

typedef struct {
  byte keybuf[32];
} prf_key[1];

static const int PRF_OUTPUT_BYTES = 32;

#endif

/**
 * Reads from /dev/urandom to sample a PRF key.
 *
 * @param key The PRF key to construct
 *
 * @return ERROR_NONE on success and ERROR_RANDOMNESS if reading
 * from /dev/urandom failed.
 */
int generate_prf_key(prf_key key);

/**
 * Evaluates the PRF given a key and input (as byte arrays), storing
 * the result in a destination byte array.
 *
 * @param dst    The destination byte array that will contain the output of the PRF
 * @param dstlen The size of the destination byte array
 * @param key    The PRF key
 * @param src    The byte array containing the input to the PRF
 * @param srclen The size of the input byte array
 *
 * @return ERROR_NONE on success, ERROR_DSTLEN_INVALID if the destination size
 *         is invalid
 */
int prf_eval(byte* dst, uint32_t dstlen, prf_key key, byte* src, uint32_t srclen);

#endif /* __CRYPTO_H__ */

