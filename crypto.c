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

#include "crypto.h"
#include "errors.h"

#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdint.h>

int generate_prf_key(byte* dst, uint32_t dstlen) {
  if (dstlen != PRF_KEY_BYTES) {
    return ERROR_PRF_KEYLEN_INVALID;
  }

  FILE* f = fopen("/dev/urandom", "r");
  if (f == NULL) {
    return ERROR_RANDOMNESS;
  }

  int bytes_read = fread(dst, 1, PRF_KEY_BYTES, f);
  if (bytes_read != PRF_KEY_BYTES) {
    return ERROR_RANDOMNESS;
  }

  fclose(f);

  return ERROR_NONE;
}

int prf_eval(byte* dst, uint32_t dstlen, byte* key, uint32_t keylen, byte* src,
    uint32_t srclen) {
  if (dstlen != PRF_OUTPUT_BYTES) {
    return ERROR_DSTLEN_INVALID;
  }

  if (keylen != PRF_KEY_BYTES) {
    return ERROR_PRF_KEYLEN_INVALID;
  }

  uint32_t outlen;
  HMAC(EVP_sha256(), key, keylen, src, srclen, dst, &outlen);
  assert(outlen == dstlen);

  return ERROR_NONE;
}

