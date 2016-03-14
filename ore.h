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

#ifndef __ORE_H__
#define __ORE_H__

#include <stdbool.h>
#include "crypto.h"

// the public parameters for the encryption scheme, used to compare ciphertexts
typedef struct {
  bool initialized;   // whether or not these parameters have been initialized
  uint32_t nbits;     // the number of bits to represent a plaintext to encrypt
  uint32_t block_len; // the number of bits in each block passed to the PRF
} ore_params[1];

// the secret key for the encryption scheme, used to perform encryption
typedef struct {
  bool initialized;   // whether or not the secret key has been initialized
  byte         keybuf[PRF_KEY_BYTES];
  ore_params   params;
} ore_secret_key[1];

// the ciphertexts of the encryption scheme
typedef struct {
  bool initialized; // whether or not the ciphertext has been initialized
  byte*        buf;
  ore_params   params;
} ore_ciphertext[1];

/**
 * Initializes an ore_params type by setting its parameters, number of bits and
 * block length.
 *
 * @param nbits     The number of bits of an input to the encryption scheme
 * @param block_len The length (in bits) of each block to be encrypted by a PRF
 *
 * @return ERROR_NONE on success, ERROR_PARAMS_INVALID if the parameter settings
 *         are invalid.
 */
int init_ore_params(ore_params params, uint32_t nbits, uint32_t block_len);

/**
 * Initializes the secret key by sampling a PRF key and copying the public
 * parameters into the secret key.
 *
 * The params struct must have been initialized with a call to init_ore_params()
 * before calling this function.
 *
 * @param sk     The secret key to initialize
 * @param params The parameters, which must have already been initialized
 *
 * @return ERROR_NONE on success, and the corresponding error return code
 *         otherwise
 */
int ore_setup(ore_secret_key sk, ore_params params);

/**
 * Cleans up any memory used by the secret key.
 *
 * @param sk The secret key to clean up
 *
 * @return ERROR_NONE on success
 */
int ore_cleanup(ore_secret_key sk);

/**
 * Performs order revealing encryption on an input message.
 *
 * The secret key must be initialized (by a call to ore_setup) before calling
 * this function.
 *
 * The ciphertext must also be initialized (by a call to init_ore_ciphertext)
 * before calling this function.
 *
 * @param ctxt The ciphertext to store the encryption (which must have been
 *             initialized)
 * @param sk   The secret key (which must have been initialized)
 * @param msg  The input in a uint64_t
 *
 * @return ERROR_NONE on success
 */
int ore_encrypt_ui(ore_ciphertext ctxt, ore_secret_key sk, uint64_t msg);

/**
 * Performs the comparison of two ciphertexts to determine the ordering of their
 * underlying plaintexts.
 *
 * The two ciphertexts must have been initialized (by a call to
 * init_ore_ciphertext) before calling this function.
 *
 * @param result_p A pointer containing the result of the comparison, which is 1
 *                 if ctxt1 encrypts a plaintext greater than ctxt2, -1 if ctxt1
 *                 encrypts a plaintext less than ctxt2, and 0 if they encrypt
 *                 equal plaintexts.
 * @param ctxt1    The first ciphertext
 * @param ctxt2    The second ciphertext
 *
 * @return ERROR_NONE on success
 */
int ore_compare(int* result_p, ore_ciphertext ctxt1, ore_ciphertext ctxt2);

/**
 * Initializes a ciphertext with the parameters described by params.
 *
 * This function assumes that init_ore_params has been called on the parameters.
 *
 * @param ctxt   The ciphertext to initialize
 * @param params The parameters to initialize the ciphertext with
 *
 * @return ERROR_NONE on success
 */
int init_ore_ciphertext(ore_ciphertext ctxt, ore_params params);

/**
 * Clears a ciphertext
 *
 * @param ctxt The ciphertext to clear
 *
 * @return ERROR_NONE on success
 */
int clear_ore_ciphertext(ore_ciphertext ctxt);

#endif /* __ORE_H__ */
