/*
 * Copyright © 2012-2020 Wickr Inc.  All rights reserved.
 *
 * This code is being released for EDUCATIONAL, ACADEMIC, AND CODE REVIEW PURPOSES
 * ONLY.  COMMERCIAL USE OF THE CODE IS EXPRESSLY PROHIBITED.  For additional details,
 * please see LICENSE
 *
 * THE CODE IS MADE AVAILABLE "AS-IS" AND WITHOUT ANY EXPRESS OR
 * IMPLIED GUARANTEES AS TO FITNESS, MERCHANTABILITY, NON-
 * INFRINGEMENT OR OTHERWISE. IT IS NOT BEING PROVIDED IN TRADE BUT ON
 * A VOLUNTARY BASIS ON BEHALF OF THE AUTHOR’S PART FOR THE BENEFIT
 * OF THE LICENSEE AND IS NOT MADE AVAILABLE FOR CONSUMER USE OR ANY
 * OTHER USE OUTSIDE THE TERMS OF THIS LICENSE. ANYONE ACCESSING THE
 * CODE SHOULD HAVE THE REQUISITE EXPERTISE TO SECURE THEIR SYSTEM
 * AND DEVICES AND TO ACCESS AND USE THE CODE FOR REVIEW PURPOSES
 * ONLY. LICENSEE BEARS THE RISK OF ACCESSING AND USING THE CODE. IN
 * PARTICULAR, AUTHOR BEARS NO LIABILITY FOR ANY INTERFERENCE WITH OR
 * ADVERSE EFFECT THAT MAY OCCUR AS A RESULT OF THE LICENSEE
 * ACCESSING AND/OR USING THE CODE ON LICENSEE’S SYSTEM.
 */

#ifndef openssl_suite_h
#define openssl_suite_h

#include <stdlib.h>
#include <stdio.h>
#include "buffer.h"
#include "cipher.h"
#include "crypto_engine.h"
#include "ecdsa.h"
#include "eckey.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup openssl_crypto OpenSSL Crypto Engine **/

/**
 @ingroup openssl_crypto

 Generate secure random bytes using the rand_bytes function from OpenSSL
 
 @param len the number of bytes to generate
 @return a buffer containing 'len' secure random bytes or NULL if random byte generation fails
 */
wickr_buffer_t *openssl_crypto_random(size_t len);

/**
 @ingroup openssl_crypto

 Generate a secure random cipher key for a particular cipher
 Currently supports AES256-GCM and AES256-CTR cipher modes
 
 @param cipher the cipher to generate a random key for
 @return a cipher key containing key material generated by 'openssl_crypto_random' or NULL if random byte generation fails
 */
wickr_cipher_key_t *openssl_cipher_key_random(wickr_cipher_t cipher);

/**
 @ingroup openssl_crypto
 
 Encrypt a buffer using AES256
 Currently supports AES256-GCM and AES256-CTR cipher modes
 
 NOTE: IV is randomly chosen using 'openssl_crypto_random' if one is not provided

 @param plaintext the content to encrypt using 'key'
 @param aad additional data to authenticate with the ciphertext (only works with authenticated ciphers)
 @param key the cipher key to use to encrypt 'plaintext'
 @param iv an initialization vector to use with the cipher mode, or NULL if one should be chosen at random
 @return a cipher result containing encrypted bytes, or NULL if the cipher mode fails or is not supported
 */
wickr_cipher_result_t *openssl_aes256_encrypt(const wickr_buffer_t *plaintext,
                                              const wickr_buffer_t *aad,
                                              const wickr_cipher_key_t *key,
                                              const wickr_buffer_t *iv);

/**
 @ingroup openssl_crypto
 
 Decrypt a cipher_result using AES256
 Currently supports AES256-GCM and AES256-CTR cipher modes
 
 @param cipher_result a cipher result generated from 'openssl_aes256_encrypt'
 @param aad additional data to authenticate with the ciphertext (only works with authenticated ciphers)
 @param key the key to use to attempt to decrypt 'cipher_result'
 @param only_auth_ciphers if true, only authenticated ciphers may be used for decryption
 @return a buffer containing decrypted bytes. If the AES mode is authenticated, NULL will be returned if key is incorrect.
 */
wickr_buffer_t *openssl_aes256_decrypt(const wickr_cipher_result_t *cipher_result,
                                       const wickr_buffer_t *aad,
                                       const wickr_cipher_key_t *key,
                                       bool only_auth_ciphers);

/**
 @ingroup openssl_crypto
 
 Calculate a SHA2 hash of a buffer using an optional salt value
 Supported modes of SHA2 are SHA256, SHA384 and SHA512
 
 @param buffer the buffer to hash
 @param salt a salt value to concatenate to buffer before taking the hash. The input to the SHA2 function will be SHA2(buffer || salt)
 Passing NULL will allow for no salt to be used
 @param mode the mode of SHA2 to use for hashing
 @return a buffer containing the derived hash or NULL if the hashing operation fails
 */
wickr_buffer_t *openssl_sha2(const wickr_buffer_t *buffer,
                             const wickr_buffer_t *salt,
                             wickr_digest_t mode);

/**
 @ingroup openssl_crypto
 
 Generate a random Elliptic Curve keypair
 Supported curve is currently limited to NIST P521

 @param curve the curve parameters to use for random key pair generation
 @return a random Elliptic Curve key pair or NULL if the random generation fails
 */
wickr_ec_key_t *openssl_ec_rand_key(wickr_ec_curve_t curve);

/**
 @ingroup openssl_crypto
 
 Import an Elliptic Curve key from a buffer

 @param buffer the buffer representing Elliptic Curve key material
 @param is_private false if the buffer represents a public key
 @return an Elliptic Curve key pair parsed from buffer or NULL if buffer does not contain a valid key, or is_private is incorrectly set
 */
wickr_ec_key_t *openssl_ec_key_import(const wickr_buffer_t *buffer, bool is_private);

/**
 @ingroup openssl_crypto
 
 Sign data using an Elliptic Curve key
 Data is hashed before signing. This function will calculate ECDSA(SHA2(data_to_sign))

 @param ec_signing_key private signing key to use for the ECDSA algorithm
 @param data_to_sign the data to hash with 'digest_mode', and then sign with 'ec_signing_key'
 @param digest_mode the digest mode to use for SHA2
 @return an ecdsa result containing the output of ECDSA(SHA2(data_to_sign)) or NULL if the 'ec_signing_key' is not a private key
 */
wickr_ecdsa_result_t *openssl_ec_sign(const wickr_ec_key_t *ec_signing_key,
                                      const wickr_buffer_t *data_to_sign,
                                      wickr_digest_t digest_mode);

/**
 @ingroup openssl_crypto
 
 Verify ECDSA signatures

 @param signature a signature produced with 'openssl_ec_sign'
 @param ec_public_key the public signing key to use for verification
 @param data_to_verify the original data that should have been signed with 'ec_public_key'. It will be hashed inside this function as part of the verification process
 @return true if 'signature' can be verified by 'ec_public_key'
 */
bool openssl_ec_verify(const wickr_ecdsa_result_t *signature,
                       const wickr_ec_key_t *ec_public_key,
                       const wickr_buffer_t *data_to_verify);

wickr_buffer_t *openssl_ecdsa_to_raw(const wickr_ecdsa_result_t *input);

wickr_ecdsa_result_t *openssl_ecdsa_from_raw(const wickr_ec_curve_t curve, const wickr_digest_t digest, const wickr_buffer_t* input);

/**
 @ingroup openssl_crypto
 
 Generate a shared secret given Elliptic Curve Diffie-Hellman parameters

 @param local the local elliptic curve private key
 @param peer the remote elliptic curve public key
 @return a buffer containing the shared secret computed with 'local' private key and 'peer' public key
 */
wickr_buffer_t *openssl_gen_shared_secret(const wickr_ec_key_t *local, const wickr_ec_key_t *peer);


/**
 @ingroup openssl_crypto
 
 Generate an HMAC

 @param data the data to take the HMAC of
 @param hmac_key a key to use for HMAC
 @param mode the digest mode to perform HMAC with. This will determine the length of the output
 @return a buffer containing the HMAC of 'data' with 'hmac_key'
 */
wickr_buffer_t *openssl_hmac_create(const wickr_buffer_t *data,
                                    const wickr_buffer_t *hmac_key,
                                    wickr_digest_t mode);

/**
 @ingroup openssl_crypto
 
 Verify an HMAC against an expected result

 @param data the data to calculate the expected HMAC with
 @param hmac_key the key to use along with 'data' to create the expected HMAC with
 @param mode the mode to use for generating the expected HMAC
 @param expected the value to compare the generated HMAC with
 @return true if 'expected' is equal to the HMAC of 'data' and 'hmac_key'
 */
bool openssl_hmac_verify(const wickr_buffer_t *data,
                         const wickr_buffer_t *hmac_key,
                         wickr_digest_t mode,
                         const wickr_buffer_t *expected);

/**
 @ingroup openssl_crypto
 
 Derive a key with HMAC Key Derivation Function

 @param input_key_material the original key to extract and expand using HKDF
 @param salt a salt value to provide to HKDF, this should be randomly generated or NULL if no salt should be used
 @param info contextual information to pass to HKDF, this can be NULL if no contextual information should be used
 @param hash_mode the hash mode to use for the HKDF output, this will determine the length of the final output
 @return a buffer containing the calculated HKDF value
 */
wickr_buffer_t *openssl_hkdf(const wickr_buffer_t *input_key_material,
                             const wickr_buffer_t *salt,
                             const wickr_buffer_t *info,
                             wickr_digest_t hash_mode);

/**
 @ingroup openssl_crypto
 
 Derive a key with HMAC Key Derivation Function

 @param input_key_material the original key to extract and expand using HKDF
 @param info contextual information to pass to HKDF, this can be NULL if no contextual information should be used
 @param hash_mode the hash mode to use for the HKDF output, this will determine the length of the final output
 @param out_len the number of bytes the input should be expanded to
 @return a buffer containing the calculated HKDF value
 */
wickr_buffer_t *openssl_hkdf_expand(const wickr_buffer_t *input_key_material,
                                    const wickr_buffer_t *info,
                                    wickr_digest_t hash_mode,
                                    size_t out_len);

/**
 @ingroup openssl_crypto
 
 Calculate the SHA2 hash of a file

 @param in_file a file to take the hash of it's contents
 @param mode the mode to use for calculating the hash
 @return a buffer containing the output of the chosen SHA2 mode of the contents of in_file
 */
wickr_buffer_t *openssl_sha2_file(FILE *in_file, wickr_digest_t mode);

/**
 @ingroup openssl_crypto
 
 Encrypt a file with AES256

 @param in_file the file to encrypt
 @param key the key to use for AES256
 @param out_file a file that should contain the encrypted data
 @return true if encryption succeeds, and 'out_file' can be written
 */
bool openssl_encrypt_file(FILE *in_file, const wickr_cipher_key_t *key, FILE *out_file);

/**
 @ingroup openssl_crypto

 Decrypt a file with AES256
 
 Note: Unauthenticated modes will always succeed and the contents of 'out_file' may be incorrect
 For this reason it is useful to use an authenticated mode such as AES256 GCM when encrypting files
 
 @param in_file the encrypted file to decrypt
 @param key the key to use for decryption
 @param out_file the file to write the decrypted data from 'in_file'
 @param only_auth_ciphers if true, only authenticated ciphers may be used for decryption
 @return true if the decryption operation succeeds, and 'out_file' can be written
 
 */
bool openssl_decrypt_file(FILE *in_file,
                          const wickr_cipher_key_t *key,
                          FILE *out_file,
                          bool only_auth_ciphers);

/**
 @ingroup openssl_crypto

 Enable FIPS mode

 @return true if openssl fips enable is allowed
*/
bool openssl_enable_fips_mode(void);

/**
 @ingroup openssl_crypto

 Determine if FIPS mode is available

 @return true if openssl fips mode is available
*/
bool openssl_is_fips_supported();

/* Functions to assist with testing */
wickr_ec_key_t *openssl_ec_key_import_test_key(wickr_ec_curve_t curve, const char *priv_hex);

#ifdef __cplusplus
}
#endif

#endif /* openssl_suite_h */
