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

#ifndef ecdh_cipher_ctx_h
#define ecdh_cipher_ctx_h

#include "crypto_engine.h"

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 
 @ingroup wickr_ecdh_cipher_ctx
 
 @struct wickr_ecdh_cipher_ctx
 
 @brief A cipher context designed to modularize the ECDH_HKDF_AES256 workflow
 
 @var wickr_ecdh_cipher_ctx::engine
 the crypto engine that will supply the ECDH, KDF, and cipher operations
 @var wickr_ecdh_cipher_ctx::local_key
 the private ec key that will be used for the ECDH operation
 @var wickr_ecdh_cipher_ctx::cipher
 the cipher key type that the kdf output will be casted into
 */
    
struct wickr_ecdh_cipher_ctx {
    wickr_crypto_engine_t engine;
    wickr_ec_key_t *local_key;
    wickr_cipher_t cipher;
};

typedef struct wickr_ecdh_cipher_ctx wickr_ecdh_cipher_ctx_t;

/**
 Create an ECDH Cipher Context with a random ec key.
 This function will generate a random Elliptic Curve key pair and then call 'wickr_ecdh_cipher_ctx_create_key'

 @param engine see property declaration of 'wickr_ecdh_cipher_ctx'
 @param curve the curve type of the local key pair that will be randomly generated for this context
 @param cipher see property declaration of 'wickr_ecdh_cipher_ctx'
 @return a newly allocated ecdh cipher context with a random local key
 */
wickr_ecdh_cipher_ctx_t *wickr_ecdh_cipher_ctx_create(wickr_crypto_engine_t engine,
                                                      wickr_ec_curve_t curve,
                                                      wickr_cipher_t cipher);

/**
 Create an ECDH Cipher Context with it's components

 @param engine see property declaration of 'wickr_ecdh_cipher_ctx'
 @param key see property declaration of 'wickr_ecdh_cipher_ctx'
 @param cipher see property declaration of 'wickr_ecdh_cipher_ctx'
 @return a newly allocated ecdh cipher context owning the properties passed in
 */
wickr_ecdh_cipher_ctx_t *wickr_ecdh_cipher_ctx_create_key(wickr_crypto_engine_t engine,
                                                          wickr_ec_key_t *key,
                                                          wickr_cipher_t cipher);

/**
 Copy an ECDH Cipher Context

 @param ctx the source context to copy
 @return a newly allocated context set containing deep copies of the properties of 'ctx'
 */
wickr_ecdh_cipher_ctx_t *wickr_ecdh_cipher_ctx_copy(const wickr_ecdh_cipher_ctx_t *ctx);

/**
 Destroy an ECDH Cipher Context

 @param ctx a pointer to a an ecdh cipher context to destroy. Properties of '*ctx' will also be destroyed
 */
void wickr_ecdh_cipher_ctx_destroy(wickr_ecdh_cipher_ctx_t **ctx);

/**
 Cipher data using the ECDH cipher context
 The cipher operation works as follows:
     1. ECDH is performed with the public and private components of 'ctx->local_key' and the public component
        of 'remote_pub' to create shared_secret
     2. shared_secret is used as input to the kdf function defined by 'kdf_params'. Currently only HKDF is supported
        as a kdf algorithm. Info and Salt parameters can be passed to HKDF via the 'wickr_kdf_meta' properties.
     3. the kdf output is casted into a 'wickr_cipher_key' with cipher type 'ctx->cipher'
     4. the resulting cipher key is used to encrypt 'plaintext', and the result is returned

 @param ctx the ecdh cipher context to use to perform the cipher operation
 @param plaintext the input data to cipher
 @param remote_pub the remote public key to use for the ECDH portion of the operation
 @param kdf_params the kdf parameters to use for the KDF portion of the operation
 @return ciphertext created from the ecdh-kdf-cipher workflow
 */
wickr_cipher_result_t *wickr_ecdh_cipher_ctx_cipher(const wickr_ecdh_cipher_ctx_t *ctx,
                                                    const wickr_buffer_t *plaintext,
                                                    const wickr_ec_key_t *remote_pub,
                                                    const wickr_kdf_meta_t *kdf_params);

/**
 Decipher data using the ECDH cipher context
 The decipher operation works the same way as the cipher operation, except the cipher key is used for a decrypt
 operation using 'ciphertext' as input. See 'wickr_ecdh_cipher_ctx_cipher' for more info

 @param ctx the ecdh cipher context to use to perform the decipher operation
 @param ciphertext data that was encrypted using 'wickr_ecdh_cipher_ctx_cipher'
 @param remote_pub the remote public key to use for the ECDH portion of the operation
 @param kdf_params the kdf parameters to use for the KDF portion of the operation
 @return plaintext decoded by the ecdh-kdf-decipher workflow
 */
wickr_buffer_t *wickr_ecdh_cipher_ctx_decipher(const wickr_ecdh_cipher_ctx_t *ctx,
                                               const wickr_cipher_result_t *ciphertext,
                                               const wickr_ec_key_t *remote_pub,
                                               const wickr_kdf_meta_t *kdf_params);
    
    
    
#ifdef __cplusplus
}
#endif

#endif /* ecdh_cipher_ctx_h */
