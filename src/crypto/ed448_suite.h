/*
 * Copyright © 2012-2017 Wickr Inc.  All rights reserved.
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

#ifndef ed448_suite_h
#define ed448_suite_h

#include <stdlib.h>
#include <stdio.h>

#include "crypto_engine.h"
#include "buffer.h"
#include "ecdsa.h"
#include "eckey.h"
#include "ecdh.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup ed448_crypto ED448 library functions **/

/**
 @ingroup ed448_crypto

 Sign data using an Elliptic Curve key
 This function will calculate EdDSA with Ed448ph(data_to_sign) (see RFC 8032). On top of this rfc, the Decaf/Espresso EC-point encoding is used internally. 

 @param ec_signing_key private signing key to use for the EDDSA algorithm
 @param data_to_sign the data to sign with 'ec_signing_key'
 @param digest_mode the digest mode to use (expected SHAKE256)
 @return an ecdsa result containing the output of EDDSA_prehash(data_to_sign) or NULL in case of failure
 */
wickr_ecdsa_result_t *ed448_sig_sign(const wickr_ec_key_t *ec_signing_key,
                               const wickr_buffer_t *data_to_sign,
                               wickr_digest_t digest_mode);


/**
 @ingroup ed448_crypto
 
 Verify EdDSA signatures

 @param signature a signature produced with 'ed448_sig_sign'
 @param ec_public_key the public signing key to use for verification
 @param data_to_verify the original data that should have been signed with 'ec_public_key'.
 @return true if 'signature' can be verified by 'ec_public_key'
 */
bool ed448_sig_verify(const wickr_ecdsa_result_t *signature,
                      const wickr_ec_key_t *ec_public_key,
                      const wickr_buffer_t *data_to_verify);

/**
 @ingroup ed448_crypto
 
 Computes a public key (i.e. scalar multiple of a point on the ED448 elliptic curve) for a given private key for EdDSA signing.

 @param raw private key
 @return the corresponding raw public key
 */
wickr_buffer_t *ed448_sig_derive_public_key(const wickr_buffer_t *private_key_data);

/**
 @ingroup ed448_crypto
 
 Computes a public key (i.e. scalar multiple of a point on the ED448 elliptic curve) for a given private key for ECDH algorithm over ED-448 curve.

 @param raw private key
 @return the corresponding raw public key
 */
wickr_buffer_t *ed448_dh_derive_public_key(const wickr_buffer_t *private_key_data);

/**
 @ingroup ed448_crypto
 
 Generate a shared secret given Elliptic Curve Diffie-Hellman parameters.
 The curve used is ED-448.
 This function internally uses 'openssl_hkdf' to extract and expand the output of the ECDH function using 'params' for options

 @param params the parameters to use for the ECDH and HKDF algorithms
 @return a buffer containing the expanded shared secret or NULL if the key exchange cannot be computed
 */
wickr_buffer_t *ed448_dh_shared_secret(const wickr_ecdh_params_t *params);

/**
 @ingroup ed448_crypto
 
 Computes a SHAKE256 digest of the given data and of given output length.

 @param data the data to aply SHAKE256 to
 @param output_length Output length in bytes of the SHAKE256 output
 @return a buffer containing the digest or NULL if computation failed
 */
wickr_buffer_t *ed448_shake256_raw(const wickr_buffer_t *data, uint16_t output_length);

/**
 @ingroup ed448_crypto
 
 Computes a SHAKE256 digest of the given data with salt and context and of given output length. 
 The input to the SHAKE function will be SHAKE256(salt || info || data)

 @param data the data to aply SHAKE256 to
 @param salt a salt value to concatenate to buffer before taking the hash.
 Passing NULL will allow for no salt to be used
 @param info contextual information to pass to SHAKE256. Also can be NULL.
 @param output_length Output length in bytes of the SHAKE256 output
 @return a buffer containing the digest or NULL if computation failed
 */
wickr_buffer_t *ed448_shake256(const wickr_buffer_t *data, const wickr_buffer_t *salt,
                               const wickr_buffer_t *info, uint16_t output_length);

#ifdef __cplusplus
}
#endif

#endif /* ed448_suite_h */
