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

#include <decaf/ed448.h>

// TODO(michal): Check which includes we really need
#include "buffer.h"
#include "cipher.h"
#include "crypto_engine.h"
#include "ecdsa.h"
#include "eckey.h"
#include "ecdh.h"

#ifdef __cplusplus
extern "C" {
#endif


#define EDDSA_448_PRIVATE_KEY_LENGTH DECAF_EDDSA_448_PRIVATE_BYTES
#define EDDSA_448_PUBLIC_KEY_LENGTH DECAF_EDDSA_448_PUBLIC_BYTES
#define EDDSA_448_SIGNATURE_LENGTH DECAF_EDDSA_448_SIGNATURE_BYTES

#define DH_448_PUBLIC_KEY_LENGTH DECAF_X448_PUBLIC_BYTES
#define DH_448_PRIVATE_KEY_LENGTH DECAF_X448_PRIVATE_BYTES
#define DH_448_SHARED_SECRET_LENGTH DECAF_X448_PUBLIC_BYTES


wickr_buffer_t *ed448_sig_sign(const wickr_ec_key_t *ec_signing_key,
                               const wickr_buffer_t *data_to_sign);


bool ed448_sig_verify(const wickr_buffer_t *signature,
                      const wickr_ec_key_t *ec_public_key,
                      const wickr_buffer_t *data_to_verify);

wickr_buffer_t *ed448_sig_derive_public_key(const wickr_buffer_t *private_key_data);

wickr_buffer_t *ed448_dh_derive_public_key(const wickr_buffer_t *private_key_data);

wickr_buffer_t *ed448_dh_shared_secret(const wickr_ec_key_t *local_key_pair,
                                       const wickr_ec_key_t *peer_public_key);

#ifdef __cplusplus
}
#endif

#endif /* ed448_suite_h */
