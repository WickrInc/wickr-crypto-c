/*
 * Copyright © 2012-2018 Wickr Inc.  All rights reserved.
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

#ifndef ecdh_h
#define ecdh_h

#include <stdlib.h>
#include "eckey.h"
#include "digest.h"
#include "kdf.h"

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 @addtogroup wickr_ecdh_params
 */

/**
 
 @ingroup wickr_ecdh_params
 
 @struct wickr_ecdh_params
 
 @brief Holds parameters used to generate Elliptic Curve Diffie-Hellman based secrets
 
  All ECDH secrets are created in two phases. In the first phase, a local key pair and peer public key are used to generate a standard ECDH shared secret, the length of which varies by curve. In the second phase, the ECDH shared secret is expanded by a KDF to get specific length output. The specific KDF and the length of it's output are controlled by the implementation provided by the crypto engine that is used to perform the key exchange operation.
 
 @var wickr_ecdh_params::local_key
 Elliptic Curve key with both public and private components set used to compute the ECDH shared secret
 @var wickr_ecdh_params::peer_key
 Elliptic Curve key with the public component of the other party's key pair used to compute the ECDH shared secret
 @var wickr_ecdh_params::kdf_info
 the kdf parameters to execute against the calculated shared secret, currently supports HKDF
 */
struct wickr_ecdh_params {
    wickr_ec_key_t *local_key;
    wickr_ec_key_t *peer_key;
    wickr_kdf_meta_t *kdf_info;
};

typedef struct wickr_ecdh_params wickr_ecdh_params_t;

/**
 
 @ingroup wickr_ecdh_params
 
 Create an Elliptic Curve Diffie-Hellman parameter set from components

 @param local_key See documentation in 'wickr_ecdh_params' property declarations
 @param peer_key See documentation in 'wickr_ecdh_params' property declarations
 @param kdf_info See documentation in 'wickr_ecdh_params' property declarations
 @return a newly allocated ecdh parameter set owning the properties passed in
 */
wickr_ecdh_params_t *wickr_ecdh_params_create(wickr_ec_key_t *local_key, wickr_ec_key_t *peer_key, wickr_kdf_meta_t *kdf_info);

/**
 
 @ingroup wickr_ecdh_params
 
 Copy an Elliptic Curve Diffie-Hellman parameter set

 @param source the Elliptic Curve Diffie-Hellman parameter set to copy
 @return a newly allocated Elliptic Curve Diffie-Hellman parameter set containing deep copies of the properties of 'info'
 */
wickr_ecdh_params_t *wickr_ecdh_params_copy(const wickr_ecdh_params_t *source);

/**
 
 @ingroup wickr_ecdh_params
 
 Destroy an Elliptic Curve Diffie-Hellman parameter set

 @param params a pointer to an Elliptic Curve Diffie-Hellman parameter set to destroy. Properties of '*params' will also be destroyed
 */
void wickr_ecdh_params_destroy(wickr_ecdh_params_t **params);

/**
 
 @ingroup wickr_ecdh_params
 
 Determine Elliptic Curve Diffie-Hellman parameter set validity

 @param params the parameter set to validate
 @return true if parameters are valid. At a minimum, the public and private components of the 'local_key', and the public component of the 'peer_key' must be set for this function to succeed
 */
bool wickr_ecdh_params_are_valid(const wickr_ecdh_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* ecdh_h */
