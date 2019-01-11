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

#ifndef eckey_h
#define eckey_h

#include <stdlib.h>
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 Wickr needs signatures to be a static size for easy parsing 
 The static size of a signature for P521 was determined as follows
 Maximum r,s size in DER ASN.1 Integer format + fixed 2 byte length metadata:
 (curve id (4bits) + digest id (4bits) + padding size(1byte))
 */
#define P521_SIGNATURE_MAX_SIZE 143
    
/**
 Maximum length of a pub key buffer for P521
 (1 byte Wickr Meta || 1 byte OpenSSL Meta || 66 bytes X || 66 bytes Y)
 */
#define P521_PUB_KEY_MAX_SIZE 134

typedef enum { EC_CURVE_ID_NIST_P521 } wickr_ec_curve_id;

/**
 @addtogroup wickr_ec_curve wickr_ec_curve_t
 */
    
/**
 
 @ingroup wickr_ec_curve
 
 @struct wickr_ec_curve
 
 @brief Metadata about curve types to help with key generation, and signatures
 
 @var wickr_ec_curve::identifier
 numerical identifier for a curve. Used in serialization to help identify a curve that was used elsewhere. Must be less than 16 since it is serialized into buffers using a 4 bit space
 @var wickr_ec_curve::signature_size
 the length of a serialized ecdsa signature using this curve, padded as needed
 */
struct wickr_ec_curve {
    wickr_ec_curve_id identifier;
    uint8_t signature_size;
    uint8_t max_pub_size;
};

typedef struct wickr_ec_curve wickr_ec_curve_t;

static const wickr_ec_curve_t EC_CURVE_NIST_P521 = { EC_CURVE_ID_NIST_P521, P521_SIGNATURE_MAX_SIZE, P521_PUB_KEY_MAX_SIZE };

/**
 
 @ingroup wickr_ec_curve
 
 @struct wickr_ec_key
 
 @brief Representation of public and private Elliptic Curve Keypair information as buffers
 
 @var wickr_ec_key::curve
 the curve information associated with this keypair
 @var wickr_ec_key::pub_data
 serialized public key information
 @var wickr_ec_key::pri_data
 serialized private key information
 */
struct wickr_ec_key {
    wickr_ec_curve_t curve;
    wickr_buffer_t *pub_data;
    wickr_buffer_t *pri_data;
};

typedef struct wickr_ec_key wickr_ec_key_t;

/**
 
 @ingroup wickr_ec_curve
 
 Create an Elliptic Curve Keypair from components
 
 NOTE: This function does not have the capability to generate key pair information, it simply constructs the data structure using pre-generated components. A crypto engine is required to generate random keypairs

 @param curve see 'wickr_ec_key' property documentation
 @param pub_data see 'wickr_ec_key' property documentation
 @param pri_data see 'wickr_ec_key' property documentation. May be NULL to represent a public key
 @return a newly allocated elliptic curve key representing either a public or private key. Takes ownership of the passed inputs
 */
wickr_ec_key_t *wickr_ec_key_create(wickr_ec_curve_t curve, wickr_buffer_t *pub_data, wickr_buffer_t *pri_data);

/**
 
 @ingroup wickr_ec_curve
 
 Copy an EC Key
 
 @param source the EC key to copy
 @return a newly allocated EC key holding a deep copy of the properties of 'source'
 */
wickr_ec_key_t *wickr_ec_key_copy(const wickr_ec_key_t *source);

/**
 
 @ingroup wickr_ec_curve
 
 Destroy an EC Key
 
 @param key a pointer to the key to destroy. All properties of '*key' will also be destroyed
 */
void wickr_ec_key_destroy(wickr_ec_key_t **key);
    
/**
 
 @ingroup wickr_ec_key
 
 Get a fixed length representation of the public key data
 NOTE: This is for protection in the future, OpenSSL pub keys are currently encoded to already be fixed length
 
 @param key the key pair to get fixed length pub_data for
 @return a buffer representating a garenteed fixed length version of 'key->pub_data'
*/
wickr_buffer_t *wickr_ec_key_get_pubdata_fixed_len(const wickr_ec_key_t *key);

/**
 
 @ingroup wickr_ec_curve
 
 Find an EC key by numerical identifier

 @param identifier the identifier in which to return the curve information for
 @return the requested curve information, or NULL if no matching information can be found
 */
const wickr_ec_curve_t *wickr_ec_curve_find(uint8_t identifier);

#ifdef __cplusplus
}
#endif

#endif /* eckey_h */
