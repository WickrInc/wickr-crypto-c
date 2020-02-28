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

#ifndef fingerprint_h
#define fingerprint_h

#include "buffer.h"
#include "eckey.h"
#include "crypto_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 @addtogroup wickr_fingerprint wickr_fingerprint
 */
    
/**
 
 @ingroup wickr_fingerprint
 
 Fingerprint output format
 
 SHORT - Output a fingerprint that is 1/2 length of the full representation
 LONG - Output a fingerprint that is encoded to be full length
 
 */
typedef enum {
    FINGERPRINT_OUTPUT_SHORT,
    FINGERPRINT_OUTPUT_LONG
} wickr_fingerprint_output;
    
/**
 
 @ingroup wickr_fingerprint
 
 Fingerprint Encoding Type
 
 SHA512 - Calculated by taking a SHA512 of the inputs concatenated together
 
 */
typedef enum { WICKR_FINGERPRINT_TYPE_SHA512 } wickr_fingerprint_type;

/**
 
 @ingroup wickr_fingerprint
 
 @struct wickr_fingerprint
 
 @brief A fingerprint representation of a combination of signature keys / identifiers
 @var wickr_fingerprint::type
 type the type of fingerprint algorithm to use when processing key/identifier
 @var wickr_fingerprint::data
 a raw data representation of the fingerprint
 */
struct wickr_fingerprint {
    wickr_fingerprint_type type;
    wickr_buffer_t *data;
};

typedef struct wickr_fingerprint wickr_fingerprint_t;

/**
 
 @ingroup wickr_fingerprint
 
 Generate a fingerprint based on a signing key / fixed user identifier

 @param engine the crypto engine to use for underlying hash operations
 @param key the key to include in the resulting fingerprint
 @param identifier a fixed user identifier to use in the resulting fingerprint
 @param type the type of fingerprint algorithm to use when processing key/identifier
 @return A unique fingerprint representing the combination of key/identifier
 */
wickr_fingerprint_t *wickr_fingerprint_gen(wickr_crypto_engine_t engine,
                                           const wickr_ec_key_t *key,
                                           const wickr_buffer_t *identifier,
                                           wickr_fingerprint_type type);

/**
 
 @ingroup wickr_fingerprint
 
 Generate a bilateral fingerprint by combining two existing fingerprints made with 'wickr_fingerprint_gen'.
 Fingerprints created by this function are identical if local/remote input values are swapped, as they are sorted
 internally before computation begins

 @param engine the crypto engine to use for underlying hash operations
 @param local the first existing fingerprint to include in the bilateral fingerprint
 @param remote the second existing fingerprint to include in the bilateral fingerprint
 @param type the type of fingerprint algorithm to use when processing local/remote
 @return A unique fingerprint representing the combination of local/remote
 */
wickr_fingerprint_t *wickr_fingerprint_gen_bilateral(wickr_crypto_engine_t engine,
                                                     const wickr_fingerprint_t *local,
                                                     const wickr_fingerprint_t *remote,
                                                     wickr_fingerprint_type type);

/**
 
 @ingroup wickr_fingerprint
 
 Create a new wickr_fingerprint struct

 @param type see 'wickr_fingerprint' property documentation
 @param data see 'wickr_fingerprint' property documentation
 @return a newly allocated fingerprint that takes ownership of the passed inputs
 */
wickr_fingerprint_t *wickr_fingerprint_create(wickr_fingerprint_type type, wickr_buffer_t *data);

    
/**
 
 @ingroup wickr_fingerprint
 
 Copy a wickr_fingerprint

 @param fingerprint the fingerprint to copy
 @return a copy of 'fingerprint' that contains a deep copy of 'data'
 */
wickr_fingerprint_t *wickr_fingerprint_copy(const wickr_fingerprint_t *fingerprint);
    

/**
 
 @ingroup wickr_fingerprint
 
 Destroy a wickr_fingerprint

 @param fingerprint the fingerprint to destroy
 */
void wickr_fingerprint_destroy(wickr_fingerprint_t **fingerprint);

/**
 
 @ingroup wickr_fingerprint
 
 Get a base32 representation of a fingerprint

 @param fingerprint the fingerprint to get the base32 representation of
 @param output_mode the output mode of the base32 representation (short/long)
 @return A string buffer containing a base32 representation of 'fingerprint' that is null terminatied
 */
wickr_buffer_t *wickr_fingerprint_get_b32(const wickr_fingerprint_t *fingerprint, wickr_fingerprint_output output_mode);
    
    
/**
 
 @ingroup wickr_fingerprint
 
 Get a hex representation of a fingerprint

 @param fingerprint the fingerprint to get the hex representation of
 @param output_mode the output mode of the base32 representation (short/long)
 @return A string buffer containing a hex representation of 'fingerprint' that is null terminatied
 */
wickr_buffer_t *wickr_fingerprint_get_hex(const wickr_fingerprint_t *fingerprint, wickr_fingerprint_output output_mode);

#ifdef __cplusplus
}
#endif
    
#endif /* fingerprint_h */
