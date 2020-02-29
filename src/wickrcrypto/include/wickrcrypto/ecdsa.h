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

#ifndef ecdsa_h
#define ecdsa_h

#include <stdlib.h>
#include "eckey.h"
#include "digest.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 @addtogroup wickr_ecdsa_result
 */

/**
 
 @ingroup wickr_ecdsa_result
 
 @struct wickr_ecdsa_result
 
 @brief Elliptic Curve Digital Signature Algorithm Result
 
 Holds values related to a generated signature using Elliptic Curve Digital Signature Algorithm
 
 @var wickr_ecdsa_result::curve
 information about the curve that the signing key belonged to
 @var wickr_ecdsa_result::digest_mode
 the digest used on the input data to the ECDSA function before the signature was taken
 @var wickr_ecdsa_result::sig_data 
 the raw signature output of the ECDSA algorithm
 */
struct wickr_ecdsa_result {
    wickr_ec_curve_t curve;
    wickr_digest_t digest_mode;
    wickr_buffer_t *sig_data;
};

typedef struct wickr_ecdsa_result wickr_ecdsa_result_t;

/**
 
 @ingroup wickr_ecdsa_result
 
 Create an ECDSA result from components

 @param curve see 'wickr_ecdsa_result' property documentation
 @param digest_mode see 'wickr_ecdsa_result' property documentation
 @param sig_data see 'wickr_ecdsa_result' property documentation property documentation
 @return a newly allocated ECDSA result owning the properties passed in
 */
wickr_ecdsa_result_t *wickr_ecdsa_result_create(wickr_ec_curve_t curve, wickr_digest_t digest_mode, wickr_buffer_t *sig_data);


/**
 
 @ingroup wickr_ecdsa_result
 
 Serialize an ECDSA result into a buffer

 @param result the ecdsa result to serialize
 @return a newly allocated buffer with serialized ECDSA result properties in the following format
    | CURVE_ID DIGEST_ID | SIG_DATA |. NOTE that CURVE_ID and DIGEST_ID are packed into 1 byte as 4 bit unsigned integers
 */
wickr_buffer_t *wickr_ecdsa_result_serialize(const wickr_ecdsa_result_t *result);

/**
 
 @ingroup wickr_ecdsa_result
 
 Create an ECDSA result from a serialized ECDSA result buffer
 
 @param buffer a buffer containing a serialized ECDSA result buffer
 @return ecdsa result parsed from 'buffer'. This function makes a copy of all bytes as it is parsing,
 so the resulting ECDSA result owns its properties. Returns NULL on parsing failure
 */
wickr_ecdsa_result_t *wickr_ecdsa_result_create_from_buffer(const wickr_buffer_t *buffer);

/**
 
 @ingroup wickr_ecdsa_result
 
 Copy an ECDSA result

 @param source the ECDSA result to copy
 @return a newly allocated ECDSA result holding a deep copy of the properties of 'source'
 */
wickr_ecdsa_result_t *wickr_ecdsa_result_copy(const wickr_ecdsa_result_t *source);

/**
 
 @ingroup wickr_ecdsa_result
 
 Destroy an ECDSA result

 @param result a pointer to the result to destroy. All properties of '*result' will also be destroyed
 */
void wickr_ecdsa_result_destroy(wickr_ecdsa_result_t **result);

#ifdef __cplusplus
}
#endif

#endif /* ecdsa_h */
