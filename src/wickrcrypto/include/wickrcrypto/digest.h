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

#ifndef digest_h
#define digest_h

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { DIGEST_SHA2 } wickr_digest_type;
typedef enum { DIGEST_ID_SHA256 = 1, DIGEST_ID_SHA384, DIGEST_ID_SHA512 } wickr_digest_id;

/**
 @addtogroup wickr_digest
 */
    
/**
 
 @ingroup wickr_digest
 
 @struct wickr_digest
 
 @brief Digest function parameters
 
 @var wickr_digest::type
 the family of digest that this digest belongs to. As an example SHA2 contains multiple modes of operation with different sizes of output
 @var wickr_digest::digest_id
 the unique identifier of this digest
 @var wickr_digest::size 
 the length of the digest output
 */
struct wickr_digest {
    wickr_digest_type type;
    wickr_digest_id digest_id;
    uint8_t size;
};

typedef struct wickr_digest wickr_digest_t;
    
#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64
    
static const wickr_digest_t DIGEST_SHA_256 = { DIGEST_SHA2, DIGEST_ID_SHA256, SHA256_DIGEST_SIZE };
static const wickr_digest_t DIGEST_SHA_384 = { DIGEST_SHA2, DIGEST_ID_SHA384, SHA384_DIGEST_SIZE };
static const wickr_digest_t DIGEST_SHA_512 = { DIGEST_SHA2, DIGEST_ID_SHA512, SHA512_DIGEST_SIZE };

/**
 
 @ingroup wickr_digest
 
 Find a digest by identifier

 @param digest_id the identifier to search for
 @return a digest struct representing the digest with id 'digest_id', or NULL if no digest is found
 */
const wickr_digest_t *wickr_digest_find_with_id(uint8_t digest_id);

#ifdef __cplusplus
}
#endif

#endif /* digest_h */
