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

#ifndef encoder_result_h
#define encoder_result_h

#include "cipher.h"
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 @addtogroup wickr_encoder_result
 */

/**
 @ingroup wickr_encoder_result
 @struct wickr_encoder_result
 @brief the result of a packet encoding operation
 @var wickr_encoder_result::packet_key
 the packet key that was randomly chosen to encrypt the payload of the packet
 @var wickr_encoder_result::packet
 encrypted wickr packet ready for transfer
 */
struct wickr_encoder_result {
    wickr_cipher_key_t *packet_key;
    wickr_packet_t *packet;
};

typedef struct wickr_encoder_result wickr_encoder_result_t;

/**
 @ingroup wickr_encoder_result_t
 
 Create an encode result from components
 
 @param packet_key see property description from 'wickr_encoder_result_t'
 @param packet see property description from 'wickr_encoder_result_t'
 @return a newly allocated encode packet result owning the parameters passed in
 */
wickr_encoder_result_t *wickr_encoder_result_create(wickr_cipher_key_t *packet_key, wickr_packet_t *packet);
    

/**
 @ingroup wickr_encoder_result_t

 Copy a Wickr encoder result
 
 @param result the result to copy
 @return a newly allocated encoder result holding a deep copy of the properties of 'result'
 */
wickr_encoder_result_t *wickr_encoder_result_copy(const wickr_encoder_result_t *result);

/**
 @ingroup wickr_encoder_result_t
 
 Destroy an encode packet result
 
 @param result a pointer to an encode packet result to destroy. Will destroy the sub properties of '*encode' as well
 */
void wickr_encoder_result_destroy(wickr_encoder_result_t **result);
    
#ifdef __cplusplus
}
#endif

#endif /* encoder_result_h */
