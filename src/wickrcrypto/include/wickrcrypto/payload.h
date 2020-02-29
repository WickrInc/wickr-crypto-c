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

#ifndef payload_h
#define payload_h

#include "buffer.h"
#include "crypto_engine.h"
#include "packet_meta.h"

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 @addtogroup wickr_payload wickr_payload
 */
    
/**
 @ingroup wickr_payload
 @struct wickr_payload
 @brief The encrypted body content of a Wickr packet
 @var wickr_payload::meta
 protected metadata for the body
 @var wickr_payload::body
 the body content of the message as provided by the sender
 */
struct wickr_payload {
    wickr_packet_meta_t *meta;
    wickr_buffer_t *body;
};

typedef struct wickr_payload wickr_payload_t;

/**
 @ingroup wickr_payload
 
 Create a payload from components
 
 @param meta see 'wickr_payload' property documentation property documentation
 @param body see 'wickr_payload' property documentation property documentation
 @return a newly allocated payload owning the properties passed in
 */
wickr_payload_t *wickr_payload_create(wickr_packet_meta_t *meta, wickr_buffer_t *body);

/**
 
 @ingroup wickr_payload
 
 Copy a payload
 
 @param source the payload to copy
 @return a newly allocated payload holding a deep copy of the properties of 'source'
 */
wickr_payload_t *wickr_payload_copy(const wickr_payload_t *source);

/**
 
 @ingroup wickr_payload
 
 Destroy a payload
 
 @param payload a pointer to the payload to destroy. All properties of '*payload' will also be destroyed
 */
void wickr_payload_destroy(wickr_payload_t **payload);
    
/**

 @ingroup wickr_payload
 
 Serialize a payload to a buffer

 @param payload the payload to serialize
 @return a buffer containing the properties of 'payload'
 */
wickr_buffer_t *wickr_payload_serialize(const wickr_payload_t *payload);
    
/**
 
 @ingroup wickr_payload
 
 Deserialize a buffer into a payload

 @param buffer a buffer containing a payload serialized with 'wickr_payload_serialize'
 @return a payload with data contained in 'buffer', or NULL if 'buffer' is not formatted properly
 */
wickr_payload_t *wickr_payload_create_from_buffer(const wickr_buffer_t *buffer);

/**
 @ingroup wickr_payload
 
 Serialize-Then-Encrypt a payload
 
 Payloads are serialized using protocol buffers (message.pb-c.h)
 
 
 @param payload the payload to encrypt
 @param engine a crypto engine capable of encryption using payload_key
 @param payload_key the key to use for encryption
 @return an encrypted payload
 */
wickr_cipher_result_t *wickr_payload_encrypt(const wickr_payload_t *payload,
                                             const wickr_crypto_engine_t *engine,
                                             const wickr_cipher_key_t *payload_key);

/**
 @ingroup wickr_payload
 
 Decrypt-Then-Deserialize
  
 @param engine a crypto engine capable of decryption using payload_key
 @param cipher_result an encrypted payload
 @param payload_key the key to use for decrypting 'cipher_result'
 @return a payload or NULL if an incorrect key is provided
 */
wickr_payload_t *wickr_payload_create_from_cipher(const wickr_crypto_engine_t *engine,
                                                  const wickr_cipher_result_t *cipher_result,
                                                  const wickr_cipher_key_t *payload_key);
    
#ifdef __cplusplus
}
#endif

#endif /* payload_h */
