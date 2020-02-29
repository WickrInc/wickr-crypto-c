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

#ifndef transport_root_key_h
#define transport_root_key_h

#include "buffer.h"
#include "stream_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
@addtogroup wickr_transport_root_key
*/

/**
 @ingroup wickr_transport_root_key
 
 @struct wickr_transport_root_key
 @brief A root key for the wickr_transport_ctx that is used to communicate the master secret for the transport communication. The root key can
 be converted to a set of stream keys based on direction for use in a transport.

 @var wickr_transport_root_key::secret
 data that represents the master secret which is cipher.key_len in size
 @var wickr_transport_root_key::cipher
 the cipher that the root key creator has chosen to use when converting the secret into a set of stream keys
 @var wickr_transport_root_key::packets_per_evo_send
 the value to set for `packets_per_evolution` when creating a stream key in the ENCODE direction
 @var wickr_transport_root_key::packets_per_evo_recv
 the value to set for `packets_per_evolution` when creating a stream key in the DECODE direction
*/
struct wickr_transport_root_key {
    wickr_buffer_t *secret;
    wickr_cipher_t cipher;
    uint32_t packets_per_evo_send;
    uint32_t packets_per_evo_recv;
};

typedef struct wickr_transport_root_key wickr_transport_root_key_t;

/**
 @ingroup wickr_transport_root_key
 
 Create a root key using a random secret of length cipher.key_key
 
 @param engine a pointer to a crypto engine that can generate random bytes
 @param cipher the cipher to use for generating stream keys
 @param packets_per_evo_send the value to set for `packets_per_evolution` when creating a stream key in the ENCODE direction
 @param packets_per_evo_recv the value to set for `packets_per_evolution` when creating a stream key in the DECODE direction
 @return a newly allocated transport root key or NULL if random generation fails
 */
wickr_transport_root_key_t *wickr_transport_root_key_create_random(const wickr_crypto_engine_t *engine,
                                                                   wickr_cipher_t cipher,
                                                                   uint32_t packets_per_evo_send,
                                                                   uint32_t packets_per_evo_recv);

/**
 @ingroup wickr_transport_root_key

 Create a root key using a random secret of length cipher.key_key

 @param secret a secret of length `cipher.key_len`
 @param cipher the cipher to use for generating stream keys
 @param packets_per_evo_send the value to set for `packets_per_evolution` when creating a stream key in the ENCODE direction
 @param packets_per_evo_recv the value to set for `packets_per_evolution` when creating a stream key in the DECODE direction
 @return a newly allocated transport root key taking ownership of `secret` or NULL if allocation fails
*/
wickr_transport_root_key_t *wickr_transport_root_key_create(wickr_buffer_t *secret,
                                                            wickr_cipher_t cipher,
                                                            uint32_t packets_per_evo_send,
                                                            uint32_t packets_per_evo_recv);

/**
 @ingroup wickr_transport_root_key

 Copy a transport root key

 @param root_key the transport root key to copy
 @return a newly allocated transport root key holding a deep copy of the properties of `root_key`
*/
wickr_transport_root_key_t *wickr_transport_root_key_copy(const wickr_transport_root_key_t *root_key);

/**
 @ingroup wickr_transport_root_key

 Destroy a transport root key

 @param root_key a pointer to the transport root key to destroy. All properties of `*root_key` will also be destroyed
*/
void wickr_transport_root_key_destroy(wickr_transport_root_key_t **root_key);

/**
 @ingroup wickr_transport_root_key
 
 Convert a transport root key into a stream key
 
 @param root_key the transport root key to convert into a stream key
 @param engine a pointer to a crypto engine that supports HKDF functionality
 @param salt the salt to use for the HKDF function
 @param stream_id a stream id that will differentiate the stream between the ENCODE and DECODE directions
 @param direction the direction to set on the resulting stream key
 @return a newly allocated stream key or NULL if stream key generation fails
 */
wickr_stream_key_t *wickr_transport_root_key_to_stream_key(const wickr_transport_root_key_t *root_key,
                                                           const wickr_crypto_engine_t *engine,
                                                           const wickr_buffer_t *salt,
                                                           const wickr_buffer_t *stream_id,
                                                           wickr_stream_direction direction);

#ifdef __cplusplus
}
#endif

#endif /* transport_root_key_h */
