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

#ifndef stream_key_h
#define stream_key_h

#include "crypto_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PACKET_PER_EVO_MIN 64
#define PACKET_PER_EVO_DEFAULT 512
#define PACKET_PER_EVO_MAX 32768

/**
 @addtogroup wickr_stream_key wickr_stream_key
 */

/**
 @ingroup wickr_stream_key
 @struct wickr_stream_key
 
 @brief A data structure representing the stream encoding / decoding key material
 A stream key holds information about the key material used for cipher operations as well as it's next evolution
 key and the number of packets this key should be used to encode or decode before evolution takes place
 
 @var wickr_stream_key::cipher_key
 key used to encrypt or decrypt packets when the key is used for cipher operations
 @var wickr_stream_key::evolution_key
 data to be used to help evolove the key when 'cipher_key' is used 'packets_per_evolution' times
 @var wickr_stream_key::packets_per_evolution
 number of packets this key should be used before it is evoloved using 'evolution_key'
 @var wickr_stream_key::user_data
 user provided data to assoiciate with the key
 */
struct wickr_stream_key {
    wickr_cipher_key_t *cipher_key;
    wickr_buffer_t *evolution_key;
    wickr_buffer_t *user_data;
    uint32_t packets_per_evolution;
};

typedef struct wickr_stream_key wickr_stream_key_t;

/**
 
 @ingroup wickr_stream_key
 
 Create a stream key from components
 
 @param cipher_key see documentation of 'wickr_stream_key' structure
 @param evolution_key see documentation of 'wickr_stream_key' structure
 @param packets_per_evolution see documentation of 'wickr_stream_key' structure
 @return a newly allocated stream key owning the properties passed in
 */
wickr_stream_key_t *wickr_stream_key_create(wickr_cipher_key_t *cipher_key, wickr_buffer_t *evolution_key, uint32_t packets_per_evolution);

/**
 
 @ingroup wickr_stream_key
 
 Create a stream key from components with user data
 
 @param cipher_key see documentation of 'wickr_stream_key' structure
 @param evolution_key see documentation of 'wickr_stream_key' structure
 @param packets_per_evolution see documentation of 'wickr_stream_key' structure
 @param user_data see documentation of 'wickr_stream_key' structure
 @return a newly allocated stream key owning the properties passed in
 */
wickr_stream_key_t *wickr_stream_key_create_user_data(wickr_cipher_key_t *cipher_key, wickr_buffer_t *evolution_key, uint32_t packets_per_evolution, wickr_buffer_t *user_data);

/**
 @ingroup wickr_stream_key
 
 Generate a random stream key
 
 @param engine the crypto engine to use for secure random cipher key generation
 @param cipher the cipher to use for generation of the internal 'cipher_key' property
 @param packets_per_evolution the number of times this key should be used before it evoloves
 @return a newly allocated stream key
 */
wickr_stream_key_t *wickr_stream_key_create_rand(const wickr_crypto_engine_t engine, wickr_cipher_t cipher, uint32_t packets_per_evolution);

/**
 @ingroup wickr_stream_key
 
 Copy a stream key
 
 @param stream_key the stream key to copy
 @return a newly allocated stream key holding a deep copy of properties from 'stream_key'
 */
wickr_stream_key_t *wickr_stream_key_copy(const wickr_stream_key_t *stream_key);

/**
 @ingroup wickr_stream_key
 
 Serialize a stream key
 
 @param key the key to serialize
 @return a serialized protocol buffer object representing the properties of 'key'
 */
wickr_buffer_t *wickr_stream_key_serialize(const wickr_stream_key_t *key);

/**
 @ingroup wickr_stream_key
 
 Create a stream key from a serialized buffer
 
 @param buffer the buffer to parse into a stream key
 @return a newly allocated stream key represented by 'buffer' or NULL if parsing buffer fails
 */
wickr_stream_key_t *wickr_stream_key_create_from_buffer(const wickr_buffer_t *buffer);

/**
 
 @ingroup wickr_stream_key
 
 Destroy a stream key
 
 @param stream_key a pointer to the stream key to destroy. All properties of '*stream_key' will also be destroyed
 */
void wickr_stream_key_destroy(wickr_stream_key_t **stream_key);

#ifdef __cplusplus
}
#endif

#endif /* stream_key_h */
