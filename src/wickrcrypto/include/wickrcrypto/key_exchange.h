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

#ifndef key_exchange_h
#define key_exchange_h

#include "buffer.h"
#include "eckey.h"
#include "crypto_engine.h"

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 @addtogroup wickr_key_exchange Key Exchange
 */
    
/**
 @ingroup wickr_key_exchange
 @struct wickr_key_exchange
 @brief Public key exchange protected data. After a shared secret is generated using a public key with
 identifier 'key_id', and run through a KDF, it is used to encrypt data to be protected by the exchange
 and the ciphertext is stored in 'exchange_ciphertext'
 @var wickr_key_exchange::exchange_id
 a unique identifier to be assoiciated with the exchange to aid a recipient in finding a particular
 exchange within an exchange set
 @var wickr_key_exchange::key_id
 the identifier of the recipient's public key was used to compute
 the key protecting 'exchange_ciphertext'. This aids a recipient in finding the particular private key they
 need to use to unlock 'exchange_ciphertext' upon receipt
 @var wickr_key_exchange::exchange_ciphertext
 ciphered shared secret + KDF protected data
 */
struct wickr_key_exchange {
    wickr_buffer_t *exchange_id;
    uint64_t key_id;
    wickr_cipher_result_t *exchange_ciphertext;
};

typedef struct wickr_key_exchange wickr_key_exchange_t;

/**
 
 @ingroup wickr_key_exchange
 
 Create a key exchange from properties
 
 @param exchange_id see 'wickr_key_exchange' property documentation property documentation
 @param key_id see 'wickr_key_exchange' property documentation property documentation
 @param exchange_ciphertext see 'wickr_key_exchange' property documentation property documentation
 @return a newly allocated packet metadata set owning the properties passed in
 */
wickr_key_exchange_t *wickr_key_exchange_create(wickr_buffer_t *exchange_id,
                                                uint64_t key_id,
                                                wickr_cipher_result_t *exchange_ciphertext);
    

/**
 
 @ingroup wickr_key_exchange
 
 Copy a key exchange
 
 @param source the key exchange to copy
 @return a newly allocated node holding a deep copy of the properties of 'source'
 */
wickr_key_exchange_t *wickr_key_exchange_copy(const wickr_key_exchange_t *source);

/**
 
 @ingroup wickr_key_exchange
 
 Destroy a key exchange
 
 @param exchange a pointer to the key exchange to destroy. All properties of '*exchange' will also be destroyed
 */
void wickr_key_exchange_destroy(wickr_key_exchange_t **exchange);

typedef wickr_array_t wickr_exchange_array_t;
    
/**
 
 @ingroup wickr_key_exchange
 
 Allocate a new key exchange array
 
 @param exchange_count the number of exchanges the array should hold
 @return a newly allocated wickr_array for key exchange objects
 */
wickr_exchange_array_t *wickr_exchange_array_new(uint32_t exchange_count);

/**
 @ingroup wickr_key_exchange
 
 Set an item in a key exchange array
 
 NOTE: Calling this function does not make a copy of 'exchange', the array simply takes ownership of it
 
 @param array the array to set 'exchange' into
 @param index the location in 'array' to set exchange
 @param exchange the exchange to set at position 'index' in 'array'
 @return true if setting succeeds, false if the index is out of bounds
 */
bool wickr_exchange_array_set_item(wickr_exchange_array_t *array, uint32_t index, wickr_key_exchange_t *exchange);

/**
 @ingroup wickr_key_exchange
 
 Fetch a key exchange from an exchange array
 
 NOTE: Calling this function does not make a copy of the exchange being returned, the array still owns it
 
 @param array the array to fetch 'index' from
 @param index the index to fetch from 'array'
 @return a key exchange representing 'index' from the array
 */
wickr_key_exchange_t *wickr_exchange_array_fetch_item(wickr_exchange_array_t *array, uint32_t index);

/**
 @ingroup wickr_key_exchange
 
 @param array the array to copy
 @return a newly allocated key exchange array that contains deep copies of the items from 'array'
 */
wickr_array_t *wickr_exchange_array_copy(wickr_exchange_array_t *array);

/**
 @ingroup wickr_key_exchange
 
 @param array a pointer to the array to destroy, all items of '*array' are also destroyed
 */
void wickr_exchange_array_destroy(wickr_exchange_array_t **array);
    
/**
 @addtogroup wickr_key_exchange_set Key Exchange Set
 */

/**
 @ingroup wickr_key_exchange_set
 @struct wickr_key_exchange_set
 @brief A collection of key exchanges for a set of recipients. The data protected inside 'exchange_ciphertext'
 for each recipient is derived by each recipient node using their individualized key exchange.
 See Wickr white paper 'Prepare Packet Header' section for more information.
 
 @var wickr_key_exchange_set::sender_pub
 the public EC key that the sender used to derive the key exchanges contained within 'exchanges'
 @var wickr_key_exchange_set::exchanges
 an array of key exchanges, one for each recipient that will be receiving this message
 */
struct wickr_key_exchange_set {
    wickr_ec_key_t *sender_pub;
    wickr_exchange_array_t *exchanges;
};

typedef struct wickr_key_exchange_set wickr_key_exchange_set_t;

/**
 @ingroup wickr_key_exchange_set
 
 Create a key exchange set from components
 
 @param sender_pub see 'wickr_key_exchange_set' property documentation property documentation
 @param exchanges see 'wickr_key_exchange_set' property documentation property documentation
 @return a newly allocated key exchange set owning the properties passed in
 */
wickr_key_exchange_set_t *wickr_key_exchange_set_create(wickr_ec_key_t *sender_pub, wickr_exchange_array_t *exchanges);

/**
 @ingroup wickr_key_exchange_set
 
 Find a particular exchange in the exchange set
 
 @param exchange_set the exchange set to search
 @param identifier the identifier of the exchange to find
 @return the key exchange for 'identifier' or NULL if it cannot be found
 */
wickr_key_exchange_t *wickr_key_exchange_set_find(const wickr_key_exchange_set_t *exchange_set,
                                                  const wickr_buffer_t *identifier);

/**
 
 @ingroup wickr_key_exchange_set
 
 Copy a key exchange set
 
 @param source the key exchange set to copy
 @return a newly allocated key exchange set holding a deep copy of the properties of 'source'
 */
wickr_key_exchange_set_t *wickr_key_exchange_set_copy(const wickr_key_exchange_set_t *source);

/**
 
 @ingroup wickr_key_exchange_set
 
 Destroy a key exchange set
 
 @param exchange_set a pointer to the key exchange set to destroy. All properties of '*exchange_set'
 will also be destroyed
 */
void wickr_key_exchange_set_destroy(wickr_key_exchange_set_t **exchange_set);

/**
 
 @ingroup wickr_key_exchange_set
 
 Serialize a key exchange set using protocol buffers
 
 @param exchange_set the exchange set to serialize into bytes
 @return bytes representing 'exchange_set' with protocol buffers or NULL if serialization fails
 */
wickr_buffer_t *wickr_key_exchange_set_serialize(const wickr_key_exchange_set_t *exchange_set);

/**
 
 @ingroup wickr_key_exchange_set
 
 Create a key exchange set from bytes
 
 @param engine a crypto engine to use for importing key information within the exchange set
 @param buffer the buffer containing a serialized representation of a 'wickr_key_exchange_set'
 @return a key exchange set built from the bytes of 'buffer' or NULL if deserialization fails    
 */
wickr_key_exchange_set_t *wickr_key_exchange_set_create_from_buffer(const wickr_crypto_engine_t *engine,
                                                                    const wickr_buffer_t *buffer);
    
#ifdef __cplusplus
}
#endif

#endif /* key_exchange_h */
