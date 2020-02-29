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

#ifndef cipher_h
#define cipher_h

#include <stdlib.h>
#include "buffer.h"
#include "kdf.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup wickr_cipher wickr_cipher_t */

typedef enum { CIPHER_ID_AES256_GCM = 0, CIPHER_ID_AES256_CTR = 1 } wickr_cipher_id;

/**
 
 @ingroup wickr_cipher
 
 @struct wickr_cipher
 
 @brief Represents a cipher that can be used in the crypto_engine. This meta object holds parameters for the cipher algorithms and maintains an identifier that can be used to look up the desired parameters for an algorithm.
 
 @var wickr_cipher::cipher_id
 identifier for the cipher to be used in serialization / deserialization to load a particular set of cipher parameters
 @var wickr_cipher::key_len
 the size of a key in bytes required to cipher / decipher input
 @var wickr_cipher::iv_len
 the size of the nonce in bytes required to cipher / decipher input
 @var wickr_cipher::auth_tag_len
 the size of the authentication tag required by the cipher to authenticate output of the cipher
 @var wickr_cipher::is_authenticated
 specifies if the cipher requires authentication. If is_authenticated is true, then auth_tag_len must be non-zero
 */
struct wickr_cipher {
    wickr_cipher_id cipher_id;
    uint8_t key_len;
    uint8_t iv_len;
    uint8_t auth_tag_len;
    bool is_authenticated;
};

typedef struct wickr_cipher wickr_cipher_t;

static const wickr_cipher_t CIPHER_AES256_GCM = { CIPHER_ID_AES256_GCM, 32, 12, 16, true };
static const wickr_cipher_t CIPHER_AES256_CTR = { CIPHER_ID_AES256_CTR, 32, 16, 0, false };

/**
 
 @ingroup wickr_cipher
 
 Find a supported cipher by identifier. When cipher results are serialized they contain the identifier of the cipher that was used to create them as the first byte

 @param cipher_id the identifier of the cipher
 @return a cipher with identifier 'cipher_id'. NULL if cipher is not found
 */
const wickr_cipher_t *wickr_cipher_find(uint8_t cipher_id);

/**
 
 @ingroup wickr_cipher
 
 @struct wickr_cipher_result
 
 The result of a cipher operation. Contains the components that are outputted by a cipher function
 
 @var wickr_cipher_result::cipher
 the cipher used to create the cipher result
 @var wickr_cipher_result::iv
 the initialization vector used in the cipher function
 @var wickr_cipher_result::cipher_text
 the output of the cipher function using 'cipher' and 'iv'
 @var wickr_cipher_result::auth_tag
 the calculated authentication tag for the output of the cipher function. Can be NULL if a non-authenticated cipher is used
 */
struct wickr_cipher_result {
    wickr_cipher_t cipher;
    wickr_buffer_t *iv;
    wickr_buffer_t *cipher_text;
    wickr_buffer_t *auth_tag;
};

typedef struct wickr_cipher_result wickr_cipher_result_t;

/**
 
 @ingroup wickr_cipher
 
 Construct a cipher result from individual components.

 @param cipher the cipher used in the cipher operation
 @param iv the initialization vector used in the cipher operation
 @param cipher_text the output bytes of a cipher function using 'cipher' and 'iv'
 @param auth_tag the authentication tag associated with 'cipher_text'. If 'cipher' is authenticated this property is required, otherwise it should be NULL
 @return A newly allocated cipher result that takes ownership of the passed inputs, or NULL if allocation fails
 */
wickr_cipher_result_t *wickr_cipher_result_create(wickr_cipher_t cipher, wickr_buffer_t *iv, wickr_buffer_t *cipher_text, wickr_buffer_t *auth_tag);

/**
 
 @ingroup wickr_cipher
 
 Copy a cipher result

 @param result the source of the copy
 @return A newly allocated cipher_result that contains deep copies of all the properties of 'result'
 */
wickr_cipher_result_t *wickr_cipher_result_copy(const wickr_cipher_result_t *result);

/**
 
 @ingroup wickr_cipher
 
 Destroy a cipher result

 @param result a pointer to the cipher result to destroy. Destruction will also destroy the individual properties of 'result'
 */
void wickr_cipher_result_destroy(wickr_cipher_result_t **result);

/**
 
 @ingroup wickr_cipher
 
 Determine if a cipher result is formed correctly

 @param result the cipher result to validate
 @return true if result is structured correctly, false if a required field is missing
 */
bool wickr_cipher_result_is_valid(const wickr_cipher_result_t *result);

/**
 
 @ingroup wickr_cipher
 
 Serialize a cipher result

 @param result the cipher result to serialize
 @return a buffer containing bytes representing the cipher result in the following format: 
    | CIPHER_ID | IV | AUTH_TAG (IF REQUIRED) | CIPHER_TEXT |
 */
wickr_buffer_t *wickr_cipher_result_serialize(const wickr_cipher_result_t *result);

/**
 
 @ingroup wickr_cipher
 
 Create a cipher result from a serialized cipher result buffer

 @param buffer a buffer created by 'wickr_cipher_result_serialize'
 @return cipher result parsed from 'buffer'. This function makes a copy of all bytes as it is parsing, 
 so the resulting cipher result owns its properties. Returns NULL on parsing failure
 */
wickr_cipher_result_t *wickr_cipher_result_from_buffer(const wickr_buffer_t *buffer);

/**
 
 @ingroup wickr_cipher
 
 @struct wickr_cipher_key
 
 A key to be provided to a cipher operation
 
 @var wickr_cipher_key::cipher 
 the cipher this key is to be used by
 @var wickr_cipher_key::key_data 
 a buffer representing the raw bytes of the key
 */
struct wickr_cipher_key {
    wickr_cipher_t cipher;
    wickr_buffer_t *key_data;
};

typedef struct wickr_cipher_key wickr_cipher_key_t;

/**
 
 @ingroup wickr_cipher
 
 Create a key from components

 @param cipher the cipher this key is to be used by
 @param key_data a buffer representing the raw bytes of the key
 @return a newly allocated cipher key that takes ownership over 'key_data'
 */
wickr_cipher_key_t *wickr_cipher_key_create(wickr_cipher_t cipher, wickr_buffer_t *key_data);

/**
 
 @ingroup wickr_cipher
 
 Copy a cipher key

 @param key the key to copy
 @return a newly allocated cipher key holding a deep copy of the properties of 'key'
 */
wickr_cipher_key_t *wickr_cipher_key_copy(const wickr_cipher_key_t *key);

/**
 
 @ingroup wickr_cipher
 
 Destroy a cipher key

 @param key a pointer to the key to destroy. All properties of '*key' will also be destroyed
 */
void wickr_cipher_key_destroy(wickr_cipher_key_t **key);

/**
 
 @ingroup wickr_cipher
 
 Serialize a cipher key

 @param key the key to serialize to a buffer
 @return a newly allocated buffer containing properties of 'key' in the following format:
    | CIPHER_ID | KEY_DATA |
 */
wickr_buffer_t *wickr_cipher_key_serialize(const wickr_cipher_key_t *key);

/**
 
 @ingroup wickr_cipher
 
 Create a cipher key from serialized bytes

 @param buffer a buffer created by 'wickr_cipher_key_serialize'
 @return cipher key parsed from 'buffer'. This function makes a copy of all bytes as it is parsing,
 so the resulting cipher key owns its properties. Returns NULL on parsing failure
 */
wickr_cipher_key_t *wickr_cipher_key_from_buffer(const wickr_buffer_t *buffer);

#ifdef __cplusplus
}
#endif

#endif /* cipher_h */
