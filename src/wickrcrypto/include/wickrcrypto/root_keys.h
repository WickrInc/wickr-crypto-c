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

#ifndef wickr_root_keys_h
#define wickr_root_keys_h

#include <stdlib.h>
#include "buffer.h"
#include "eckey.h"
#include "crypto_engine.h"
#include "storage.h"
#include "devinfo.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup wickr_root_keys */

/**
 @ingroup wickr_root_keys
 @struct wickr_root_keys
 @brief Root level crypto keys for signatures, local encryption, and remote encryption
 
 @var wickr_root_keys::node_signature_root
 signature key used to sign nodes
 @var wickr_root_keys::node_storage_root
 the root storage key used to derive local storage key for nodes
 @var wickr_root_keys::remote_storage_root
 the root storage key used to encrypt remote content for all nodes
 */
struct wickr_root_keys {
    wickr_ec_key_t *node_signature_root;
    wickr_cipher_key_t *node_storage_root;
    wickr_cipher_key_t *remote_storage_root;
};

typedef struct wickr_root_keys wickr_root_keys_t;

/**
 @ingroup wickr_root_keys
 
 Create a root key set from components

 @param node_signature_root see 'wickr_root_keys' property documentation
 @param node_storage_root see 'wickr_root_keys' property documentation
 @param remote_storage_root see 'wickr_root_keys' property documentation
 @return a newly allocated root key set. Takes ownership of the passed inputs
 */
wickr_root_keys_t *wickr_root_keys_create(wickr_ec_key_t *node_signature_root, wickr_cipher_key_t *node_storage_root,
                                          wickr_cipher_key_t *remote_storage_root);

/**
 @ingroup wickr_root_keys

 Generate a random set of root keys
 
 @param engine a crypto engine supporting random EC and cipher key generation
 @return a random set of root keys
 */
wickr_root_keys_t *wickr_root_keys_generate(const wickr_crypto_engine_t *engine);

/**
 @ingroup wickr_root_keys
 
 Create a root key set from the serialized output of 'wickr_root_keys_serialize'

 @param engine a crypto engine to validate the decoded EC keys
 @param buffer a buffer containing serialized root keys
 @return a root key set parsed out of buffer, or NULL if parsing fails
 */
wickr_root_keys_t *wickr_root_keys_create_from_buffer(const wickr_crypto_engine_t *engine, const wickr_buffer_t *buffer);

/**
 @ingroup wickr_root_keys
 Serialize root keys into a buffer

 @param keys the keys to serialize
 @return a buffer containing serialized root keys as a protocol buffer object
    
 */
wickr_buffer_t *wickr_root_keys_serialize(const wickr_root_keys_t *keys);

/**
 @ingroup wickr_root_keys
 Serialize and encrypt root keys

 @param keys the keys to serialize and encrypt
 @param engine a crypto engine capable of encrypting data using 'export_key'
 @param export_key the key to use for encryption of the serialized keys
 @return a cipher result of serialized 'keys' encrypted with 'export_key'
 */
wickr_cipher_result_t *wickr_root_keys_export(const wickr_root_keys_t *keys, const wickr_crypto_engine_t *engine, const wickr_cipher_key_t *export_key);

/**
 @ingroup wickr_root_keys
 
 Convert a root key set into a storage key set for a local device
 
 Currently the local storage key is created by taking SHA256(keys->node_storage_root || dev_info->system_salt)

 @param keys the keys to convert
 @param engine a crypto engine to use for conversion
 @param dev_info the device to localize the keys to
 @return a set of storage keys bound to 'dev_info'
 */
wickr_storage_keys_t *wickr_root_keys_localize(const wickr_root_keys_t *keys, const wickr_crypto_engine_t *engine, const wickr_dev_info_t *dev_info);

/**
 
 @ingroup wickr_root_keys
 
 Copy a root key set
 
 @param source the root key set to copy
 @return a newly allocated root key set holding a deep copy of the properties of 'source'
 */
wickr_root_keys_t *wickr_root_keys_copy(const wickr_root_keys_t *source);

/**
 @ingroup wickr_root_keys
 
 Destroy a root key set
 
 @param keys a pointer to a root key set to destroy. Will destroy the sub properties of '*keys' as well
 */
void wickr_root_keys_destroy(wickr_root_keys_t **keys);

#ifdef __cplusplus
}
#endif

#endif /* wickr_root_keys_h */
