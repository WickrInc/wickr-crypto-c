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

#ifndef identity_h
#define identity_h

#include <stdlib.h>
#include "buffer.h"
#include "eckey.h"
#include "ecdsa.h"
#include "crypto_engine.h"
#include "root_keys.h"
#include "fingerprint.h"

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 @addtogroup wickr_identity wickr_identity
 */

/** @ingroup wickr_identity
 Identifiers should be 32 bytes on the Wickr system, this requirement could drop or change in the future 
 */
#define IDENTIFIER_LEN 32


/* Define ROOT and NODE identity types */
typedef enum { IDENTITY_TYPE_ROOT, IDENTITY_TYPE_NODE } wickr_identity_type;

/**
 
 @ingroup wickr_identity
 
 Identity chain status
 
 UNKNOWN - Signature validation has never been attempted on the chain
 VALID - Signature validation has been attempted and has passed on the chain
 INVALID - Signature validation has been attempted and has failed on chain
 
 */
typedef enum { IDENTITY_CHAIN_STATUS_UNKNOWN, IDENTITY_CHAIN_STATUS_VALID, IDENTITY_CHAIN_STATUS_INVALID } wickr_identity_chain_status;

/** 
 
 @ingroup wickr_identity
 @struct wickr_identity
 
 @brief A signing identity on the Wickr system
 
 ROOT - Account level, serves as the root of trust for all nodes associated with it. The root sig_key signs each node to provide authenticity of its ownership
 NODE - Application level identifier, serves as the root of trust for all ephemeral keypairs associated with it, the node is owned / signed by a ROOT node. Nodes are messaging endpoints, owned by a particular root for the purpose of multi-client messaging
 
 Identities are meant to be cached, pinned, and optimally "verified" either out of band, or in band using a feature such as Wickr's "video verification". When verifying a new node identity, the root that was previously cached should be loaded and used to perform the signature validation of the new node. Node identities should also be cached, for the purpose of being able to consistently verify ephemeral keypairs signed by that node as part of generating message key exchanges
 
 @var wickr_identity::type
 the type of identity (NODE OR ROOT)
 @var wickr_identity::identifier
 a system wide unique value for this identity
 @var wickr_identity::sig_key
 the signing key of the identity, will contain private information for your local identity to support signing, and only public information of other identities
 @var wickr_identity::signature 
 the signature of the public 'sig_key', signed by the root private 'sig_key'. NULL if root identity
 
 */
struct wickr_identity {
    wickr_identity_type type;
    wickr_buffer_t *identifier;
    wickr_ec_key_t *sig_key;
    wickr_ecdsa_result_t *signature;
};

typedef struct wickr_identity wickr_identity_t;

/**
 
 @ingroup wickr_identity
 @struct wickr_identity_chain
 Wickr Crypto Identity Chain
 
 @brief Represents a root -> node relationship as well as it's signature status.
 
 @var wickr_identity_chain::status
 current status of the signature validity of the chain. It is determined by validating the signature of the node, by using the public 'sig_key' property of the root
 @var wickr_identity_chain::root
 an identity of type 'IDENTITY_TYPE_ROOT'
 @var wickr_identity_chain::node
 an identity of type 'IDENTITY_TYPE_NODE'
 
 */
struct wickr_identity_chain {
    wickr_identity_chain_status status;
    wickr_identity_t *root;
    wickr_identity_t *node;
};

typedef struct wickr_identity_chain wickr_identity_chain_t;

/**
 
 @ingroup wickr_identity
 
 Create an identity from components

 @param type see 'wickr_identity' property documentation
 @param identifier see 'wickr_identity' property documentation
 @param sig_key see 'wickr_identity' property documentation
 @param signature see 'wickr_identity' property documentation
 @return a newly allocated identity that takes ownership of the passed inputs
 */
wickr_identity_t *wickr_identity_create(wickr_identity_type type, wickr_buffer_t *identifier, wickr_ec_key_t *sig_key, wickr_ecdsa_result_t *signature);

/**
 
 @ingroup wickr_identity
 
 Sign provided data using an identity signing key

 @param identity the identity to use for signing
 @param engine a crypto engine supporting signatures using the identity's signing key
 @param data buffer to sign
 @return an ECDSA result containing a signature of 'data' using the 'sig_key' property of 'identity'. NULL if the provided identity does not contain a private signing key
 */
wickr_ecdsa_result_t *wickr_identity_sign(const wickr_identity_t *identity, const wickr_crypto_engine_t *engine, const wickr_buffer_t *data);

/**
 
 @ingroup wickr_identity
 
 Generate a new random node identity, given a root identity

 @param engine a crypto engine supporting random Elliptic Curve Key generation
 @param root_identity a root identity that supports generating signatures with a private signing key
 @return a newly allocated node identity signing by root identity 'root_identity'. The 'identifier' property of the node is generated at random to be 'IDENTIFIER_LEN' in length (currently 32 bytes). NULL if root_identity is not a root, or it does not contain a private signing key
 */
wickr_identity_t *wickr_node_identity_gen(const wickr_crypto_engine_t *engine, const wickr_identity_t *root_identity);

/**
 
 @ingroup wickr_identity
 
 Copy an identity
 
 @param source the identity to copy
 @return a newly allocated identity holding a deep copy of the properties of 'source'
 */
wickr_identity_t *wickr_identity_copy(const wickr_identity_t *source);

/**
 
 @ingroup wickr_identity
 
 Destroy an identity
 
 @param identity a pointer to the identity to destroy. All properties of '*identity' will also be destroyed
 */
void wickr_identity_destroy(wickr_identity_t **identity);
    
/**
 
 @ingroup wickr_identity
 
 Serialize an identity to bytes
 
 @param identity the identity to serialize
 @return a buffer containing a serialized representation of 'identity' or null if serialization fails
 */
wickr_buffer_t *wickr_identity_serialize(const wickr_identity_t *identity);
    


/**
 
 @ingroup wickr_identity
 
 Create an identity from a buffer that was created with 'wickr_identity_serialize'
 
 @param buffer the buffer that contains a serialized representation of an identity
 @param engine the crypto engine to use to import the key components of the identity
 @return deserialized identity or null if the deserialization fails
 */
wickr_identity_t *wickr_identity_create_from_buffer(const wickr_buffer_t *buffer, const wickr_crypto_engine_t *engine);

/**
 
 @ingroup wickr_identity
 
 A unique fingerprint representing the identifier and public signing key of this identity. See 'fingerprint.h'
 
 @param identity the identity to get a unique fingerprint of
 @param engine the crypto engine to use for underlying hash operations
 @return a unique fingerprint currently calculated as SHA512(identifier || sig_pub->pub_data)
 */
wickr_fingerprint_t *wickr_identity_get_fingerprint(const wickr_identity_t *identity,
                                                    wickr_crypto_engine_t engine);


/**
 
 @ingroup wickr_identity
 
 A fingerprint that is unique between identity and remote_identity
 
 @param identity the identity to get a bilateral fingerprint of
 @param remote_identity the other party included in the fingerprint
 @param engine engine the crypto engine to use for underlying hash operations
 @return a bilateral fingerprint of (identity,remote_identity) or (remote_identity,identity)
 calculated using SHA512(fingerprint(identity) || fingerprint(remote_identity)).
*/
 
wickr_fingerprint_t *wickr_identity_get_bilateral_fingerprint(const wickr_identity_t *identity,
                                                              const wickr_identity_t *remote_identity,
                                                              wickr_crypto_engine_t engine);
    
/**
 
 @ingroup wickr_identity_chain
 
 Serialize an identity chain to bytes
 
 @param identity_chain the identity to serialize
 @return a buffer containing a serialized representation of 'identity_chain' or null if serialization fails
 */
wickr_buffer_t *wickr_identity_chain_serialize(const wickr_identity_chain_t *identity_chain);

/**
 
 @ingroup wickr_identity_chain
 
 Create an identity chain from a buffer that was created with 'wickr_identity_chain_serialize'
 
 @param buffer the buffer that contains a serialized representation of an identity chain
 @param engine the crypto engine to use to import the key components of the identity chain
 @return deserialized identity chain or null if the deserialization fails
 */
wickr_identity_chain_t *wickr_identity_chain_create_from_buffer(const wickr_buffer_t *buffer, const wickr_crypto_engine_t *engine);

/**
 
 @ingroup wickr_identity
 
 Create an identity chain from components

 @param root see 'wickr_identity_chain' property documentation
 @param node see 'wickr_identity_chain' property documentation
 @return a newly allocated identity chain that takes ownership of the passed inputs
 */
wickr_identity_chain_t *wickr_identity_chain_create(wickr_identity_t *root, wickr_identity_t *node);

/**
 
 @ingroup wickr_identity
 
 Copy an identity chain
 
 @param source the identity chain to copy
 @return a newly allocated identity chain holding a deep copy of the properties of 'source'
 */
wickr_identity_chain_t *wickr_identity_chain_copy(const wickr_identity_chain_t *source);

/**
 
 @ingroup wickr_identity
 
 Verify the validity of an identity chain

 @param chain the chain to validate
 @param engine a crypto engine that supports verifying signatures
 @return true if the 'signature' of the 'node' property of 'chain' can be properly verified with the public 'sig_key' from the 'root' property of 'chain'
 */
bool wickr_identity_chain_validate(const wickr_identity_chain_t *chain, const wickr_crypto_engine_t *engine);

/**
 
 @ingroup wickr_identity
 
 Destroy an identity chain
 
 @param chain a pointer to the identity chain to destroy. All properties of '*chain' will also be destroyed
 */
void wickr_identity_chain_destroy(wickr_identity_chain_t **chain);

#ifdef __cplusplus
}
#endif

#endif /* identity_h */
