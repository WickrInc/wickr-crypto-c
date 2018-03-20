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

#ifndef node_h
#define node_h

#include <stdlib.h>
#include "buffer.h"
#include "ecdsa.h"
#include "eckey.h"
#include "devinfo.h"
#include "crypto_engine.h"
#include "root_keys.h"
#include "identity.h"
#include "ephemeral_keypair.h"
#include "array.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef wickr_array_t wickr_node_array_t;

/**
 @addtogroup wickr_node
 */
    
/**
 
 @ingroup wickr_node
 @struct wickr_node
 
 @brief Represents a message destination at a point in time
 
 A particular root identity may be associated with many different node identities,
 each of which are bound to their root identity (see 'wickr_identity_chain' documentation). The node identity is also associated with a device identifier
 (see 'msg_proto_id' in 'wickr_dev_info') representing the environment the node is executing in. On each send to a particular node, 
 the ephemeral_keypair can be rotated by replacing it with another ephemeral_keypair in the node's pool. 
 The chain of signatures in this node must be verifiable, as it will be checked for validity during message composition via a call to 'wickr_node_verify_signature_chain'
 
 @var wickr_node::dev_id
 msg_proto_id of the 'wickr_dev_info' struct in the executing environment of the node
 @var wickr_node::id_chain
 the current identity chain of the node, representing its root->node relationship hirearchy
 @var wickr_node::ephemeral_keypair 
 the key pair that is currently associated with message key exchange generation for this node
 
 */
struct wickr_node {
    wickr_buffer_t *dev_id;
    wickr_identity_chain_t *id_chain;
    wickr_ephemeral_keypair_t *ephemeral_keypair;
};

typedef struct wickr_node wickr_node_t;

/**
 
 @ingroup wickr_node
 
 Create a node from components

 @param dev_id see 'wickr_node' property documentation
 @param id_chain see 'wickr_node' property documentation
 @param ephemeral_keypair see 'wickr_node' property documentation
 @return a newly allocated node. Takes ownership of the passed inputs
 */
wickr_node_t *wickr_node_create(wickr_buffer_t *dev_id, wickr_identity_chain_t *id_chain, wickr_ephemeral_keypair_t *ephemeral_keypair);

/**
 
 @ingroup wickr_node
 
 Rotate in a new ephemeral key pair for message sending
 
 NOTE: This function DOES NOT ensure that new_keypair is signed properly. To do that, you must call 'wickr_node_verify_signature_chain' after rotation

 @param node the node to rotate 'new_keypair' into
 @param new_keypair the key pair to rotate into place
 @param copy if true, perform a deep copy of 'new_keypair' before rotating
 @return true if the rotation succeeds, false if the copy fails
 */
bool wickr_node_rotate_keypair(wickr_node_t *node, wickr_ephemeral_keypair_t *new_keypair, bool copy);

/**
 
 @ingroup wickr_node
 
 Copy an node
 
 @param source the node to copy
 @return a newly allocated node holding a deep copy of the properties of 'source'
 */
wickr_node_t *wickr_node_copy(const wickr_node_t *source);

/**
 
 @ingroup wickr_node
 
 Destroy a node
 
 @param node a pointer to the node to destroy. All properties of '*node' will also be destroyed
 */
void wickr_node_destroy(wickr_node_t **node);

/**
 
 @ingroup wickr_node
 
 Verify the integrity of the signature chain for a node
 
 In order to be valid, the ephemeral keypair's signature must validate with the id_chain's 'node' public signing key. 
 The id_chain's 'node' signature must validate with the id_chain's 'root' public signing key

 @param node the node to verify
 @param engine a crypto engine capable of verifying EC signatures
 @return true if the chain validates, false if there are any signature validation failures
 */
bool wickr_node_verify_signature_chain(wickr_node_t *node, const wickr_crypto_engine_t *engine);

/**
 
 @ingroup wickr_node
 
 Create an array of nodes

 @param node_count the number of nodes the array should hold
 @return a newly allocated array with enough space to hold 'node_count' nodes
 */
wickr_node_array_t *wickr_node_array_new(uint32_t node_count);

/**
 
 @ingroup wickr_node
 
 Set an item in the node array

 NOTE: 'node' is not copied into the array, ownership is simply transferred to the array
 
 @param array the array to set a node into
 @param index the index to place the node into the array
 @param node the node to place at 'index' in the array
 @return true if the insert succeeds, false if the index is out of range
 */
bool wickr_node_array_set_item(wickr_array_t *array, uint32_t index, wickr_node_t *node);

/**
 
 @ingroup wickr_node
 
 Fetch an item in the node array

 NOTE: a fetched node is not copied out of the array, it is still owned by the array
 
 @param array the array to fetch from
 @param index the index in the array to fetch from
 @return the node at 'index'. NULL if the index is out of bounds
 */
wickr_node_t *wickr_node_array_fetch_item(const wickr_array_t *array, uint32_t index);

/**
 
 @ingroup wickr_node
 
 Make a deep copy of a node array

 @param array the array to copy
 @return a newly allocated wickr_node_array that contains a copy of each element from 'array'
 */
wickr_node_array_t *wickr_node_array_copy(const wickr_node_array_t *array);
    
/**
 
 @ingroup wickr_node
 
 Serialize a node to bytes
 
 @param node the node to serialize
 @return a buffer containing a serialized representation of 'node' or null if serialization fails
 */
wickr_buffer_t *wickr_node_serialize(const wickr_node_t *node);
    
/**
 
 @ingroup wickr_node
 
 Create a node from a buffer that was created with 'wickr_node_serialize'
 
 @param buffer the buffer that contains a serialized representation of a node
 @param engine the crypto engine to use to import the key components of the node
 @return deserialized node or null if the deserialization fails
 */
wickr_node_t *wickr_node_create_from_buffer(const wickr_buffer_t *buffer, const wickr_crypto_engine_t *engine);

/**
 
 @ingroup wickr_node
 
 Destroy a node array

 NOTE: Nodes in the array are not destroyed, only the container array
 
 @param array the array to destroy
 */
void wickr_node_array_destroy(wickr_node_array_t **array);

#ifdef __cplusplus
}
#endif

#endif /* node_h */
