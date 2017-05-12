
#include "node.h"
#include "memory.h"

#define NODE_ARRAY_TYPE_ID 1

wickr_node_t *wickr_node_create(wickr_buffer_t *dev_id, wickr_identity_chain_t *id_chain, wickr_ephemeral_keypair_t *ephemeral_keypair)
{
    if (!dev_id || !id_chain) {
        return NULL;
    }
    
    wickr_node_t *new_node = wickr_alloc_zero(sizeof(wickr_node_t));
    
    if (!new_node) {
        return NULL;
    }
    
    new_node->dev_id = dev_id;
    new_node->id_chain = id_chain;
    new_node->ephemeral_keypair = ephemeral_keypair;
    
    return new_node;
}

bool wickr_node_rotate_keypair(wickr_node_t *node, wickr_ephemeral_keypair_t *new_keypair, bool copy)
{
    if (!node || !new_keypair) {
        return false;
    }
    
    wickr_ephemeral_keypair_destroy(&node->ephemeral_keypair);
    
    if (copy) {
        wickr_ephemeral_keypair_t *copy_keypair = wickr_ephemeral_keypair_copy(new_keypair);
        if (!copy_keypair) {
            return false;
        }
        node->ephemeral_keypair = copy_keypair;
    }
    else {
        node->ephemeral_keypair = new_keypair;
    }
    
    return true;
}

bool wickr_node_verify_signature_chain(wickr_node_t *node, const wickr_crypto_engine_t *engine)
{
    
    /* If the current id_chain status is unknown, we have never tried to do a validation and must do it now before continuing */
    if (node->id_chain->status == IDENTITY_CHAIN_STATUS_UNKNOWN) {
        bool is_valid = wickr_identity_chain_validate(node->id_chain, engine);
        node->id_chain->status = is_valid ? IDENTITY_CHAIN_STATUS_VALID : IDENTITY_CHAIN_STATUS_INVALID;
    }
    
    /* If the id_chain status is invalid, then return false without continuing */
    if (node->id_chain->status == IDENTITY_CHAIN_STATUS_INVALID) {
        return false;
    }
    
    /* If the key pair ownership can't be verified by the node signature key in the id_chain, return false */
    if (!wickr_ephemeral_keypair_verify_owner(node->ephemeral_keypair, engine, node->id_chain->node)) {
        return false;
    }
    
    return true;
}

wickr_node_t *wickr_node_copy(const wickr_node_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_buffer_t *dev_id_copy = wickr_buffer_copy(source->dev_id);
    
    if (!dev_id_copy) {
        return NULL;
    }
    
    wickr_identity_chain_t *id_chain_copy = wickr_identity_chain_copy(source->id_chain);
    
    if (!id_chain_copy) {
        wickr_buffer_destroy(&dev_id_copy);
        return NULL;
    }
    
    wickr_ephemeral_keypair_t *keypair_copy = wickr_ephemeral_keypair_copy(source->ephemeral_keypair);
    
    if (!keypair_copy && source->ephemeral_keypair) {
        wickr_buffer_destroy(&dev_id_copy);
        wickr_identity_chain_destroy(&id_chain_copy);
        return NULL;
    }
    
    wickr_node_t *node_copy = wickr_node_create(dev_id_copy, id_chain_copy, keypair_copy);
    
    if (!node_copy) {
        wickr_buffer_destroy(&dev_id_copy);
        wickr_identity_chain_destroy(&id_chain_copy);
        wickr_ephemeral_keypair_destroy(&keypair_copy);
    }
    
    return node_copy;
}

void wickr_node_destroy(wickr_node_t **node)
{
    if (!node || !*node) {
        return;
    }
    
    wickr_buffer_destroy(&(*node)->dev_id);
    wickr_identity_chain_destroy(&(*node)->id_chain);
    wickr_ephemeral_keypair_destroy(&(*node)->ephemeral_keypair);
    wickr_free(*node);
    *node = NULL;
}

wickr_node_array_t *wickr_node_array_new(uint32_t node_count)
{
    return wickr_array_new(node_count, NODE_ARRAY_TYPE_ID, (wickr_array_copy_func)wickr_node_copy,
                           (wickr_array_destroy_func)wickr_node_destroy);
}

bool wickr_node_array_set_item(wickr_array_t *array, uint32_t index, wickr_node_t *node)
{
    return wickr_array_set_item(array, index, node, false);
}

wickr_node_t *wickr_node_array_fetch_item(const wickr_array_t *array, uint32_t index)
{
    return wickr_array_fetch_item(array, index, false);
}

wickr_node_array_t *wickr_node_array_copy(const wickr_node_array_t *array)
{
    return wickr_array_copy(array, true);
}

void wickr_node_array_destroy(wickr_node_array_t **array)
{
    if (!array || !*array) {
        return;
    }
    
    wickr_array_destroy(array, false);
}
