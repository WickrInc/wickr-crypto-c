
#include "private/node_priv.h"
#include "private/identity_priv.h"
#include "private/ephemeral_keypair_priv.h"
#include "private/identity_priv.h"
#include "private/buffer_priv.h"

#include "memory.h"

void wickr_node_proto_free(Wickr__Proto__Node *proto_node)
{
    if (!proto_node) {
        return;
    }
    
    wickr_identity_chain_proto_free(proto_node->id_chain);
    wickr_ephemeral_keypair_proto_free(proto_node->ephemeral_keypair);
    wickr_free(proto_node);
}

Wickr__Proto__Node *wickr_node_to_proto(const wickr_node_t *node)
{
    if (!node || !node->dev_id) {
        return NULL;
    }
    
    Wickr__Proto__EphemeralKeypair *ephemeral_keypair = wickr_ephemeral_keypair_to_proto(node->ephemeral_keypair);
    
    if (node->ephemeral_keypair && !ephemeral_keypair) {
        return NULL;
    }
    
    Wickr__Proto__IdentityChain *identity_chain = wickr_identity_chain_to_proto(node->id_chain);
    
    if (!identity_chain) {
        wickr_ephemeral_keypair_proto_free(ephemeral_keypair);
        return NULL;
    }
    
    Wickr__Proto__Node *proto_node = wickr_alloc_zero(sizeof(Wickr__Proto__Node));
    
    if (!proto_node) {
        wickr_ephemeral_keypair_proto_free(ephemeral_keypair);
        return NULL;
    }
    
    wickr__proto__node__init(proto_node);
    
    proto_node->has_devid = true;
    proto_node->devid.data = node->dev_id->bytes;
    proto_node->devid.len = node->dev_id->length;
    proto_node->ephemeral_keypair = ephemeral_keypair;
    proto_node->id_chain = identity_chain;
    
    return proto_node;
}

wickr_node_t *wickr_node_create_from_proto(const Wickr__Proto__Node *proto, const wickr_crypto_engine_t *engine)
{
    if (!proto) {
        return NULL;
    }
    
    if (!proto->has_devid) {
        return NULL;
    }
    
    wickr_buffer_t *dev_id = wickr_buffer_from_protobytes(proto->devid);
    
    if (!dev_id) {
        return NULL;
    }
    
    wickr_identity_chain_t *id_chain = wickr_identity_chain_create_from_proto(proto->id_chain, engine);
    
    if (!id_chain) {
        wickr_buffer_destroy(&dev_id);
        return NULL;
    }
    
    wickr_ephemeral_keypair_t *keypair = NULL;
    
    if (proto->ephemeral_keypair) {
        keypair = wickr_ephemeral_keypair_create_from_proto(proto->ephemeral_keypair, engine);
        
        if (!keypair) {
            wickr_buffer_destroy(&dev_id);
            wickr_identity_chain_destroy(&id_chain);
            return NULL;
        }
    }
    
    wickr_node_t *node = wickr_node_create(dev_id, id_chain, keypair);
    
    if (!node) {
        wickr_buffer_destroy(&dev_id);
        wickr_identity_chain_destroy(&id_chain);
        wickr_ephemeral_keypair_destroy(&keypair);
    }
    
    return node;
}

wickr_buffer_t *wickr_node_make_status_cache(const wickr_node_t *node,
                                             const wickr_crypto_engine_t *engine)
{
    if (!node || !engine) {
        return NULL;
    }
    
    if (!node->ephemeral_keypair ||
        !node->id_chain ||
        !node->ephemeral_keypair->ec_key ||
        !node->ephemeral_keypair->signature ||
        !node->id_chain->_status_cache) {
        return NULL;
    }
    
    uint8_t status_int = (uint8_t)node->status;
    wickr_buffer_t status_buffer =  { .length = sizeof(uint8_t), .bytes = &status_int };
    
    wickr_buffer_t *buffers[] = {
        node->ephemeral_keypair->ec_key->pub_data,
        node->ephemeral_keypair->signature->sig_data,
        &status_buffer
    };
    
    wickr_buffer_t *concat_buffer = wickr_buffer_concat_multi(buffers, BUFFER_ARRAY_LEN(buffers));
    
    if (!concat_buffer) {
        return NULL;
    }
    
    wickr_buffer_t *cache_buffer = engine->wickr_crypto_engine_digest(concat_buffer, NULL, DIGEST_SHA_512);
    wickr_buffer_destroy(&concat_buffer);
    
    return cache_buffer;
}

bool wickr_node_has_valid_cache(const wickr_node_t *node,
                                const wickr_crypto_engine_t *engine)
{
    if (!node || !engine || !node->_status_cache) {
        return false;
    }
    
    /* If the underlying identity chain isn't valid, we need to return false to ensure it is recalculated */
    if (!wickr_identity_chain_has_valid_cache(node->id_chain, engine)) {
        return false;
    }
    
    wickr_buffer_t *current_cache_value = wickr_node_make_status_cache(node, engine);
    
    /* If the cache value has changed, it is no longer valid */
    bool has_valid_cache = wickr_buffer_is_equal(current_cache_value, node->_status_cache, NULL);
    wickr_buffer_destroy(&current_cache_value);
    
    return has_valid_cache;
}

void wickr_node_update_status_cache(wickr_node_t *node, const wickr_crypto_engine_t *engine)
{
    wickr_buffer_destroy(&node->_status_cache);
    node->_status_cache = wickr_node_make_status_cache(node, engine);
}

