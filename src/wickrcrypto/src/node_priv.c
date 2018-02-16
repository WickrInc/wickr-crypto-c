
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
