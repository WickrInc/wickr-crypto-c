
#include "identity_priv.h"
#include "protobuf_util.h"
#include <string.h>
#include "memory.h"

void wickr_identity_proto_free(Wickr__Proto__Identity *proto)
{
    if (!proto) {
        return;
    }
    
    if (proto->has_signature) {
        wickr_free(proto->signature.data);
    }
    wickr_free(proto);
}

void wickr_identity_chain_proto_free(Wickr__Proto__IdentityChain *proto)
{
    if (!proto) {
        return;
    }
    wickr_identity_proto_free(proto->node);
    wickr_identity_proto_free(proto->root);
    wickr_free(proto);
}

Wickr__Proto__Identity *wickr_identity_to_proto(const wickr_identity_t *identity)
{
    if (!identity) {
        return NULL;
    }
    
    Wickr__Proto__Identity *proto = wickr_alloc_zero(sizeof(Wickr__Proto__Identity));
    wickr__proto__identity__init(proto);
    
    proto->has_type = true;
    proto->has_sig_key = true;
    proto->has_identifier = true;
    
    proto->type = identity->type == IDENTITY_TYPE_ROOT ? WICKR__PROTO__IDENTITY__TYPE__IDENTITY_TYPE_ROOT : WICKR__PROTO__IDENTITY__TYPE__IDENTITY_TYPE_NODE;
    
    proto->identifier.data = identity->identifier->bytes;
    proto->identifier.len = identity->identifier->length;
    

    proto->sig_key.data = identity->sig_key->pub_data->bytes;
    proto->sig_key.len = identity->sig_key->pub_data->length;
    
    if (identity->type == IDENTITY_TYPE_NODE) {
        wickr_buffer_t *signature_buffer = wickr_ecdsa_result_serialize(identity->signature);
        
        if (!signature_buffer) {
            wickr_identity_proto_free(proto);
            return NULL;
        }
        
        proto->signature.data = wickr_alloc_zero(signature_buffer->length);
        
        if (!proto->signature.data) {
            wickr_buffer_destroy(&signature_buffer);
            wickr_identity_proto_free(proto);
            return NULL;
        }
        
        proto->signature.len = signature_buffer->length;
        proto->has_signature = true;
        
        memcpy(proto->signature.data, signature_buffer->bytes, signature_buffer->length);
        wickr_buffer_destroy(&signature_buffer);
    }
    
    
    return proto;
}

wickr_identity_t *wickr_identity_create_from_proto(const Wickr__Proto__Identity *proto_identity,
                                                   const wickr_crypto_engine_t *engine)
{
    if (!proto_identity || !proto_identity->has_identifier ||
        !proto_identity->has_sig_key || !proto_identity->has_type ||
        !engine) {
        return NULL;
    }
    
    wickr_buffer_t *id_buffer = wickr_buffer_from_protobytes(proto_identity->identifier);
    
    if (!id_buffer) {
        return NULL;
    }
    
    wickr_ec_key_t *sig_key = wickr_ec_key_from_protobytes(proto_identity->sig_key, engine, false);
    
    if (!sig_key) {
        wickr_buffer_destroy(&id_buffer);
        return NULL;
    }
    
    wickr_ecdsa_result_t *signature = NULL;
    
    if (proto_identity->has_signature) {
        wickr_buffer_t temp = { proto_identity->signature.len, proto_identity->signature.data };
        signature = wickr_ecdsa_result_create_from_buffer(&temp);
        
        if (!signature) {
            wickr_buffer_destroy(&id_buffer);
            wickr_ec_key_destroy(&sig_key);
            return NULL;
        }
    }
    
    wickr_identity_type type = proto_identity->type == WICKR__PROTO__IDENTITY__TYPE__IDENTITY_TYPE_NODE ? IDENTITY_TYPE_NODE : IDENTITY_TYPE_ROOT;
    
    wickr_identity_t *identity = wickr_identity_create(type, id_buffer, sig_key, signature);
    
    if (!identity) {
        wickr_buffer_destroy(&id_buffer);
        wickr_ec_key_destroy(&sig_key);
        wickr_ecdsa_result_destroy(&signature);
    }
    
    return identity;
}

Wickr__Proto__IdentityChain *wickr_identity_chain_to_proto(const wickr_identity_chain_t *chain)
{
    if (!chain) {
        return NULL;
    }
    
    Wickr__Proto__Identity *root = wickr_identity_to_proto(chain->root);
    
    if (!root) {
        return NULL;
    }
    
    Wickr__Proto__Identity *node = wickr_identity_to_proto(chain->node);
    
    if (!node) {
        wickr_identity_proto_free(root);
        return NULL;
    }
    
    Wickr__Proto__IdentityChain *proto_chain = wickr_alloc_zero(sizeof(Wickr__Proto__IdentityChain));
    wickr__proto__identity_chain__init(proto_chain);
    
    if (!proto_chain) {
        wickr_identity_proto_free(root);
        wickr_identity_proto_free(node);
        return NULL;
    }
    
    proto_chain->node = node;
    proto_chain->root = root;
    
    return proto_chain;
}

wickr_identity_chain_t *wickr_identity_chain_create_from_proto(const Wickr__Proto__IdentityChain *proto_chain,
                                                          const wickr_crypto_engine_t *engine)
{
    if (!proto_chain || !engine) {
        return NULL;
    }
    
    wickr_identity_t *root = wickr_identity_create_from_proto(proto_chain->root, engine);
    
    if (!root) {
        return NULL;
    }
    
    wickr_identity_t *node = wickr_identity_create_from_proto(proto_chain->node, engine);
    
    if (!node) {
        wickr_identity_destroy(&root);
        return NULL;
    }
    
    wickr_identity_chain_t *chain = wickr_identity_chain_create(root, node);
    
    if (!chain) {
        wickr_identity_destroy(&root);
        wickr_identity_destroy(&node);
        return NULL;
    }
    
    return chain;
}
