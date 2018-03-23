
#include "private/ephemeral_keypair_priv.h"
#include "private/eckey_priv.h"
#include "private/ecdsa_priv.h"
#include "private/buffer_priv.h"
#include "memory.h"

void wickr_ephemeral_keypair_proto_free(Wickr__Proto__EphemeralKeypair *proto_keypair)
{
    if (!proto_keypair) {
        return;
    }
    
    if (proto_keypair->has_key_signature) {
        wickr_free(proto_keypair->key_signature.data);
    }
    
    wickr_free(proto_keypair);
}

Wickr__Proto__EphemeralKeypair *wickr_ephemeral_keypair_to_proto(const wickr_ephemeral_keypair_t *keypair)
{
    if (!keypair || !keypair->ec_key) {
        return NULL;
    }
    
    Wickr__Proto__EphemeralKeypair *proto_keypair = wickr_alloc_zero(sizeof(Wickr__Proto__EphemeralKeypair));
    
    if (!proto_keypair) {
        return NULL;
    }
    
    wickr__proto__ephemeral_keypair__init(proto_keypair);
    
    proto_keypair->has_ec_key = true;
    proto_keypair->ec_key.data = keypair->ec_key->pub_data->bytes;
    proto_keypair->ec_key.len = keypair->ec_key->pub_data->length;
    
    proto_keypair->has_identifier = true;
    proto_keypair->identifier = keypair->identifier;
    
    if (keypair->signature) {
        
        wickr_buffer_t *signature_buffer = wickr_ecdsa_result_serialize(keypair->signature);
        
        if (!signature_buffer) {
            wickr_ephemeral_keypair_proto_free(proto_keypair);
            return NULL;
        }
        
        proto_keypair->has_key_signature = true;
        
        if (!wickr_buffer_to_protobytes(&proto_keypair->key_signature, signature_buffer)) {
            wickr_buffer_destroy(&signature_buffer);
            wickr_ephemeral_keypair_proto_free(proto_keypair);
            return NULL;
        }
        
        wickr_buffer_destroy(&signature_buffer);
        
    }
    
    return proto_keypair;
}

wickr_ephemeral_keypair_t *wickr_ephemeral_keypair_create_from_proto(const Wickr__Proto__EphemeralKeypair *proto,
                                                                     const wickr_crypto_engine_t *engine)
{
    if (!proto) {
        return NULL;
    }
    
    if (!proto->has_ec_key || !proto->has_identifier) {
        return NULL;
    }
        
    wickr_ec_key_t *ec_key = wickr_ec_key_from_protobytes(proto->ec_key, engine, false);
    
    if (!ec_key) {
        return NULL;
    }
    
    wickr_ecdsa_result_t *signature = NULL;
    
    if (proto->has_key_signature) {
        signature = wickr_ecdsa_result_from_protobytes(proto->key_signature);

        if (!signature) {
            wickr_ec_key_destroy(&ec_key);
            return NULL;
        }
    }
    
    wickr_ephemeral_keypair_t *keypair = wickr_ephemeral_keypair_create(proto->identifier, ec_key, signature);
    
    if (!keypair) {
        wickr_ec_key_destroy(&ec_key);
        wickr_ecdsa_result_destroy(&signature);
    }
    
    return keypair;
}
