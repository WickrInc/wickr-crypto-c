
#include "ephemeral_keypair.h"
#include "private/ephemeral_keypair_priv.h"
#include "memory.h"

wickr_ephemeral_keypair_t *wickr_ephemeral_keypair_create(uint64_t identifier, wickr_ec_key_t *ec_key, wickr_ecdsa_result_t *signature)
{
    if (!ec_key) {
        return NULL;
    }
    
    wickr_ephemeral_keypair_t *new_keypair = wickr_alloc_zero(sizeof(wickr_ephemeral_keypair_t));
    
    if (!new_keypair) {
        return NULL;
    }
    
    new_keypair->ec_key = ec_key;
    new_keypair->identifier = identifier;
    new_keypair->signature = signature;
    
    return new_keypair;
}

wickr_ephemeral_keypair_t *wickr_ephemeral_keypair_generate_identity(const wickr_crypto_engine_t *engine, uint64_t identifier, const wickr_identity_t *identity)
{
    wickr_ec_key_t *rnd_key = engine->wickr_crypto_engine_ec_rand_key(engine->default_curve);
    
    if (!rnd_key) {
        return NULL;
    }
    
    wickr_ecdsa_result_t *signature = wickr_identity_sign(identity, engine, rnd_key->pub_data);
    
    if (!signature) {
        wickr_ec_key_destroy(&rnd_key);
        return NULL;
    }
    
    wickr_ephemeral_keypair_t *new_key = wickr_ephemeral_keypair_create(identifier, rnd_key, signature);
    
    if (!new_key) {
        wickr_ec_key_destroy(&rnd_key);
        wickr_ecdsa_result_destroy(&signature);
    }
    
    return new_key;
}

void wickr_ephemeral_keypair_make_public(const wickr_ephemeral_keypair_t *keypair)
{
    wickr_buffer_destroy_zero(&keypair->ec_key->pri_data);
}

wickr_ephemeral_keypair_t *wickr_ephemeral_keypair_copy(const wickr_ephemeral_keypair_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_ec_key_t *keypair_copy = wickr_ec_key_copy(source->ec_key);
    
    if (!keypair_copy) {
        return NULL;
    }
    
    wickr_ecdsa_result_t *signature_copy = wickr_ecdsa_result_copy(source->signature);
    
    if (source->signature && !signature_copy) {
        wickr_ec_key_destroy(&keypair_copy);
        return NULL;
    }
    
    wickr_ephemeral_keypair_t *eph_keypair_copy = wickr_ephemeral_keypair_create(source->identifier, keypair_copy, signature_copy);
    
    if (!eph_keypair_copy) {
        wickr_ec_key_destroy(&keypair_copy);
        wickr_ecdsa_result_destroy(&signature_copy);
    }
    
    return eph_keypair_copy;
}

bool wickr_ephemeral_keypair_verify_owner(const wickr_ephemeral_keypair_t *keypair, const wickr_crypto_engine_t *engine, const wickr_identity_t *owner)
{
    if (!keypair || !engine || !owner) {
        return false;
    }
    
    return engine->wickr_crypto_engine_ec_verify(keypair->signature, owner->sig_key, keypair->ec_key->pub_data);
}

void wickr_ephemeral_keypair_destroy(wickr_ephemeral_keypair_t **keypair)
{
    if (!keypair || !*keypair) {
        return;
    }
    
    wickr_ec_key_destroy(&(*keypair)->ec_key);
    wickr_ecdsa_result_destroy(&(*keypair)->signature);
    wickr_free(*keypair);
    *keypair = NULL;
}

wickr_buffer_t *wickr_ephemeral_keypair_serialize(const wickr_ephemeral_keypair_t *keypair)
{
    if (!keypair) {
        return NULL;
    }
    
    Wickr__Proto__EphemeralKeypair *proto_keypair = wickr_ephemeral_keypair_to_proto(keypair);
    
    if (!proto_keypair) {
        return NULL;
    }
    
    size_t packed_size = wickr__proto__ephemeral_keypair__get_packed_size(proto_keypair);
    
    wickr_buffer_t *packed_buffer = wickr_buffer_create_empty(packed_size);
    
    if (!packed_buffer) {
        wickr_ephemeral_keypair_proto_free(proto_keypair);
        return NULL;
    }
    
    wickr__proto__ephemeral_keypair__pack(proto_keypair, packed_buffer->bytes);
    wickr_ephemeral_keypair_proto_free(proto_keypair);
    
    return packed_buffer;
}

wickr_ephemeral_keypair_t *wickr_ephemeral_keypair_create_from_buffer(const wickr_buffer_t *buffer, const wickr_crypto_engine_t *engine)
{
    if (!buffer) {
        return NULL;
    }
    
    Wickr__Proto__EphemeralKeypair *proto_keypair = wickr__proto__ephemeral_keypair__unpack(NULL, buffer->length, buffer->bytes);
    
    if (!proto_keypair) {
        return NULL;
    }
    
    wickr_ephemeral_keypair_t *return_keypair = wickr_ephemeral_keypair_create_from_proto(proto_keypair, engine);
    wickr__proto__ephemeral_keypair__free_unpacked(proto_keypair, NULL);
    
    return return_keypair;
}
