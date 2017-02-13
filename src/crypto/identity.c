
#include "identity.h"
#include "memory.h"

wickr_identity_t *wickr_identity_create(wickr_identity_type type, wickr_buffer_t *identifier, wickr_ec_key_t *sig_key, wickr_ecdsa_result_t *signature)
{
    if (!identifier || identifier->length != IDENTIFIER_LEN || !sig_key) {
        return NULL;
    }
    
    wickr_identity_t *new_identity = wickr_alloc_zero(sizeof(wickr_identity_t));
    
    if (!new_identity) {
        return NULL;
    }
    
    new_identity->type = type;
    new_identity->identifier = identifier;
    new_identity->sig_key = sig_key;
    new_identity->signature = signature;
    
    return new_identity;
}

wickr_ecdsa_result_t *wickr_identity_sign(const wickr_identity_t *identity, const wickr_crypto_engine_t *engine, const wickr_buffer_t *data)
{
    if (!identity || !identity->sig_key->pri_data || !engine || !data) {
        return NULL;
    }
    
    return engine->wickr_crypto_engine_ec_sign(identity->sig_key, data, DIGEST_SHA_512);
}

wickr_identity_t *wickr_node_identity_gen(const wickr_crypto_engine_t *engine, const wickr_identity_t *root_identity)
{
    if (!engine || !root_identity || root_identity->type != IDENTITY_TYPE_ROOT) {
        return NULL;
    }
    
    wickr_ec_key_t *node_sig_key = engine->wickr_crypto_engine_ec_rand_key(engine->default_curve);
    
    if (!node_sig_key) {
        return NULL;
    }
    
    wickr_ecdsa_result_t *node_sig = wickr_identity_sign(root_identity, engine, node_sig_key->pub_data);
    
    if (!node_sig) {
        wickr_ec_key_destroy(&node_sig_key);
        return NULL;
    }
    
    wickr_buffer_t *rand_id = engine->wickr_crypto_engine_crypto_random(IDENTIFIER_LEN);
    
    if (!rand_id) {
        wickr_ec_key_destroy(&node_sig_key);
        wickr_ecdsa_result_destroy(&node_sig);
        return NULL;
    }
    
    wickr_identity_t *node_identity = wickr_identity_create(IDENTITY_TYPE_NODE, rand_id, node_sig_key, node_sig);
    
    if (!node_identity) {
        wickr_ec_key_destroy(&node_sig_key);
        wickr_ecdsa_result_destroy(&node_sig);
        wickr_buffer_destroy(&rand_id);
    }
    
    return node_identity;
}

wickr_identity_t *wickr_identity_copy(const wickr_identity_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_buffer_t *identifier_copy = wickr_buffer_copy(source->identifier);
    
    if (!identifier_copy) {
        return NULL;
    }
    
    wickr_ec_key_t *sig_key_copy = wickr_ec_key_copy(source->sig_key);
    
    if (!sig_key_copy) {
        wickr_buffer_destroy(&identifier_copy);
        return NULL;
    }
    
    wickr_ecdsa_result_t *sig_copy = wickr_ecdsa_result_copy(source->signature);
    
    wickr_identity_t *copy = wickr_identity_create(source->type, identifier_copy, sig_key_copy, sig_copy);
    
    if (!copy) {
        wickr_buffer_destroy(&identifier_copy);
        wickr_ec_key_destroy(&sig_key_copy);
        wickr_ecdsa_result_destroy(&sig_copy);
    }
    
    return copy;
}

void wickr_identity_destroy(wickr_identity_t **identity)
{
    if (!identity || !*identity) {
        return;
    }
    
    wickr_buffer_destroy(&(*identity)->identifier);
    wickr_ec_key_destroy(&(*identity)->sig_key);
    wickr_ecdsa_result_destroy(&(*identity)->signature);
    wickr_free(*identity);
    *identity = NULL;
}

wickr_identity_chain_t *wickr_identity_chain_create(wickr_identity_t *root, wickr_identity_t *node)
{
    if (!root || !node) {
        return NULL;
    }
    
    wickr_identity_chain_t *new_chain = wickr_alloc_zero(sizeof(wickr_identity_chain_t));
    
    if (!new_chain) {
        return NULL;
    }
    
    new_chain->root = root;
    new_chain->node = node;
    new_chain->status = IDENTITY_CHAIN_STATUS_UNKNOWN;
    
    return new_chain;
}

wickr_identity_chain_t *wickr_identity_chain_copy(const wickr_identity_chain_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_identity_t *root_copy = wickr_identity_copy(source->root);
    
    if (!root_copy) {
        return NULL;
    }
    
    wickr_identity_t *node_copy = wickr_identity_copy(source->node);
    
    if (!node_copy) {
        wickr_identity_destroy(&root_copy);
        return NULL;
    }
    
    wickr_identity_chain_t *copy = wickr_identity_chain_create(root_copy, node_copy);
    
    if (!copy) {
        wickr_identity_destroy(&root_copy);
        wickr_identity_destroy(&node_copy);
        return NULL;
    }
    
    copy->status = source->status;
    
    return copy;
}

bool wickr_identity_chain_validate(const wickr_identity_chain_t *chain, const wickr_crypto_engine_t *engine)
{
    if (!chain || !engine) {
        return false;
    }
    
    return engine->wickr_crypto_engine_ec_verify(chain->node->signature, chain->root->sig_key, chain->node->sig_key->pub_data);
}

void wickr_identity_chain_destroy(wickr_identity_chain_t **chain)
{
    if (!chain || !*chain) {
        return;
    }
    
    wickr_identity_destroy(&(*chain)->node);
    wickr_identity_destroy(&(*chain)->root);
    wickr_free(*chain);
    *chain = NULL;
}
