
#include "ecdh.h"
#include "memory.h"

wickr_ecdh_params_t *wickr_ecdh_params_create(wickr_ec_key_t *local_key, wickr_ec_key_t *peer_key, wickr_kdf_meta_t *kdf_info)
{
    if (!local_key || !peer_key) {
        return NULL;
    }
    
    wickr_ecdh_params_t *new_params = wickr_alloc_zero(sizeof(wickr_ecdh_params_t));
    
    if (!new_params) {
        return NULL;
    }
    
    new_params->local_key = local_key;
    new_params->peer_key = peer_key;
    new_params->kdf_info = kdf_info;
    
    if (!wickr_ecdh_params_are_valid(new_params)) {
        wickr_ecdh_params_destroy(&new_params);
        return NULL;
    }
    
    return new_params;
}

wickr_ecdh_params_t *wickr_ecdh_params_copy(const wickr_ecdh_params_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_ec_key_t *local_key = wickr_ec_key_copy(source->local_key);
    
    if (!local_key) {
        return NULL;
    }
    
    wickr_ec_key_t *peer_key = wickr_ec_key_copy(source->peer_key);
    
    if (!peer_key) {
        wickr_ec_key_destroy(&local_key);
        return NULL;
    }
    
    wickr_kdf_meta_t *kdf_info = wickr_kdf_meta_copy(source->kdf_info);
    
    if (!kdf_info) {
        wickr_ec_key_destroy(&local_key);
        wickr_ec_key_destroy(&peer_key);
        return NULL;
    }
    
    return wickr_ecdh_params_create(local_key, peer_key, kdf_info);
}

void wickr_ecdh_params_destroy(wickr_ecdh_params_t **params)
{
    if (!params || !*params) {
        return;
    }
    
    wickr_ec_key_destroy(&(*params)->local_key);
    wickr_ec_key_destroy(&(*params)->peer_key);
    wickr_kdf_meta_destroy(&(*params)->kdf_info);
    
    wickr_free(*params);
    *params = NULL;
}

bool wickr_ecdh_params_are_valid(const wickr_ecdh_params_t *params)
{
    if (!params) {
        return false;
    }
    
    if (!params->peer_key->pub_data) {
        return false;
    }
    
    if (!params->local_key->pri_data || !params->local_key->pub_data) {
        return false;
    }
    
    if (!params->kdf_info) {
        return false;
    }
    
    return true;
}
