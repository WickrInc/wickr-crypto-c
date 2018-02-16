
#include "eckey.h"
#include "memory.h"

wickr_ec_key_t *wickr_ec_key_create(wickr_ec_curve_t curve, wickr_buffer_t *pub_data, wickr_buffer_t *pri_data)
{
    if (!pub_data) {
        return NULL;
    }
    
    wickr_ec_key_t *new_key = wickr_alloc_zero(sizeof(wickr_ec_key_t));
    new_key->curve = curve;
    new_key->pub_data = pub_data;
    new_key->pri_data = pri_data;
    
    return new_key;
}

wickr_ec_key_t *wickr_ec_key_copy(const wickr_ec_key_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_buffer_t *pub_key_copy = wickr_buffer_copy(source->pub_data);
    
    if (!pub_key_copy) {
        return NULL;
    }
    
    wickr_buffer_t *pri_key_copy = NULL;
    
    if (source->pri_data) {
        pri_key_copy = wickr_buffer_copy(source->pri_data);
        
        if (!pri_key_copy) {
            wickr_buffer_destroy(&pub_key_copy);
            return NULL;
        }
    }
    
    return wickr_ec_key_create(source->curve, pub_key_copy, pri_key_copy);
}

const wickr_ec_curve_t *wickr_ec_curve_find(uint8_t identifier)
{
    switch (identifier) {
        case EC_CURVE_ID_NIST_P521:
            return &EC_CURVE_NIST_P521;
        default:
            return NULL;
    }
}

void wickr_ec_key_destroy(wickr_ec_key_t **key)
{
    if (!key || !*key) {
        return;
    }
    
    wickr_buffer_destroy_zero(&(*key)->pub_data);
    wickr_buffer_destroy_zero(&(*key)->pri_data);
    wickr_free(*key);
    *key = NULL;
}
