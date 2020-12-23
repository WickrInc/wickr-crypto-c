
#include "kyber_key.h"
#include "memory.h"

const wickr_kyber_mode_t *wickr_kyber_mode_find(uint8_t mode_id) {
    switch (mode_id) {
        case KYBER_MODE_ID_1024:
            return &KYBER_MODE_1024;
        default:
            return NULL;
    }
}

wickr_kyber_pub_key_t *wickr_kyber_pub_key_create(wickr_kyber_mode_t mode, wickr_buffer_t *key_data)
{
    if (!key_data) {
        return NULL;
    }
    
    wickr_kyber_pub_key_t *pub_key = wickr_alloc_zero(sizeof(wickr_kyber_pub_key_t));
    
    if (!pub_key) {
        return NULL;
    }
    
    pub_key->mode = mode;
    pub_key->key_data = key_data;
    
    return pub_key;
}

wickr_kyber_pub_key_t *wickr_kyber_pub_key_copy(const wickr_kyber_pub_key_t *key)
{
    if (!key) {
        return NULL;
    }
    
    wickr_buffer_t *key_data_copy = wickr_buffer_copy(key->key_data);
    
    if (!key_data_copy) {
        return NULL;
    }
    
    wickr_kyber_pub_key_t *copy_key = wickr_kyber_pub_key_create(key->mode, key_data_copy);
    
    if (!copy_key) {
        wickr_buffer_destroy(&key_data_copy);
    }
    
    return copy_key;
}

void wickr_kyber_pub_key_destroy(wickr_kyber_pub_key_t **key)
{
    if (!key || !*key) {
        return;
    }
    
    wickr_buffer_destroy(&(*key)->key_data);
    wickr_free(*key);
    *key = NULL;
}

wickr_buffer_t *wickr_kyber_pub_key_serialize(const wickr_kyber_pub_key_t *key)
{
    if (!key) {
        return NULL;
    }
    
    wickr_buffer_t id_buffer = {
        .bytes = (uint8_t *)&key->mode.identifier,
        .length = sizeof(uint8_t)
    };
    
    return wickr_buffer_concat(&id_buffer, key->key_data);
}

wickr_kyber_pub_key_t *wickr_kyber_pub_key_create_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer || buffer->length <= sizeof(uint8_t)) {
        return NULL;
    }
    
    const wickr_kyber_mode_t *mode = wickr_kyber_mode_find(buffer->bytes[0]);
    
    if (!mode) {
        return NULL;
    }
    
    if (buffer->length < mode->public_key_len + sizeof(uint8_t)) {
        return NULL;
    }
    
    wickr_buffer_t *key_buffer = wickr_buffer_copy_section(buffer, sizeof(uint8_t), mode->public_key_len);
    
    if (!key_buffer) {
        return NULL;
    }
    
    wickr_kyber_pub_key_t *pub_key = wickr_kyber_pub_key_create(*mode, key_buffer);
    
    if (!pub_key) {
        wickr_buffer_destroy(&key_buffer);
    }
    
    return pub_key;
}

wickr_kyber_secret_key_t *wickr_kyber_secret_key_create(wickr_kyber_mode_t mode, wickr_buffer_t *key_data)
{
    if (!key_data) {
        return NULL;
    }
    
    wickr_kyber_secret_key_t *secret_key = wickr_alloc_zero(sizeof(wickr_kyber_secret_key_t));
    
    if (!secret_key) {
        return NULL;
    }
    
    secret_key->mode = mode;
    secret_key->key_data = key_data;
    
    return secret_key;
}

wickr_kyber_secret_key_t *wickr_kyber_secret_key_copy(const wickr_kyber_secret_key_t *key)
{
    if (!key) {
        return NULL;
    }
    
    wickr_buffer_t *key_data_copy = wickr_buffer_copy(key->key_data);
    
    if (!key_data_copy) {
        return NULL;
    }
    
    wickr_kyber_secret_key_t *copy_key = wickr_kyber_secret_key_create(key->mode, key_data_copy);
    
    if (!copy_key) {
        wickr_buffer_destroy(&key_data_copy);
    }
    
    return copy_key;
}

void wickr_kyber_secret_key_destroy(wickr_kyber_secret_key_t **key)
{
    if (!key || !*key) {
        return;
    }
    
    wickr_buffer_destroy_zero(&(*key)->key_data);
    wickr_free(*key);
    *key = NULL;
}

wickr_buffer_t *wickr_kyber_secret_key_serialize(const wickr_kyber_secret_key_t *key)
{
    if (!key) {
        return NULL;
    }
    
    wickr_buffer_t id_buffer = {
        .bytes = (uint8_t *)&key->mode.identifier,
        .length = sizeof(uint8_t)
    };
    
    return wickr_buffer_concat(&id_buffer, key->key_data);
}

wickr_kyber_secret_key_t *wickr_kyber_secret_key_create_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer || buffer->length <= sizeof(uint8_t)) {
        return NULL;
    }
    
    const wickr_kyber_mode_t *mode = wickr_kyber_mode_find(buffer->bytes[0]);
    
    if (!mode) {
        return NULL;
    }
    
    if (buffer->length < mode->secret_key_len + sizeof(uint8_t)) {
        return NULL;
    }
    
    wickr_buffer_t *key_buffer = wickr_buffer_copy_section(buffer, sizeof(uint8_t), mode->secret_key_len);
    
    if (!key_buffer) {
        return NULL;
    }
    
    wickr_kyber_secret_key_t *secret_key = wickr_kyber_secret_key_create(*mode, key_buffer);
    
    if (!secret_key) {
        wickr_buffer_destroy_zero(&key_buffer);
    }
    
    return secret_key;
}

wickr_kyber_keypair_t *wickr_kyber_keypair_create(wickr_kyber_mode_t mode, wickr_kyber_pub_key_t *public_key, wickr_kyber_secret_key_t *secret_key)
{
    if (!public_key || !secret_key) {
        return NULL;
    }
    
    wickr_kyber_keypair_t *keypair = wickr_alloc_zero(sizeof(wickr_kyber_keypair_t));
    
    if (!keypair) {
        return NULL;
    }
    
    keypair->public_key = public_key;
    keypair->secret_key = secret_key;
    
    return keypair;
}

wickr_kyber_keypair_t *wickr_kyber_keypair_copy(const wickr_kyber_keypair_t *keypair)
{
    if (!keypair) {
        return NULL;
    }
    
    wickr_kyber_pub_key_t *pub_key_copy = wickr_kyber_pub_key_copy(keypair->public_key);
    
    if (!pub_key_copy) {
        return NULL;
    }
    
    wickr_kyber_secret_key_t *secret_key_copy = wickr_kyber_secret_key_copy(keypair->secret_key);
    
    if (!secret_key_copy) {
        wickr_kyber_pub_key_destroy(&pub_key_copy);
        return NULL;
    }
    
    wickr_kyber_keypair_t *keypair_copy = wickr_kyber_keypair_create(keypair->mode, pub_key_copy, secret_key_copy);
    
    if (!keypair_copy) {
        wickr_kyber_pub_key_destroy(&pub_key_copy);
        wickr_kyber_secret_key_destroy(&secret_key_copy);
    }
    
    return keypair_copy;
}

void wickr_kyber_keypair_destroy(wickr_kyber_keypair_t **keypair)
{
    if (!keypair || !*keypair) {
        return;
    }
    
    wickr_kyber_pub_key_destroy(&(*keypair)->public_key);
    wickr_kyber_secret_key_destroy(&(*keypair)->secret_key);
    wickr_free(*keypair);
    *keypair = NULL;
}
