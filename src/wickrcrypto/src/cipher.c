
#include "cipher.h"
#include "memory.h"

const wickr_cipher_t *wickr_cipher_find(uint8_t cipher_id) {
    switch (cipher_id) {
        case CIPHER_ID_AES256_GCM:
            return &CIPHER_AES256_GCM;
        case CIPHER_ID_AES256_CTR:
            return &CIPHER_AES256_CTR;
        default:
            return NULL;
    }
}

wickr_cipher_result_t *wickr_cipher_result_create(wickr_cipher_t cipher, wickr_buffer_t *iv, wickr_buffer_t *cipher_text, wickr_buffer_t *auth_tag)
{
    /* The IV is required and must be the same length */
    if (!iv || iv->length != cipher.iv_len) {
        return NULL;
    }
    
    /* The auth tag is a required field if the cipher is authenticated */
    if (cipher.is_authenticated && !auth_tag) {
        return NULL;
    }
    
    /* Make sure auth tag is the correct length */
    if (auth_tag && auth_tag->length != cipher.auth_tag_len) {
        return NULL;
    }
    
    wickr_cipher_result_t *new_result = wickr_alloc_zero(sizeof(wickr_cipher_result_t));
    new_result->cipher = cipher;
    
    
    new_result->iv = iv;
    new_result->cipher_text = cipher_text;
    new_result->auth_tag = auth_tag;
    
    return new_result;
}

wickr_cipher_result_t *wickr_cipher_result_copy(const wickr_cipher_result_t *result)
{
    if (!result) {
        return NULL;
    }
    
    wickr_buffer_t *iv_copy = wickr_buffer_copy(result->iv);
    wickr_buffer_t *cipher_text_copy;
    if (result->cipher_text)
        cipher_text_copy = wickr_buffer_copy(result->cipher_text);
    else
        cipher_text_copy = NULL;
    wickr_buffer_t *auth_tag_copy = result->auth_tag ? wickr_buffer_copy(result->auth_tag) : NULL;
    
    return wickr_cipher_result_create(result->cipher, iv_copy, cipher_text_copy, auth_tag_copy);
}

void wickr_cipher_result_destroy(wickr_cipher_result_t **result)
{
    if (!*result) {
        return;
    }
    
    wickr_buffer_destroy(&(*result)->iv);
    if ((*result)->cipher_text)
        wickr_buffer_destroy(&(*result)->cipher_text);
    wickr_buffer_destroy(&(*result)->auth_tag);
    
    wickr_free((*result));
    *result = NULL;
}

bool wickr_cipher_result_is_valid(const wickr_cipher_result_t *result)
{
    if (!result) {
        return false;
    }
    
    if (!result->iv) {
        return false;
    }
    
    if (result->cipher.is_authenticated && !result->auth_tag) {
        return false;
    }
    
    return true;
}

wickr_buffer_t *wickr_cipher_result_serialize(const wickr_cipher_result_t *result)
{
    if (!result || !wickr_cipher_result_is_valid(result)) {
        return NULL;
    }
    
    uint8_t mode_int = (uint8_t)result->cipher.cipher_id;
    wickr_buffer_t mode_buffer = { sizeof(uint8_t), &mode_int };
    
    if (!result->cipher.is_authenticated) {
        wickr_buffer_t *components[] = { &mode_buffer, result->iv, result->cipher_text };
        return wickr_buffer_concat_multi(components, BUFFER_ARRAY_LEN(components));
    }
    
    wickr_buffer_t *components[] = { &mode_buffer, result->iv, result->auth_tag, result->cipher_text };
    return wickr_buffer_concat_multi(components, BUFFER_ARRAY_LEN(components));
}

wickr_cipher_result_t *wickr_cipher_result_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    const wickr_cipher_t *mode = wickr_cipher_find(buffer->bytes[0]);
    
    if (!mode) {
        return NULL;
    }
    
    size_t required_size = sizeof(uint8_t) + mode->iv_len + mode->auth_tag_len;
    
    if (buffer->length < required_size) {
        return NULL;
    }
    
    size_t buffer_pos = sizeof(uint8_t);
    
    wickr_buffer_t *iv = wickr_buffer_copy_section(buffer, sizeof(uint8_t), mode->iv_len);
    buffer_pos += mode->iv_len;
    
    if (!iv) {
        return NULL;
    }
    
    wickr_buffer_t *auth_tag = NULL;
    
    if (mode->is_authenticated) {
        auth_tag = wickr_buffer_copy_section(buffer, sizeof(uint8_t) + mode->iv_len, mode->auth_tag_len);
        if (!auth_tag) {
            wickr_buffer_destroy(&iv);
            return NULL;
        }
        buffer_pos += mode->auth_tag_len;
    }
    
    wickr_buffer_t *cipher_text;
    if (buffer->length > required_size) {
        cipher_text = wickr_buffer_copy_section(buffer, buffer_pos, buffer->length - buffer_pos);
    
        if (!cipher_text) {
            wickr_buffer_destroy(&iv);
            if (auth_tag) {
                wickr_buffer_destroy(&auth_tag);
            }
            return NULL;
        }
    } else {
        cipher_text = NULL;
    }
    return wickr_cipher_result_create(*mode, iv, cipher_text, auth_tag);
}

wickr_cipher_key_t *wickr_cipher_key_create(wickr_cipher_t cipher, wickr_buffer_t *key_data)
{
    if (!key_data || key_data->length != cipher.key_len) {
        return NULL;
    }
    
    wickr_cipher_key_t *new_key = wickr_alloc_zero(sizeof(wickr_cipher_key_t));
    new_key->cipher = cipher;
    new_key->key_data = key_data;
    
    return new_key;
}

wickr_cipher_key_t *wickr_cipher_key_copy(const wickr_cipher_key_t *key)
{
    if (!key) {
        return NULL;
    }
    
    wickr_buffer_t *key_data_copy = wickr_buffer_copy(key->key_data);
    
    if (!key_data_copy) {
        return NULL;
    }
    
    wickr_cipher_key_t *copy_key = wickr_cipher_key_create(key->cipher, key_data_copy);
    
    if (!copy_key) {
        wickr_buffer_destroy_zero(&key_data_copy);
    }
    
    return copy_key;
}

void wickr_cipher_key_destroy(wickr_cipher_key_t **key)
{
    if (!key || !*key) {
        return;
    }
    
    wickr_buffer_destroy_zero(&(*key)->key_data);
    wickr_free(*key);
    *key = NULL;
}

wickr_buffer_t *wickr_cipher_key_serialize(const wickr_cipher_key_t *key)
{
    if (!key) {
        return NULL;
    }
    
    uint8_t wickr_cipher_id = (uint8_t)key->cipher.cipher_id;
    
    wickr_buffer_t cipher_id_buffer;
    cipher_id_buffer.length = sizeof(uint8_t);
    cipher_id_buffer.bytes = &wickr_cipher_id;
    
    return wickr_buffer_concat(&cipher_id_buffer, key->key_data);
}

wickr_cipher_key_t *wickr_cipher_key_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer || buffer->length <= sizeof(uint8_t)) {
        return NULL;
    }
    
    const wickr_cipher_t *cipher = wickr_cipher_find(buffer->bytes[0]);
    
    if (!cipher || (buffer->length - sizeof(uint8_t) < cipher->key_len)) {
        return NULL;
    }
    
    wickr_buffer_t *key_buffer = wickr_buffer_copy_section(buffer, sizeof(uint8_t), cipher->key_len);
    
    if (!key_buffer) {
        return NULL;
    }
    
    return wickr_cipher_key_create(*cipher, key_buffer);
}
