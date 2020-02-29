
#include "transport_root_key.h"
#include "memory.h"

wickr_transport_root_key_t *wickr_transport_root_key_create_random(const wickr_crypto_engine_t *engine,
                                                                   wickr_cipher_t cipher,
                                                                   uint32_t packets_per_evo_send,
                                                                   uint32_t packets_per_evo_recv)
{
    if (!engine) {
        return NULL;
    }
    
    wickr_buffer_t *secret = engine->wickr_crypto_engine_crypto_random(cipher.key_len);
    
    if (!secret) {
        return NULL;
    }
    
    wickr_transport_root_key_t *root_key = wickr_transport_root_key_create(secret, cipher, packets_per_evo_send, packets_per_evo_recv);
    
    if (!root_key) {
        wickr_buffer_destroy(&secret);
    }
    
    return root_key;
}

wickr_transport_root_key_t *wickr_transport_root_key_create(wickr_buffer_t *secret,
                                                            wickr_cipher_t cipher,
                                                            uint32_t packets_per_evo_send,
                                                            uint32_t packets_per_evo_recv)
{
    if (!secret || secret->length != cipher.key_len) {
        return NULL;
    }
    
    wickr_transport_root_key_t *root_key = wickr_alloc_zero(sizeof(wickr_transport_root_key_t));
    
    if (!root_key) {
        return NULL;
    }
    
    root_key->cipher = cipher;
    root_key->secret = secret;
    root_key->packets_per_evo_send = packets_per_evo_send;
    root_key->packets_per_evo_recv = packets_per_evo_recv;
    
    return root_key;
}

wickr_transport_root_key_t *wickr_transport_root_key_copy(const wickr_transport_root_key_t *root_key)
{
    if (!root_key) {
        return NULL;
    }
    
    wickr_buffer_t *secret_copy = wickr_buffer_copy(root_key->secret);
    
    if (!secret_copy) {
        return NULL;
    }
    
    wickr_transport_root_key_t *root_key_copy = wickr_transport_root_key_create(secret_copy,
                                                                                root_key->cipher,
                                                                                root_key->packets_per_evo_send,
                                                                                root_key->packets_per_evo_recv);
    
    if (!root_key_copy) {
        wickr_buffer_destroy(&secret_copy);
    }
    
    return root_key_copy;
}

void wickr_transport_root_key_destroy(wickr_transport_root_key_t **root_key)
{
    if (!root_key || !*root_key) {
        return;
    }
    
    wickr_buffer_destroy(&(*root_key)->secret);
    wickr_free(*root_key);
    *root_key = NULL;
}

wickr_stream_key_t *wickr_transport_root_key_to_stream_key(const wickr_transport_root_key_t *root_key,
                                                           const wickr_crypto_engine_t *engine,
                                                           const wickr_buffer_t *salt,
                                                           const wickr_buffer_t *stream_id,
                                                           wickr_stream_direction direction)
{
    if (!root_key || !salt || !stream_id) {
        return NULL;
    }
    
    wickr_kdf_meta_t kdf_meta =  { .algo = KDF_HKDF_SHA512, .salt = (wickr_buffer_t *)salt, .info = (wickr_buffer_t *)stream_id };
    wickr_kdf_result_t *raw_key_material = engine->wickr_crypto_kdf_meta(&kdf_meta, root_key->secret);
    
    if (!raw_key_material || raw_key_material->hash->length != root_key->cipher.key_len * 2) {
        return NULL;
    }
    
    wickr_buffer_t *cipher_key_data = wickr_buffer_copy_section(raw_key_material->hash, 0, root_key->cipher.key_len);
    wickr_cipher_key_t *cipher_key = wickr_cipher_key_create(root_key->cipher, cipher_key_data);
    
    if (!cipher_key) {
        wickr_buffer_destroy(&cipher_key_data);
        return NULL;
    }
    
    wickr_buffer_t *evo_key = wickr_buffer_copy_section(raw_key_material->hash, root_key->cipher.key_len, root_key->cipher.key_len);
    wickr_kdf_result_destroy(&raw_key_material);
    
    wickr_stream_key_t *stream_key = NULL;
    
    if (direction == STREAM_DIRECTION_ENCODE) {
        stream_key = wickr_stream_key_create(cipher_key, evo_key, root_key->packets_per_evo_send);
    } else {
        stream_key = wickr_stream_key_create(cipher_key, evo_key, root_key->packets_per_evo_recv);
    }
    
    if (!stream_key) {
        wickr_cipher_key_destroy(&cipher_key);
        wickr_buffer_destroy(&evo_key);
    }
    
    return stream_key;
    
}
