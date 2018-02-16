//
//  stream_key.c
//  Crypto
//
//  Created by Tom Leavy on 7/28/17.
//
//

#include "private/stream_key_priv.h"
#include "memory.h"

wickr_stream_key_t *wickr_stream_key_create(wickr_cipher_key_t *cipher_key, wickr_buffer_t *evolution_key, uint32_t packets_per_evolution)
{
    return wickr_stream_key_create_user_data(cipher_key, evolution_key, packets_per_evolution, NULL);
}

wickr_stream_key_t *wickr_stream_key_create_user_data(wickr_cipher_key_t *cipher_key, wickr_buffer_t *evolution_key, uint32_t packets_per_evolution, wickr_buffer_t *user_data)
{
    if (!cipher_key || !evolution_key ||
        (packets_per_evolution < PACKET_PER_EVO_MIN || packets_per_evolution > PACKET_PER_EVO_MAX))
    {
        return NULL;
    }
    
    wickr_stream_key_t *new_stream_key = wickr_alloc_zero(sizeof(wickr_stream_key_t));
    
    if (!new_stream_key) {
        return NULL;
    }
    
    new_stream_key->cipher_key = cipher_key;
    new_stream_key->evolution_key = evolution_key;
    new_stream_key->packets_per_evolution = packets_per_evolution;
    new_stream_key->user_data = user_data;
    
    return new_stream_key;
}

wickr_stream_key_t *wickr_stream_key_create_rand(const wickr_crypto_engine_t engine, wickr_cipher_t cipher, uint32_t packets_per_evolution)
{
    wickr_cipher_key_t *cipher_key = engine.wickr_crypto_engine_cipher_key_random(cipher);
    
    if (!cipher_key) {
        return NULL;
    }
    
    wickr_buffer_t *evo_key = engine.wickr_crypto_engine_crypto_random(cipher.key_len);
    
    if (!evo_key) {
        wickr_cipher_key_destroy(&cipher_key);
        return NULL;
    }
    
    wickr_stream_key_t *stream_key = wickr_stream_key_create(cipher_key, evo_key, packets_per_evolution);
    
    if (!stream_key) {
        wickr_cipher_key_destroy(&cipher_key);
        wickr_buffer_destroy(&evo_key);
    }
    
    return stream_key;
}

wickr_stream_key_t *wickr_stream_key_copy(const wickr_stream_key_t *stream_key)
{
    if (!stream_key) {
        return NULL;
    }
    
    wickr_cipher_key_t *key_copy = wickr_cipher_key_copy(stream_key->cipher_key);
    
    if (!key_copy) {
        return NULL;
    }
    
    wickr_buffer_t *evo_key_copy = wickr_buffer_copy(stream_key->evolution_key);
    
    if (!evo_key_copy) {
        wickr_cipher_key_destroy(&key_copy);
        return NULL;
    }
    
    wickr_buffer_t *user_data_copy = wickr_buffer_copy(stream_key->user_data);
    
    if (stream_key->user_data && !user_data_copy) {
        wickr_cipher_key_destroy(&key_copy);
        wickr_buffer_destroy(&evo_key_copy);
        return NULL;
    }
    
    wickr_stream_key_t *stream_key_copy = wickr_stream_key_create_user_data(key_copy,
                                                                            evo_key_copy,
                                                                            stream_key->packets_per_evolution,
                                                                            user_data_copy);
    
    if (!stream_key_copy) {
        wickr_cipher_key_destroy(&key_copy);
        wickr_buffer_destroy(&evo_key_copy);
        wickr_buffer_destroy(&user_data_copy);
    }
    
    return stream_key_copy;
}

wickr_buffer_t *wickr_stream_key_serialize(const wickr_stream_key_t *key)
{
    if (!key) {
        return NULL;
    }
    
    Wickr__Proto__StreamKey *proto_key = wickr_stream_key_to_proto(key);
    
    if (!key) {
        return NULL;
    }
    
    size_t length = wickr__proto__stream_key__get_packed_size(proto_key);
    
    wickr_buffer_t *buffer = wickr_buffer_create_empty(length);
    
    if (!buffer) {
        wickr_stream_key_proto_free(proto_key);
        return NULL;
    }
    
    wickr__proto__stream_key__pack(proto_key, buffer->bytes);
    wickr_stream_key_proto_free(proto_key);
    
    return buffer;
}

wickr_stream_key_t *wickr_stream_key_create_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    Wickr__Proto__StreamKey *proto_key = wickr__proto__stream_key__unpack(NULL, buffer->length, buffer->bytes);
    
    if (!proto_key) {
        return NULL;
    }
    
    wickr_stream_key_t *stream_key = wickr_stream_key_create_from_proto(proto_key);
    wickr__proto__stream_key__free_unpacked(proto_key, NULL);
    
    return stream_key;
}

void wickr_stream_key_destroy(wickr_stream_key_t **stream_key)
{
    if (!stream_key || !*stream_key) {
        return;
    }
    
    wickr_cipher_key_destroy(&(*stream_key)->cipher_key);
    wickr_buffer_destroy_zero(&(*stream_key)->evolution_key);
    wickr_buffer_destroy(&(*stream_key)->user_data);
    
    wickr_free(*stream_key);
    *stream_key = NULL;
}
