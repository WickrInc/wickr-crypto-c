
#include "private/stream_key_priv.h"
#include "memory.h"
#include "private/buffer_priv.h"

void wickr_stream_key_proto_free(Wickr__Proto__StreamKey *proto_key)
{
    if (!proto_key) {
        return;
    }
    wickr_free(proto_key->cipher_key.data);
    wickr_free(proto_key);
}

Wickr__Proto__StreamKey *wickr_stream_key_to_proto(const wickr_stream_key_t *key)
{
    if (!key) {
        return NULL;
    }
    
    Wickr__Proto__StreamKey *proto = wickr_alloc_zero(sizeof(Wickr__Proto__StreamKey));
    
    if (!proto) {
        return NULL;
    }
    
    wickr__proto__stream_key__init(proto);
    
    wickr_buffer_t *key_buffer = wickr_cipher_key_serialize(key->cipher_key);
    
    if (!key_buffer) {
        wickr_free(proto);
        return NULL;
    }
    
    if (!wickr_buffer_to_protobytes(&proto->cipher_key, key_buffer)) {
        wickr_buffer_destroy(&key_buffer);
        return NULL;
    }
    
    wickr_buffer_destroy(&key_buffer);

    proto->evolution_key.data = key->evolution_key->bytes;
    proto->evolution_key.len = key->evolution_key->length;
    
    if (key->user_data) {
        proto->has_user_data = true;
        proto->user_data.data = key->user_data->bytes;
        proto->user_data.len = key->user_data->length;
    }
    
    proto->packets_per_evo = key->packets_per_evolution;
    proto->has_cipher_key = true;
    proto->has_evolution_key = true;
    proto->has_packets_per_evo = true;
    
    return proto;
}

wickr_stream_key_t *wickr_stream_key_create_from_proto(const Wickr__Proto__StreamKey *proto)
{
    if (!proto || !proto->has_cipher_key || !proto->has_evolution_key || !proto->has_packets_per_evo) {
        return NULL;
    }
    
    wickr_buffer_t *key_buffer = wickr_buffer_create(proto->cipher_key.data, proto->cipher_key.len);
    
    if (!key_buffer) {
        return NULL;
    }
    
    wickr_cipher_key_t *cipher_key = wickr_cipher_key_from_buffer(key_buffer);
    wickr_buffer_destroy(&key_buffer);
    
    if (!cipher_key) {
        return NULL;
    }
    
    wickr_buffer_t *evo_key = wickr_buffer_create(proto->evolution_key.data, proto->evolution_key.len);
    
    if (!evo_key) {
        wickr_cipher_key_destroy(&cipher_key);
        return NULL;
    }
    
    wickr_buffer_t *user_data = NULL;
    
    if (proto->has_user_data) {
        user_data = wickr_buffer_create(proto->user_data.data, proto->user_data.len);
        
        if (!user_data) {
            wickr_cipher_key_destroy(&cipher_key);
            wickr_buffer_destroy(&evo_key);
            return NULL;
        }
    }
    
    wickr_stream_key_t *stream_key = wickr_stream_key_create_user_data(cipher_key, evo_key, proto->packets_per_evo, user_data);
    
    if (!stream_key) {
        wickr_cipher_key_destroy(&cipher_key);
        wickr_buffer_destroy(&evo_key);
        return NULL;
    }
    
    return stream_key;
}
