
#include "payload.h"
#include "memory.h"
#include "message.pb-c.h"

wickr_payload_t *wickr_payload_create(wickr_packet_meta_t *meta, wickr_buffer_t *body)
{
    if (!meta || !body) {
        return NULL;
    }
    
    wickr_payload_t *new_payload = wickr_alloc_zero(sizeof(wickr_payload_t));
    
    if (!new_payload) {
        return NULL;
    }
    
    new_payload->meta = meta;
    new_payload->body = body;
    
    return new_payload;
}

wickr_payload_t *wickr_payload_copy(const wickr_payload_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_packet_meta_t *meta_copy = wickr_packet_meta_copy(source->meta);
    
    if (!meta_copy) {
        return NULL;
    }
    
    wickr_buffer_t *body_copy = wickr_buffer_copy(source->body);
    
    if (!body_copy) {
        wickr_packet_meta_destroy(&meta_copy);
        return NULL;
    }
    
    wickr_payload_t *copy = wickr_payload_create(meta_copy, body_copy);
    
    if (!copy) {
        wickr_packet_meta_destroy(&meta_copy);
        wickr_buffer_destroy_zero(&body_copy);
    }
    
    return copy;
}

void wickr_payload_destroy(wickr_payload_t **payload)
{
    if (!payload || !*payload) {
        return;
    }
    
    wickr_packet_meta_destroy(&(*payload)->meta);
    wickr_buffer_destroy_zero(&(*payload)->body);
    wickr_free(*payload);
    *payload = NULL;
}

wickr_buffer_t *wickr_payload_serialize(const wickr_payload_t *payload)
{
    if (!payload) {
        return NULL;
    }
    
    Wickr__Proto__Payload__Meta__Ephemerality proto_eph = WICKR__PROTO__PAYLOAD__META__EPHEMERALITY__INIT;
    proto_eph.ttl = payload->meta->ephemerality_settings.ttl;
    
    if (payload->meta->ephemerality_settings.bor != 0) {
        proto_eph.bor = payload->meta->ephemerality_settings.bor;
        proto_eph.has_bor = true;
    }
    else {
        proto_eph.has_bor = false;
    }
    
    Wickr__Proto__Payload__Meta proto_meta = WICKR__PROTO__PAYLOAD__META__INIT;
    proto_meta.channel_tag.data = payload->meta->channel_tag->bytes;
    proto_meta.channel_tag.len = payload->meta->channel_tag->length;
    proto_meta.content_type = payload->meta->content_type;
    proto_meta.ephemerality_settings = &proto_eph;
    proto_meta.has_channel_tag = true;
    proto_meta.has_content_type = true;
    
    
    Wickr__Proto__Payload proto_payload = WICKR__PROTO__PAYLOAD__INIT;
    proto_payload.metadata = &proto_meta;
    proto_payload.body.data = payload->body->bytes;
    proto_payload.body.len = payload->body->length;
    
    size_t result_size = wickr__proto__payload__get_packed_size(&proto_payload);
    
    wickr_buffer_t *serialized_payload = wickr_buffer_create_empty(result_size);
    
    if (!serialized_payload) {
        return NULL;
    }
    
    wickr__proto__payload__pack(&proto_payload, serialized_payload->bytes);
    
    return serialized_payload;
}

wickr_payload_t *wickr_payload_create_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    Wickr__Proto__Payload *proto_payload = wickr__proto__payload__unpack(NULL, buffer->length, buffer->bytes);
    
    if (!proto_payload) {
        return NULL;
    }
    
    Wickr__Proto__Payload__Meta *proto_meta = proto_payload->metadata;
    Wickr__Proto__Payload__Meta__Ephemerality *proto_eph = proto_meta->ephemerality_settings;
    
    wickr_ephemeral_info_t ephemerality_settings;
    ephemerality_settings.ttl = proto_eph->ttl;
    ephemerality_settings.bor = proto_eph->has_bor ? proto_eph->bor : 0;
    
    wickr_buffer_t *channel_tag = wickr_buffer_create(proto_meta->channel_tag.data, proto_meta->channel_tag.len);
    
    if (!channel_tag) {
        wickr__proto__payload__free_unpacked(proto_payload, NULL);
        return NULL;
    }
    
    uint32_t content_type = proto_meta->has_content_type ? proto_meta->content_type : 0;
    
    wickr_packet_meta_t *meta = wickr_packet_meta_create(ephemerality_settings, channel_tag, content_type);
    
    if (!meta) {
        wickr_buffer_destroy(&channel_tag);
        wickr__proto__payload__free_unpacked(proto_payload, NULL);
        return NULL;
    }
    
    wickr_buffer_t *body = wickr_buffer_create(proto_payload->body.data, proto_payload->body.len);
    wickr__proto__payload__free_unpacked(proto_payload, NULL);
    
    if (!body) {
        wickr_buffer_destroy(&channel_tag);
        wickr_packet_meta_destroy(&meta);
        return NULL;
    }
    
    wickr_payload_t *payload = wickr_payload_create(meta, body);
    
    if (!payload) {
        wickr_buffer_destroy(&channel_tag);
        wickr_packet_meta_destroy(&meta);
        wickr_buffer_destroy_zero(&body);
        return NULL;
    }
    
    return payload;
}

/* Low level payload encryption, safer to call from wickr_ctx instead! */
wickr_cipher_result_t *wickr_payload_encrypt(const wickr_payload_t *payload, const wickr_crypto_engine_t *engine, const wickr_cipher_key_t *payload_key)
{
    if (!payload || !engine || !payload_key) {
        return NULL;
    }
    
    wickr_buffer_t *buffer = wickr_payload_serialize(payload);
    
    if (!buffer) {
        return NULL;
    }
    
    wickr_cipher_result_t *return_result = engine->wickr_crypto_engine_cipher_encrypt(buffer, NULL, payload_key, NULL);
    wickr_buffer_destroy_zero(&buffer);
    
    return return_result;
}

/* Low level payload decryption, safer to call from wickr_ctx instead! */
wickr_payload_t *wickr_payload_create_from_cipher(const wickr_crypto_engine_t *engine,
                                                  const wickr_cipher_result_t *cipher_result,
                                                  const wickr_cipher_key_t *payload_key)
{
    if (!engine || !cipher_result || !payload_key) {
        return NULL;
    }
    
    wickr_buffer_t *decoded_payload = engine->wickr_crypto_engine_cipher_decrypt(cipher_result, NULL, payload_key, true);
    
    if (!decoded_payload) {
        return NULL;
    }
    
    wickr_payload_t *deserialized_payload = wickr_payload_create_from_buffer(decoded_payload);
    wickr_buffer_destroy_zero(&decoded_payload);
    
    return deserialized_payload;
}
