
#include "stream_info_priv.h"
#include "stream.pb-c.h"
#include "memory.h"

wickr_stream_info_t *wickr_stream_info_create(wickr_stream_key_t *key, wickr_buffer_t *user_data)
{
    if (!key) {
        return NULL;
    }
    
    wickr_stream_info_t *info = wickr_alloc_zero(sizeof(wickr_stream_info_t));
    
    if (!info) {
        return NULL;
    }
    
    info->key = key;
    info->user_data = user_data;
    
    return info;
}

wickr_stream_info_t *wickr_stream_info_copy(const wickr_stream_info_t *info)
{
    if (!info) {
        return NULL;
    }
    
    wickr_stream_key_t *key_copy = wickr_stream_key_copy(info->key);
    
    if (!key_copy) {
        return NULL;
    }
    
    wickr_buffer_t *user_info = wickr_buffer_copy(info->user_data);
    
    if (info->user_data && !user_info) {
        wickr_stream_key_destroy(&key_copy);
        return NULL;
    }
    
    wickr_stream_info_t *copy = wickr_stream_info_create(key_copy, user_info);
    
    if (!copy) {
        wickr_stream_key_destroy(&key_copy);
        wickr_buffer_destroy(&user_info);
    }
    
    return copy;
}

void wickr_stream_info_destroy(wickr_stream_info_t **info)
{
    if (!info || !*info) {
        return;
    }
    
    wickr_stream_key_destroy(&(*info)->key);
    wickr_buffer_destroy(&(*info)->user_data);
    wickr_free(*info);
    *info = NULL;
}

wickr_buffer_t *wickr_stream_info_serialize(const wickr_stream_info_t *info)
{
    if (!info) {
        return NULL;
    }
    
    Wickr__Proto__StreamInfo *info_proto = wickr_stream_info_to_proto(info);
    
    if (!info_proto) {
        return NULL;
    }
    
    size_t len = wickr__proto__stream_info__get_packed_size(info_proto);
    
    wickr_buffer_t *packed_buffer = wickr_buffer_create_empty(len);
    
    if (!packed_buffer) {
        wickr_stream_info_proto_free(info_proto);
        return NULL;
    }
    
    wickr__proto__stream_info__pack(info_proto, packed_buffer->bytes);
    wickr_stream_info_proto_free(info_proto);
    
    return packed_buffer;
}

wickr_stream_info_t *wickr_stream_info_create_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    Wickr__Proto__StreamInfo *proto_info = wickr__proto__stream_info__unpack(NULL, buffer->length, buffer->bytes);
    
    if (!proto_info) {
        return NULL;
    }
    
    wickr_stream_info_t *return_info = wickr_stream_info_create_from_proto(proto_info);
    wickr__proto__stream_info__free_unpacked(proto_info, NULL);
    
    return return_info;
}
