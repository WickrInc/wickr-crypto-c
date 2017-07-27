
#include "stream_info_priv.h"
#include "stream_cipher_priv.h"
#include "protobuf_util.h"
#include "memory.h"

void wickr_stream_info_proto_free(Wickr__Proto__StreamInfo *proto_info)
{
    if (!proto_info) {
        return;
    }
    
    wickr_stream_key_proto_free(proto_info->key);
    wickr_free(proto_info);
}

Wickr__Proto__StreamInfo *wickr_stream_info_to_proto(const wickr_stream_info_t *info)
{
    if (!info) {
        return NULL;
    }
    
    Wickr__Proto__StreamInfo *proto_info = wickr_alloc_zero(sizeof(Wickr__Proto__StreamInfo));
    
    if (!proto_info) {
        return NULL;
    }
    
    wickr__proto__stream_info__init(proto_info);
    
    if (info->user_data) {
        proto_info->has_user_data = true;
        proto_info->user_data.data = info->user_data->bytes;
        proto_info->user_data.len = info->user_data->length;
    }
    
    proto_info->key = wickr_stream_key_to_proto(info->key);
    
    if (!proto_info->key) {
        wickr_free(proto_info);
        return NULL;
    }
    
    return proto_info;
}

wickr_stream_info_t *wickr_stream_info_create_from_proto(const Wickr__Proto__StreamInfo *proto)
{
    if (!proto) {
        return NULL;
    }
    
    wickr_stream_key_t *stream_key = wickr_stream_key_create_from_proto(proto->key);
    
    if (!stream_key) {
        return NULL;
    }
    
    wickr_buffer_t *user_data = NULL;
    
    if (proto->has_user_data) {
        user_data = wickr_buffer_from_protobytes(proto->user_data);
    }
    
    wickr_stream_info_t *info = wickr_stream_info_create(stream_key, user_data);
    
    if (!info) {
        wickr_stream_key_destroy(&stream_key);
        wickr_buffer_destroy(&user_data);
    }
    
    return info;
}
