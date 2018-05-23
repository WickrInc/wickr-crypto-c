
#include "private/cipher_priv.h"
#include "private/buffer_priv.h"

wickr_cipher_key_t *wickr_cipher_key_from_protobytes(ProtobufCBinaryData buffer)
{
    wickr_buffer_t node_key_buffer = {
        .bytes = buffer.data,
        .length = buffer.len
    };
    
    return wickr_cipher_key_from_buffer(&node_key_buffer);
}

bool wickr_cipher_key_to_protobytes(ProtobufCBinaryData *proto_bin, const wickr_cipher_key_t *cipher_key)
{
    if (!proto_bin || !cipher_key) {
        return false;
    }
    
    wickr_buffer_t *serialized = wickr_cipher_key_serialize(cipher_key);
    
    if (!serialized) {
        return false;
    }
    
    bool res = wickr_buffer_to_protobytes(proto_bin, serialized);
    wickr_buffer_destroy_zero(&serialized);
    
    return res;
}

wickr_cipher_result_t *wickr_cipher_result_from_protobytes(ProtobufCBinaryData buffer)
{
    wickr_buffer_t cipher_result_buffer = {
        .bytes = buffer.data,
        .length = buffer.len
    };
    
    return wickr_cipher_result_from_buffer(&cipher_result_buffer);
}

bool wickr_cipher_result_to_protobytes(ProtobufCBinaryData *proto_bin, const wickr_cipher_result_t *cipher_result)
{
    if (!proto_bin || !cipher_result) {
        return false;
    }
    
    wickr_buffer_t *serialized = wickr_cipher_result_serialize(cipher_result);
    
    if (!serialized) {
        return false;
    }
    
    bool res = wickr_buffer_to_protobytes(proto_bin, serialized);
    wickr_buffer_destroy_zero(&serialized);
    
    return res;
}
