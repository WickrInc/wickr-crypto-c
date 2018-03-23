
#include "private/cipher_priv.h"

wickr_cipher_key_t *wickr_cipher_key_from_protobytes(ProtobufCBinaryData buffer)
{
    wickr_buffer_t node_key_buffer = {
        .bytes = buffer.data,
        .length = buffer.len
    };
    
    return wickr_cipher_key_from_buffer(&node_key_buffer);
}

wickr_cipher_result_t *wickr_cipher_result_from_protobytes(ProtobufCBinaryData buffer)
{
    wickr_buffer_t cipher_result_buffer = {
        .bytes = buffer.data,
        .length = buffer.len
    };
    
    return wickr_cipher_result_from_buffer(&cipher_result_buffer);
}
