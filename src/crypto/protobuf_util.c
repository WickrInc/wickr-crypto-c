
#include "protobuf_util.h"

wickr_buffer_t *wickr_buffer_from_protobytes(ProtobufCBinaryData buffer)
{
    return wickr_buffer_create(buffer.data, buffer.len);
}

wickr_cipher_key_t *wickr_cipher_key_from_protobytes(ProtobufCBinaryData buffer)
{
    wickr_buffer_t node_key_buffer;
    node_key_buffer.bytes = buffer.data;
    node_key_buffer.length = buffer.len;
    
    return wickr_cipher_key_from_buffer(&node_key_buffer);
}

wickr_ec_key_t *wickr_ec_key_from_protobytes(ProtobufCBinaryData buffer, const wickr_crypto_engine_t *engine, bool is_private)
{
    wickr_buffer_t key_buffer;
    key_buffer.bytes = buffer.data;
    key_buffer.length = buffer.len;
    
    return engine->wickr_crypto_engine_ec_key_import(&key_buffer, is_private);
}

wickr_ecdsa_result_t *wickr_ecdsa_result_from_protobytes(ProtobufCBinaryData buffer)
{
    wickr_buffer_t ecdsa_result_buffer;
    ecdsa_result_buffer.bytes = buffer.data;
    ecdsa_result_buffer.length = buffer.len;
    
    return wickr_ecdsa_result_create_from_buffer(&ecdsa_result_buffer);
}
