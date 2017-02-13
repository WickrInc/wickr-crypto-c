
#include "protobuf_util.h"

wickr_cipher_key_t *wickr_cipher_key_from_protobytes(ProtobufCBinaryData buffer)
{
    wickr_buffer_t node_key_buffer;
    node_key_buffer.bytes = buffer.data;
    node_key_buffer.length = buffer.len;
    
    return wickr_cipher_key_from_buffer(&node_key_buffer);
}

wickr_ec_key_t *wickr_ec_key_from_protobytes(ProtobufCBinaryData buffer, const wickr_crypto_engine_t *engine)
{
    wickr_buffer_t key_buffer;
    key_buffer.bytes = buffer.data;
    key_buffer.length = buffer.len;
    
    return engine->wickr_crypto_engine_ec_key_import(&key_buffer, true);
}
