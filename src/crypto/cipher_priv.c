
#include "cipher_priv.h"

wickr_cipher_key_t *wickr_cipher_key_from_protobytes(ProtobufCBinaryData buffer)
{
    wickr_buffer_t node_key_buffer;
    node_key_buffer.bytes = buffer.data;
    node_key_buffer.length = buffer.len;
    
    return wickr_cipher_key_from_buffer(&node_key_buffer);
}
