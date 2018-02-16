
#include "private/ecdsa_priv.h"

wickr_ecdsa_result_t *wickr_ecdsa_result_from_protobytes(ProtobufCBinaryData buffer)
{
    wickr_buffer_t ecdsa_result_buffer;
    ecdsa_result_buffer.bytes = buffer.data;
    ecdsa_result_buffer.length = buffer.len;
    
    return wickr_ecdsa_result_create_from_buffer(&ecdsa_result_buffer);
}
