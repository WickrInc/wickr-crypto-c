
#include "buffer_priv.h"

wickr_buffer_t *wickr_buffer_from_protobytes(ProtobufCBinaryData buffer)
{
    return wickr_buffer_create(buffer.data, buffer.len);
}
