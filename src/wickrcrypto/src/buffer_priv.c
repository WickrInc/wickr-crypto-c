
#include "private/buffer_priv.h"
#include "memory.h"
#include <string.h>

wickr_buffer_t *wickr_buffer_from_protobytes(ProtobufCBinaryData buffer)
{
    return wickr_buffer_create(buffer.data, buffer.len);
}

bool wickr_buffer_to_protobytes(ProtobufCBinaryData *proto_bin, const wickr_buffer_t *buffer)
{
    if (!proto_bin || !buffer) {
        return false;
    }
    
    proto_bin->data = wickr_alloc(buffer->length);
    
    if (!proto_bin->data) {
        return false;
    }
    
    memcpy(proto_bin->data, buffer->bytes, buffer->length);
    proto_bin->len = buffer->length;
    
    return true;
}
