
#include "private/eckey_priv.h"

wickr_ec_key_t *wickr_ec_key_from_protobytes(ProtobufCBinaryData buffer, const wickr_crypto_engine_t *engine, bool is_private)
{
    wickr_buffer_t key_buffer;
    key_buffer.bytes = buffer.data;
    key_buffer.length = buffer.len;
    
    return engine->wickr_crypto_engine_ec_key_import(&key_buffer, is_private);
}
