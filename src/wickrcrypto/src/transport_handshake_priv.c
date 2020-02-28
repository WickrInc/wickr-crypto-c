
#include "private/transport_handshake_priv.h"
#include "private/identity_priv.h"
#include "private/buffer_priv.h"
#include "private/transport_root_key_priv.h"
#include "transport_packet.h"
#include "memory.h"

Wickr__Proto__HandshakeV1__Seed *wickr_proto_handshake_seed_create(const wickr_identity_chain_t *id_chain,
                                                                   const wickr_buffer_t *ephemeral_pub_key,
                                                                   bool needs_remote_identity)
{
    if (!id_chain) {
        return NULL;
    }
    
    Wickr__Proto__HandshakeV1__Seed *seed = wickr_alloc_zero(sizeof(Wickr__Proto__HandshakeV1__Seed));
    
    if (!seed) {
        return NULL;
    }
    
    wickr__proto__handshake_v1__seed__init(seed);
    seed->id_chain = wickr_identity_chain_to_proto(id_chain);
    seed->has_ephemeral_pubkey = true;
    seed->has_identity_required = true;
    seed->identity_required = needs_remote_identity;
    
    if (!wickr_buffer_to_protobytes(&seed->ephemeral_pubkey, ephemeral_pub_key)) {
        wickr_free(seed);
        return NULL;
    }
    
    if (!seed->id_chain) {
        wickr_free(seed);
        return NULL;
    }
    
    return seed;
}

void wickr_proto_handshake_seed_free(Wickr__Proto__HandshakeV1__Seed *seed)
{
    wickr_identity_chain_proto_free(seed->id_chain);
    wickr_free(seed->ephemeral_pubkey.data);
    wickr_free(seed);
}

Wickr__Proto__HandshakeV1ResponseData *wickr_proto_handshake_response_data_create(const wickr_transport_root_key_t *root_key)
{
    if (!root_key) {
        return NULL;
    }
    
    Wickr__Proto__TransportRootKey *root_key_proto = wickr_transport_root_key_to_proto(root_key);
    
    if (!root_key_proto) {
        return NULL;
    }
    
    Wickr__Proto__HandshakeV1ResponseData *res_data = wickr_alloc_zero(sizeof(Wickr__Proto__HandshakeV1ResponseData));
    
    if (!res_data) {
        wickr_transport_root_key_proto_free(root_key_proto);
        return NULL;
    }
    
    wickr__proto__handshake_v1_response_data__init(res_data);
    res_data->root_key = root_key_proto;
    
    return res_data;
}

wickr_buffer_t *wickr_proto_handshake_response_data_serialize(const Wickr__Proto__HandshakeV1ResponseData *data)
{
    if (!data) {
        return NULL;
    }
    
    size_t buffer_size = wickr__proto__handshake_v1_response_data__get_packed_size(data);
    wickr_buffer_t *response_data_buffer = wickr_buffer_create_empty_zero(buffer_size);
    
    if (!response_data_buffer) {
        return NULL;
    }
    
    wickr__proto__handshake_v1_response_data__pack(data, response_data_buffer->bytes);
    return response_data_buffer;
}

Wickr__Proto__HandshakeV1ResponseData *wickr_proto_handshake_response_data_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    return wickr__proto__handshake_v1_response_data__unpack(NULL, buffer->length, buffer->bytes);
}

void wickr_proto_handshake_response_data_free(Wickr__Proto__HandshakeV1ResponseData *data)
{
    if (!data) {
        return;
    }
    
    wickr_transport_root_key_proto_free(data->root_key);
    wickr_free(data);
}

Wickr__Proto__HandshakeV1__Response *wickr_proto_handshake_response_create(const wickr_buffer_t *ephemeral_pubkey,
                                                                           const wickr_buffer_t *encrypted_response_data,
                                                                           const wickr_identity_chain_t *identity_chain)
{
    if (!ephemeral_pubkey || !encrypted_response_data) {
        return NULL;
    }
    
    Wickr__Proto__HandshakeV1__Response *response = wickr_alloc_zero(sizeof(Wickr__Proto__HandshakeV1__Response));
    
    if (!response) {
        return NULL;
    }
    
    wickr__proto__handshake_v1__response__init(response);
    
    if (identity_chain) {
        response->id_chain = wickr_identity_chain_to_proto(identity_chain);
        if (!response->id_chain) {
            wickr_free(response);
            return NULL;
        }
    }
    
    if (!wickr_buffer_to_protobytes(&response->ephemeral_pubkey, ephemeral_pubkey)) {
        wickr_free(response);
        return NULL;
    }
    
    if (!wickr_buffer_to_protobytes(&response->encrypted_response_data, encrypted_response_data)) {
        wickr_free(response);
        return NULL;
    }
    
    response->has_ephemeral_pubkey = true;
    response->has_encrypted_response_data = true;
    
    return response;
}

void wickr_proto_handshake_response_free(Wickr__Proto__HandshakeV1__Response *response)
{
    if (!response) {
        return;
    }
    
    wickr_identity_chain_proto_free(response->id_chain);
    wickr_free(response->ephemeral_pubkey.data);
    wickr_free(response->encrypted_response_data.data);
    wickr_free(response);
}

Wickr__Proto__HandshakeV1 *wickr_proto_handshake_create_with_seed(Wickr__Proto__HandshakeV1__Seed *seed)
{
    if (!seed) {
        return NULL;
    }
    
    Wickr__Proto__HandshakeV1 *proto_handshake = wickr_alloc_zero(sizeof(Wickr__Proto__HandshakeV1));
    
    if (!proto_handshake) {
        return NULL;
    }
    
    wickr__proto__handshake_v1__init(proto_handshake);
    
    proto_handshake->payload_case = WICKR__PROTO__HANDSHAKE_V1__PAYLOAD_SEED;
    proto_handshake->seed = seed;
    
    return proto_handshake;
}

Wickr__Proto__HandshakeV1 *wickr_proto_handshake_create_with_response(Wickr__Proto__HandshakeV1__Response *response)
{
    if (!response) {
        return NULL;
    }
    
    Wickr__Proto__HandshakeV1 *proto_handshake = wickr_alloc_zero(sizeof(Wickr__Proto__HandshakeV1));
    
    if (!proto_handshake) {
        return NULL;
    }
    
    wickr__proto__handshake_v1__init(proto_handshake);
    
    proto_handshake->payload_case = WICKR__PROTO__HANDSHAKE_V1__PAYLOAD_RESPONSE;
    proto_handshake->response = response;
    
    return proto_handshake;
}

void wickr_proto_handshake_free(Wickr__Proto__HandshakeV1 *handshake)
{
    if (!handshake) {
        return;
    }
    
    switch (handshake->payload_case) {
        case WICKR__PROTO__HANDSHAKE_V1__PAYLOAD_SEED:
            wickr_proto_handshake_seed_free(handshake->seed);
            break;
        case WICKR__PROTO__HANDSHAKE_V1__PAYLOAD_RESPONSE:
            wickr_proto_handshake_response_free(handshake->response);
        default:
            break;
    }
    
    wickr_free(handshake);
}

wickr_buffer_t *wickr_proto_handshake_serialize(const Wickr__Proto__HandshakeV1 *handshake)
{
    if (!handshake) {
        return NULL;
    }
    
    size_t packed_size = wickr__proto__handshake_v1__get_packed_size(handshake);
    
    wickr_buffer_t *packed_buffer = wickr_buffer_create_empty(packed_size);
    
    if (!packed_buffer) {
        return NULL;
    }
    
    wickr__proto__handshake_v1__pack(handshake, packed_buffer->bytes);
    
    return packed_buffer;
}

Wickr__Proto__HandshakeV1 *wickr_proto_handshake_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    return wickr__proto__handshake_v1__unpack(NULL, buffer->length, buffer->bytes);
}

Wickr__Proto__HandshakeV1 *wickr_proto_handshake_from_packet(const wickr_transport_packet_t *packet)
{
    if (!packet || packet->meta.body_type != TRANSPORT_PAYLOAD_TYPE_HANDSHAKE) {
        return NULL;
    }
    
    return wickr_proto_handshake_from_buffer(packet->body);
}

wickr_transport_packet_t *wickr_proto_handshake_to_packet(const Wickr__Proto__HandshakeV1 *handshake)
{
    if (!handshake) {
        return NULL;
    }
    
    wickr_buffer_t *buffer = wickr_proto_handshake_serialize(handshake);
    
    if (!buffer) {
        return NULL;
    }
    
    wickr_transport_packet_meta_t meta;
    wickr_transport_packet_meta_initialize_handshake(&meta, 1, TRANSPORT_MAC_TYPE_NONE); /* Will get signed later to adjust mac type */
    
    wickr_transport_packet_t *packet = wickr_transport_packet_create(meta, buffer);
    
    if (!packet) {
        wickr_buffer_destroy(&buffer);
    }
    
    return packet;
}
