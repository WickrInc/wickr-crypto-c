
#include "transport_packet.h"
#include "memory.h"
#include <string.h>

void wickr_transport_packet_meta_initialize_handshake(wickr_transport_packet_meta_t *meta_out,
                                                      uint8_t protocol_version,
                                                      wickr_transport_packet_mac_type mac_type)
{
    meta_out->mac_type = mac_type;
    meta_out->body_type = TRANSPORT_PAYLOAD_TYPE_HANDSHAKE;
    meta_out->body_meta.handshake.flags = 0;
    meta_out->body_meta.handshake.protocol_version = protocol_version;
}

void wickr_transport_packet_meta_initialize_data(wickr_transport_packet_meta_t *meta_out,
                                                 uint64_t sequence_number,
                                                 wickr_transport_packet_mac_type mac_type)
{
    meta_out->mac_type = mac_type;
    meta_out->body_type = TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT;
    meta_out->body_meta.data.sequence_number = sequence_number;
}

wickr_buffer_t *wickr_transport_packet_meta_serialize(const wickr_transport_packet_meta_t *meta)
{
    if (!meta) {
        return NULL;
    }
    
    uint8_t length = 0;
    
    switch (meta->body_type) {
        case TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT:
            length = sizeof(uint8_t) /* body + mac type */ + sizeof(uint64_t); /* seq_number */
            break;
        case TRANSPORT_PAYLOAD_TYPE_HANDSHAKE:
            length = sizeof(uint8_t) /* body + mac type */ + sizeof(uint8_t) /* protocol version */ + sizeof(uint64_t); /* flags */
        default:
            break;
    }
    
    wickr_buffer_t *serialized = wickr_buffer_create_empty_zero(length);
    
    if (!serialized) {
        return NULL;
    }
    
    size_t pos = 0;
    
    serialized->bytes[0] = (((uint8_t)meta->body_type) << 4) | ((uint8_t)meta->mac_type);
    
    pos += sizeof(uint8_t);
    
    switch (meta->body_type) {
        case TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT:
            if (!wickr_buffer_modify_section(serialized, (uint8_t *)&meta->body_meta.data.sequence_number, pos, sizeof(uint64_t))) {
                wickr_buffer_destroy(&serialized);
                return NULL;
            }
            pos += sizeof(uint64_t);
            break;
        case TRANSPORT_PAYLOAD_TYPE_HANDSHAKE:
            if (!wickr_buffer_modify_section(serialized, (uint8_t *)&meta->body_meta.handshake.protocol_version, pos, sizeof(uint8_t))) {
                wickr_buffer_destroy(&serialized);
                return NULL;
            }
            pos += sizeof(uint8_t);
            if (!wickr_buffer_modify_section(serialized, (uint8_t *)&meta->body_meta.handshake.flags, pos, sizeof(uint64_t))) {
                wickr_buffer_destroy(&serialized);
                return NULL;
            }
            pos += sizeof(uint64_t);
            break;
        default:
            wickr_buffer_destroy(&serialized);
            return NULL;
    }
    
    return serialized;
}

int wickr_transport_packet_meta_initialize_buffer(wickr_transport_packet_meta_t *meta_out, const wickr_buffer_t *buffer)
{
    if (!buffer || buffer->length <= 1) {
        return -1;
    }
    
    int loc = 0;
    
    uint8_t type_data = buffer->bytes[0];
    
    meta_out->body_type = (type_data & 0xF0) >> 4;
    meta_out->mac_type = type_data & 0xF;
    
    loc += sizeof(uint8_t);
    
    switch (meta_out->body_type) {
        case TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT:
            
            if (buffer->length < (sizeof(uint8_t) + sizeof(uint64_t))) {
                return -1;
            }
            
            memcpy(&meta_out->body_meta.data.sequence_number, buffer->bytes + sizeof(uint8_t), sizeof(uint64_t));
            loc += sizeof(uint64_t);
            
            break;
        case TRANSPORT_PAYLOAD_TYPE_HANDSHAKE:
            
            if (buffer->length < (sizeof(uint8_t) * 2 + sizeof(uint64_t))) {
                return -1;
            }
            
            meta_out->body_meta.handshake.protocol_version = (uint8_t)buffer->bytes[sizeof(uint8_t)];
            loc += sizeof(uint8_t);
            memcpy(&meta_out->body_meta.handshake.flags, buffer->bytes + sizeof(uint8_t) * 2, sizeof(uint64_t));
            loc += sizeof(uint64_t);
            
            break;
        default:
            return -2;
    }
    
    return loc;
}

wickr_transport_packet_t *wickr_transport_packet_create(wickr_transport_packet_meta_t meta, wickr_buffer_t *body)
{
    if (!body) {
        return NULL;
    }
    
    wickr_transport_packet_t *transport_pkt = wickr_alloc_zero(sizeof(wickr_transport_packet_t));
    
    if (!transport_pkt) {
        return NULL;
    }
    
    transport_pkt->meta = meta;
    transport_pkt->body = body;
        
    return transport_pkt;
}

wickr_transport_packet_t *wickr_transport_packet_copy(const wickr_transport_packet_t *pkt)
{
    if (!pkt) {
        return NULL;
    }
    
    wickr_buffer_t *body_copy = wickr_buffer_copy(pkt->body);
    
    if (!body_copy) {
        return NULL;
    }
    
    wickr_buffer_t *mac_copy = wickr_buffer_copy(pkt->mac);
    
    if (pkt->mac && !mac_copy) {
        wickr_buffer_destroy(&body_copy);
        return NULL;
    }
    
    wickr_transport_packet_t *copy =wickr_transport_packet_create(pkt->meta,
                                                                  body_copy);
    
    if (!copy) {
        wickr_buffer_destroy(&body_copy);
        wickr_buffer_destroy(&mac_copy);
        return NULL;
    }
    
    copy->mac = mac_copy;
    
    return copy;
}

void wickr_transport_packet_destroy(wickr_transport_packet_t **pkt)
{
    if (!pkt || !*pkt) {
        return;
    }
    
    wickr_buffer_destroy(&(*pkt)->network_buffer);
    wickr_buffer_destroy(&(*pkt)->body);
    wickr_buffer_destroy(&(*pkt)->mac);
    wickr_free(*pkt);
    *pkt = NULL;
}

wickr_buffer_t *wickr_transport_packet_serialize(const wickr_transport_packet_t *pkt)
{
    if (!pkt) {
        return NULL;
    }
    
    wickr_buffer_t *meta_buffer = wickr_transport_packet_meta_serialize(&pkt->meta);
    
    if (!meta_buffer) {
        return NULL;
    }
    
    wickr_buffer_t *components[] = { meta_buffer, pkt->body, pkt->mac };
    wickr_buffer_t *return_buffer = wickr_buffer_concat_multi(components, BUFFER_ARRAY_LEN(components));
    wickr_buffer_destroy(&meta_buffer);
        
    return return_buffer;
}

wickr_transport_packet_t *wickr_transport_packet_create_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    wickr_transport_packet_meta_t meta;
    
    int start_pos = wickr_transport_packet_meta_initialize_buffer(&meta, buffer);
    
    if (start_pos <= 0) {
        return NULL;
    }
    
    size_t mac_size = 0;
    
    switch (meta.mac_type) {
        case TRANSPORT_MAC_TYPE_EC_P521:
            mac_size = EC_CURVE_NIST_P521.signature_size;
            break;
        default:
            mac_size = 0;
    }
    
    if (buffer->length <= (start_pos + mac_size)) {
        return NULL;
    }
    
    wickr_buffer_t *mac_buffer = NULL;
    
    if (mac_size != 0) {
        mac_buffer = wickr_buffer_copy_section(buffer, buffer->length - mac_size, mac_size);
        
        if (!mac_buffer) {
            return NULL;
        }
    }
    
    wickr_buffer_t *body_buffer = wickr_buffer_copy_section(buffer, start_pos,
                                                            buffer->length - mac_size - start_pos);
    
    if (!body_buffer) {
        wickr_buffer_destroy(&mac_buffer);
        return NULL;
    }
    
    wickr_transport_packet_t *pkt = wickr_transport_packet_create(meta, body_buffer);
    
    if (!pkt) {
        wickr_buffer_destroy(&mac_buffer);
        wickr_buffer_destroy(&body_buffer);
        return NULL;
    }
    
    pkt->mac = mac_buffer;
    
    /* Keep a copy of the network buffer for later use of verifying signature */
    pkt->network_buffer = wickr_buffer_copy(buffer);
    
    if (!pkt->network_buffer) {
        wickr_transport_packet_destroy(&pkt);
        return NULL;
    }
    
    return pkt;
}

bool wickr_transport_packet_sign(wickr_transport_packet_t *pkt, const wickr_crypto_engine_t *engine, const wickr_identity_chain_t *identity_chain)
{
    if (!pkt || !engine || !identity_chain) {
        return false;
    }
    
    wickr_transport_packet_mac_type new_mac_type;
    
    switch (identity_chain->node->sig_key->curve.identifier) {
        case EC_CURVE_ID_NIST_P521:
            new_mac_type = TRANSPORT_MAC_TYPE_EC_P521;
            break;
        default:
            return false;
    }
    
    wickr_transport_packet_mac_type old_mac_type = pkt->meta.mac_type;
    
    pkt->meta.mac_type = new_mac_type;
    wickr_buffer_t *data_to_sign = wickr_transport_packet_serialize(pkt);
    pkt->meta.mac_type = old_mac_type;
    
    if (!data_to_sign) {
        return false;
    }
    
    wickr_ecdsa_result_t *signature = wickr_identity_sign(identity_chain->node, engine, data_to_sign);
    wickr_buffer_destroy(&data_to_sign);
    
    if (!signature) {
        return false;
    }
    
    wickr_buffer_t *signature_buffer = wickr_ecdsa_result_serialize(signature);
    wickr_ecdsa_result_destroy(&signature);
    
    if (!signature_buffer) {
        return false;
    }
    
    pkt->mac = signature_buffer;
    pkt->meta.mac_type = new_mac_type;
    
    pkt->network_buffer = wickr_transport_packet_serialize(pkt);
    
    return pkt->network_buffer != NULL;
}

bool wickr_transport_packet_verify(const wickr_transport_packet_t *packet, const wickr_crypto_engine_t *engine, wickr_identity_chain_t *identity_chain)
{
    if (!identity_chain || !packet || !packet->mac || packet->meta.mac_type != TRANSPORT_MAC_TYPE_EC_P521) {
        return false;
    }
    
    if (!packet->network_buffer) {
        wickr_buffer_t *network_buffer = wickr_transport_packet_serialize(packet);
        if (!network_buffer) {
            return NULL;
        }
        ((wickr_transport_packet_t *)packet)->network_buffer = network_buffer;
    }
    
    if (!wickr_identity_chain_validate(identity_chain, engine)) {
        return false;
    }
    
    if (packet->network_buffer->length <= packet->mac->length) {
        return false;
    }
    
    wickr_ecdsa_result_t *signature = wickr_ecdsa_result_create_from_buffer(packet->mac);
    
    if (!signature) {
        return false;
    }
    
    /* Create a temp buffer with a length that puts it's end before the start of the mac */
    wickr_buffer_t validation_buffer;
    validation_buffer.bytes = packet->network_buffer->bytes;
    validation_buffer.length = packet->network_buffer->length - packet->mac->length;
    
    bool return_val = engine->wickr_crypto_engine_ec_verify(signature, identity_chain->node->sig_key, &validation_buffer);
    
    wickr_ecdsa_result_destroy(&signature);
    
    return return_val;
}
