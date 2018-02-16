//
//  transport_priv.c
//  Crypto
//
//  Created by Tom Leavy on 5/10/17.
//
//

#include "private/transport_priv.h"
#include "memory.h"

wickr_transport_packet_t *wickr_transport_packet_create(uint64_t seq_num,
                                                        wickr_transport_payload_type body_type,
                                                        wickr_buffer_t *body)
{
    if (!body) {
        return NULL;
    }
    
    wickr_transport_packet_t *transport_pkt = wickr_alloc_zero(sizeof(wickr_transport_packet_t));
    
    if (!transport_pkt) {
        return NULL;
    }
    
    transport_pkt->seq_num = seq_num;
    transport_pkt->body_type = body_type;
    transport_pkt->body = body;
    transport_pkt->mac_type = TRANSPORT_MAC_TYPE_NONE;
    
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
    
    wickr_transport_packet_t *copy = wickr_transport_packet_create(pkt->seq_num, pkt->body_type, body_copy);
    
    if (!copy) {
        wickr_buffer_destroy(&body_copy);
        wickr_buffer_destroy(&mac_copy);
        return NULL;
    }
    
    copy->mac_type = pkt->mac_type;
    copy->mac = mac_copy;
    
    return copy;
}

void wickr_transport_packet_destroy(wickr_transport_packet_t **pkt)
{
    if (!pkt || !*pkt) {
        return;
    }
    
    wickr_buffer_destroy(&(*pkt)->body);
    wickr_buffer_destroy(&(*pkt)->mac);
    wickr_free(*pkt);
    *pkt = NULL;
}

wickr_buffer_t *wickr_transport_packet_make_meta_buffer(const wickr_transport_packet_t *pkt)
{
    if (!pkt) {
        return NULL;
    }
    
    wickr_buffer_t seq_buffer;
    seq_buffer.length = sizeof(uint64_t);
    seq_buffer.bytes = (uint8_t *)&pkt->seq_num;
    
    uint8_t type_data = (((uint8_t)pkt->body_type) << 4) | ((uint8_t)pkt->mac_type);
    
    wickr_buffer_t type_buffer;
    type_buffer.length = sizeof(uint8_t);
    type_buffer.bytes = &type_data;
    
    return wickr_buffer_concat(&seq_buffer, &type_buffer);
}

wickr_buffer_t *wickr_transport_packet_serialize(const wickr_transport_packet_t *pkt)
{
    if (!pkt) {
        return NULL;
    }
    
    wickr_buffer_t *meta_buffer = wickr_transport_packet_make_meta_buffer(pkt);
    
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
    if (!buffer || buffer->length <= TRANSPORT_PKT_HEADER_SIZE) {
        return NULL;
    }
    
    uint64_t seq_num = ((uint64_t *)buffer->bytes)[0];
    uint8_t type_data = buffer->bytes[sizeof(uint64_t)];
    
    const wickr_transport_payload_type payload_type = (type_data & 0xF0) >> 4;
    const wickr_transport_mac_type mac_type = type_data & 0xF;
    
    wickr_buffer_t *mac_buffer = NULL;
    
    switch (payload_type) {
        case TRANSPORT_PAYLOAD_TYPE_HANDSHAKE:
        {
            wickr_ec_curve_t curve;
            
            switch (mac_type) {
                case TRANSPORT_MAC_TYPE_EC_P521:
                    curve = EC_CURVE_NIST_P521;
                    break;
                default:
                    return NULL;
            }
            
            if (buffer->length <= (TRANSPORT_PKT_HEADER_SIZE + curve.signature_size)) {
                return NULL;
            }
            
            mac_buffer = wickr_buffer_copy_section(buffer, buffer->length - curve.signature_size, curve.signature_size);
            
            if (!mac_buffer) {
                return NULL;
            }
        }
            break;
        case TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT:
            /* Currently we only support authenticated ciphers for transports, so the mac will be NULL
             since the mac is included in the body as part of the wickr_cipher_result serialization. The
             GCM encryption for example will include the seq_num and type_buffer fields as AAD data so the GCM
             tag in the cipher_result will authenticate the entire packet. Future versions of the library may support
             CTR + HMAC, or something similar, which will create the need for placing the HMAC in the mac field */
            
            if (mac_type != TRANSPORT_MAC_TYPE_AUTH_CIPHER) {
                return NULL;
            }
            break;
        default:
            return NULL;
    }
    
    uint8_t start_pos = TRANSPORT_PKT_HEADER_SIZE;
    size_t mac_size = mac_buffer == NULL ? 0 : mac_buffer->length;
    
    wickr_buffer_t *body_buffer = wickr_buffer_copy_section(buffer, start_pos,
                                                            buffer->length - mac_size - start_pos);
    
    if (!body_buffer) {
        wickr_buffer_destroy(&mac_buffer);
        return NULL;
    }
    
    wickr_transport_packet_t *pkt = wickr_transport_packet_create(seq_num,
                                                                  payload_type,
                                                                  body_buffer);
    
    if (!pkt) {
        wickr_buffer_destroy(&mac_buffer);
        wickr_buffer_destroy(&body_buffer);
        return NULL;
    }
    
    pkt->mac_type = mac_type;
    pkt->mac = mac_buffer;
    
    return pkt;
}

bool wickr_transport_packet_sign(wickr_transport_packet_t *pkt, const wickr_crypto_engine_t *engine, const wickr_identity_t *identity)
{
    if (!pkt || !engine || !identity) {
        return false;
    }
    
    switch (identity->sig_key->curve.identifier) {
        case EC_CURVE_ID_NIST_P521:
            pkt->mac_type = TRANSPORT_MAC_TYPE_EC_P521;
            break;
        default:
            return NULL;
    }
    
    wickr_buffer_t *data_to_sign = wickr_transport_packet_serialize(pkt);
    
    if (!data_to_sign) {
        pkt->mac_type = TRANSPORT_MAC_TYPE_NONE;
        return false;
    }
    
    wickr_ecdsa_result_t *signature = wickr_identity_sign(identity, engine, data_to_sign);
    wickr_buffer_destroy(&data_to_sign);
    
    if (!signature) {
        pkt->mac_type = TRANSPORT_MAC_TYPE_NONE;
        return false;
    }
    
    wickr_buffer_t *signature_buffer = wickr_ecdsa_result_serialize(signature);
    wickr_ecdsa_result_destroy(&signature);
    
    if (!signature_buffer) {
        pkt->mac_type = TRANSPORT_MAC_TYPE_NONE;
        return false;
    }
    
    pkt->mac = signature_buffer;
    
    return true;
}

bool wickr_transport_packet_verify(const wickr_transport_packet_t *packet, const wickr_buffer_t *packet_buffer, const wickr_crypto_engine_t *engine, const wickr_identity_t *identity)
{
    if (!packet || !packet_buffer || !packet->mac) {
        return false;
    }
    
    if (packet_buffer->length <= packet->mac->length) {
        return false;
    }
    
    wickr_ecdsa_result_t *signature = wickr_ecdsa_result_create_from_buffer(packet->mac);
    
    if (!signature) {
        return false;
    }
    
    /* Create a temp buffer with a length that puts it's end before the start of the mac */
    wickr_buffer_t validation_buffer;
    validation_buffer.bytes = packet_buffer->bytes;
    validation_buffer.length = packet_buffer->length - packet->mac->length;
    
    bool return_val = engine->wickr_crypto_engine_ec_verify(signature, identity->sig_key, &validation_buffer);
    
    wickr_ecdsa_result_destroy(&signature);
    
    return return_val;
}

wickr_transport_packet_t *wickr_transport_packet_create_proto_handshake(const wickr_transport_ctx_t *ctx, const Wickr__Proto__Handshake *handshake)
{
    size_t packed_size = wickr__proto__handshake__get_packed_size(handshake);
    
    wickr_buffer_t *handshake_buffer = wickr_buffer_create_empty(packed_size);
    
    if (!handshake_buffer) {
        return NULL;
    }
    
    wickr__proto__handshake__pack(handshake, handshake_buffer->bytes);
    
    uint64_t seq_number = ctx->tx_stream->last_seq + 1;
    
    /* Create a temp packet with no mac so that we can sign it with the next function call */
    wickr_transport_packet_t *handshake_packet = wickr_transport_packet_create(seq_number, TRANSPORT_PAYLOAD_TYPE_HANDSHAKE, handshake_buffer);
    
    if (!handshake_packet) {
        wickr_buffer_destroy(&handshake_buffer);
        return NULL;
    }
    
    /* Sign the packet to set the correct mac type */
    if (!wickr_transport_packet_sign(handshake_packet, &ctx->engine, ctx->local_identity->id_chain->node)) {
        wickr_transport_packet_destroy(&handshake_packet);
        return NULL;
    }
    
    ctx->tx_stream->last_seq = seq_number;
    
    return handshake_packet;
}

Wickr__Proto__Handshake *wickr_transport_packet_to_proto_handshake(const wickr_transport_packet_t *packet,
                                                        Wickr__Proto__Handshake__PayloadCase expected_payload)
{
    if (!packet) {
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = wickr__proto__handshake__unpack(NULL, packet->body->length, packet->body->bytes);
    
    if (!handshake_data) {
        return NULL;
    }
    
    if (handshake_data->version != CURRENT_HANDSHAKE_VERSION ||
        handshake_data->payload_case != expected_payload)
    {
        wickr__proto__handshake__free_unpacked(handshake_data, NULL);
        return NULL;
    }
    
    return handshake_data;
}
