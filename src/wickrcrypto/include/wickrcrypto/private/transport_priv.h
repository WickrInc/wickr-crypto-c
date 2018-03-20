/*
 * Copyright © 2012-2018 Wickr Inc.  All rights reserved.
 *
 * This code is being released for EDUCATIONAL, ACADEMIC, AND CODE REVIEW PURPOSES
 * ONLY.  COMMERCIAL USE OF THE CODE IS EXPRESSLY PROHIBITED.  For additional details,
 * please see LICENSE
 *
 * THE CODE IS MADE AVAILABLE "AS-IS" AND WITHOUT ANY EXPRESS OR
 * IMPLIED GUARANTEES AS TO FITNESS, MERCHANTABILITY, NON-
 * INFRINGEMENT OR OTHERWISE. IT IS NOT BEING PROVIDED IN TRADE BUT ON
 * A VOLUNTARY BASIS ON BEHALF OF THE AUTHOR’S PART FOR THE BENEFIT
 * OF THE LICENSEE AND IS NOT MADE AVAILABLE FOR CONSUMER USE OR ANY
 * OTHER USE OUTSIDE THE TERMS OF THIS LICENSE. ANYONE ACCESSING THE
 * CODE SHOULD HAVE THE REQUISITE EXPERTISE TO SECURE THEIR SYSTEM
 * AND DEVICES AND TO ACCESS AND USE THE CODE FOR REVIEW PURPOSES
 * ONLY. LICENSEE BEARS THE RISK OF ACCESSING AND USING THE CODE. IN
 * PARTICULAR, AUTHOR BEARS NO LIABILITY FOR ANY INTERFERENCE WITH OR
 * ADVERSE EFFECT THAT MAY OCCUR AS A RESULT OF THE LICENSEE
 * ACCESSING AND/OR USING THE CODE ON LICENSEE’S SYSTEM.
 */

#ifndef transport_priv_h
#define transport_priv_h

#include "transport_ctx.h"
#include "stream_ctx.h"
#include "stream.pb-c.h"

typedef enum { TRANSPORT_MAC_TYPE_NONE, TRANSPORT_MAC_TYPE_AUTH_CIPHER, TRANSPORT_MAC_TYPE_EC_P521 } wickr_transport_mac_type;

struct wickr_transport_ctx {
    wickr_crypto_engine_t engine;
    wickr_node_t *local_identity;
    wickr_node_t *remote_identity;
    wickr_stream_ctx_t *rx_stream;
    wickr_stream_ctx_t *tx_stream;
    wickr_transport_status status;
    uint32_t evo_count;
    wickr_transport_callbacks_t callbacks;
    void *user;
    wickr_transport_data_flow data_flow;
};

#define CURRENT_HANDSHAKE_VERSION 1
#define TRANSPORT_PKT_HEADER_SIZE (sizeof(uint64_t) + sizeof(uint8_t))


typedef enum { WICKR_HANDSHAKE_PHASE_INIT, WICKR_HANDSHAKE_PHASE_RESPONSE, WICKR_HANDSHAKE_PHASE_FINALIZE } wickr_handshake_phase;

struct wickr_transport_packet {
    uint64_t seq_num;
    wickr_transport_payload_type body_type;
    wickr_buffer_t *body;
    wickr_transport_mac_type mac_type;
    wickr_buffer_t *mac;
};

typedef struct wickr_transport_packet wickr_transport_packet_t;

wickr_transport_packet_t *wickr_transport_packet_create(uint64_t seq_num,
                                                        wickr_transport_payload_type body_type,
                                                        wickr_buffer_t *body);

wickr_transport_packet_t *wickr_transport_packet_copy(const wickr_transport_packet_t *pkt);

void wickr_transport_packet_destroy(wickr_transport_packet_t **pkt);

wickr_buffer_t *wickr_transport_packet_serialize(const wickr_transport_packet_t *pkt);

wickr_transport_packet_t *wickr_transport_packet_create_from_buffer(const wickr_buffer_t *buffer);

bool wickr_transport_packet_sign(wickr_transport_packet_t *pkt,
                                 const wickr_crypto_engine_t *engine,
                                 const wickr_identity_t *identity);

bool wickr_transport_packet_verify(const wickr_transport_packet_t *packet,
                                   const wickr_buffer_t *packet_buffer,
                                   const wickr_crypto_engine_t *engine,
                                   const wickr_identity_t *identity);

wickr_buffer_t *wickr_transport_packet_make_meta_buffer(const wickr_transport_packet_t *pkt);

wickr_transport_packet_t *wickr_transport_packet_create_proto_handshake(const wickr_transport_ctx_t *ctx,
                                                                        const Wickr__Proto__Handshake *handshake);

Wickr__Proto__Handshake *wickr_transport_packet_to_proto_handshake(const wickr_transport_packet_t *packet,
                                                                   Wickr__Proto__Handshake__PayloadCase expected_payload);

#endif /* transport_priv_h */
