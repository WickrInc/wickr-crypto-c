/*
* Copyright © 2012-2020 Wickr Inc.  All rights reserved.
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

#ifndef transport_handshake_priv_h
#define transport_handshake_priv_h

#include "stream.pb-c.h"
#include "private/transport_priv.h"
#include "transport_root_key.h"

struct wickr_transport_handshake_t {
    wickr_crypto_engine_t engine;
    wickr_identity_chain_t *local_identity;
    wickr_identity_chain_t *remote_identity;
    wickr_array_t *packet_list;
    wickr_transport_handshake_identity_callback identity_callback;
    wickr_transport_handshake_status status;
    wickr_ec_key_t *local_ephemeral_key;
    wickr_transport_root_key_t *root_key;
    wickr_transport_packet_t *pending_identity_verify_packet;
    bool is_initiator;
    uint8_t protocol_version;
    uint32_t evo_count;
    void *user;
};

Wickr__Proto__HandshakeV1__Seed *wickr_proto_handshake_seed_create(const wickr_identity_chain_t *id_chain,
                                                                   const wickr_buffer_t *ephemeral_pub_key,
                                                                   bool needs_remote_identity);
void wickr_proto_handshake_seed_free(Wickr__Proto__HandshakeV1__Seed *seed);
Wickr__Proto__HandshakeV1__Response *wickr_proto_handshake_response_create(const wickr_buffer_t *ephemeral_pubkey,
                                                                           const wickr_buffer_t *encrypted_response_data,
                                                                           const wickr_identity_chain_t *identity_chain);
void wickr_proto_handshake_response_free(Wickr__Proto__HandshakeV1__Response *response);
Wickr__Proto__HandshakeV1 *wickr_proto_handshake_create_with_seed(Wickr__Proto__HandshakeV1__Seed *seed);
Wickr__Proto__HandshakeV1 *wickr_proto_handshake_create_with_response(Wickr__Proto__HandshakeV1__Response *response);
void wickr_proto_handshake_free(Wickr__Proto__HandshakeV1 *handshake);
wickr_buffer_t *wickr_proto_handshake_serialize(const Wickr__Proto__HandshakeV1 *handshake);
Wickr__Proto__HandshakeV1 *wickr_proto_handshake_from_buffer(const wickr_buffer_t *buffer);
Wickr__Proto__HandshakeV1 *wickr_proto_handshake_from_packet(const wickr_transport_packet_t *packet);
wickr_transport_packet_t *wickr_proto_handshake_to_packet(const Wickr__Proto__HandshakeV1 *handshake);

Wickr__Proto__HandshakeV1ResponseData *wickr_proto_handshake_response_data_create(const wickr_transport_root_key_t *root_key);

wickr_buffer_t *wickr_proto_handshake_response_data_serialize(const Wickr__Proto__HandshakeV1ResponseData *data);
Wickr__Proto__HandshakeV1ResponseData *wickr_proto_handshake_response_data_from_buffer(const wickr_buffer_t *buffer);
void wickr_proto_handshake_response_data_free(Wickr__Proto__HandshakeV1ResponseData *data);

#endif /* transport_handshake_priv */
