//
//  transport_packet.h
//  wickrcrypto
//
//  Created by Tom Leavy on 1/28/20.
//

#ifndef transport_packet_h
#define transport_packet_h

#include "buffer.h"
#include "identity.h"

typedef enum {
    TRANSPORT_PAYLOAD_TYPE_HANDSHAKE, /* Payload is a handshake control packet */
    TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT /* Payload contains encrypted application data */
} wickr_transport_packet_payload_type;

typedef enum {
    TRANSPORT_MAC_TYPE_NONE,
    TRANSPORT_MAC_TYPE_AUTH_CIPHER,
    TRANSPORT_MAC_TYPE_EC_P521
} wickr_transport_packet_mac_type;

struct wickr_transport_handshake_meta {
    uint8_t protocol_version;
    uint64_t flags; /* Future use */
};

typedef struct wickr_transport_handshake_meta wickr_transport_handshake_meta_t;

struct wickr_transport_data_meta {
    uint64_t sequence_number;
};

typedef struct wickr_transport_data_meta wickr_transport_data_meta_t;

struct wickr_transport_packet_meta {
    union {
        wickr_transport_handshake_meta_t handshake;
        wickr_transport_data_meta_t data;
    } body_meta;
    wickr_transport_packet_payload_type body_type;
    wickr_transport_packet_mac_type mac_type;
};

typedef struct wickr_transport_packet_meta wickr_transport_packet_meta_t;

void wickr_transport_packet_meta_initialize_handshake(wickr_transport_packet_meta_t *meta_out,
                                                      uint8_t protocol_version,
                                                      wickr_transport_packet_mac_type mac_type);

void wickr_transport_packet_meta_initialize_data(wickr_transport_packet_meta_t *meta_out,
                                                 uint64_t sequence_number,
                                                 wickr_transport_packet_mac_type mac_type);

int wickr_transport_packet_meta_initialize_buffer(wickr_transport_packet_meta_t *meta_out, const wickr_buffer_t *buffer);

wickr_buffer_t *wickr_transport_packet_meta_serialize(const wickr_transport_packet_meta_t *meta);

struct wickr_transport_packet {
    wickr_buffer_t *network_buffer;
    wickr_buffer_t *body;
    wickr_buffer_t *mac;
    wickr_transport_packet_meta_t meta;
};

typedef struct wickr_transport_packet wickr_transport_packet_t;

wickr_transport_packet_t *wickr_transport_packet_create(wickr_transport_packet_meta_t meta, wickr_buffer_t *body);

wickr_transport_packet_t *wickr_transport_packet_copy(const wickr_transport_packet_t *pkt);

void wickr_transport_packet_destroy(wickr_transport_packet_t **pkt);

wickr_buffer_t *wickr_transport_packet_serialize(const wickr_transport_packet_t *pkt);

wickr_transport_packet_t *wickr_transport_packet_create_from_buffer(const wickr_buffer_t *buffer);

bool wickr_transport_packet_sign(wickr_transport_packet_t *pkt,
                                 const wickr_crypto_engine_t *engine,
                                 const wickr_identity_chain_t *identity_chain);

bool wickr_transport_packet_verify(const wickr_transport_packet_t *packet,
                                   const wickr_crypto_engine_t *engine,
                                   wickr_identity_chain_t *identity_chain);

#endif /* transport_packet_h */
