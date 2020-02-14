//
//  transport_root_key.h
//  wickrcrypto
//
//  Created by Thomas Leavy on 1/24/20.
//

#ifndef transport_root_key_h
#define transport_root_key_h

#include "buffer.h"
#include "stream_ctx.h"

struct wickr_transport_root_key_t {
    wickr_buffer_t *secret;
    wickr_cipher_t cipher;
    uint32_t packets_per_evo_send;
    uint32_t packets_per_evo_recv;
};

typedef struct wickr_transport_root_key_t wickr_transport_root_key_t;

wickr_transport_root_key_t *wickr_transport_root_key_create_random(const wickr_crypto_engine_t *engine,
                                                                   wickr_cipher_t cipher,
                                                                   uint32_t packets_per_evo_send,
                                                                   uint32_t packets_per_evo_recv);

wickr_transport_root_key_t *wickr_transport_root_key_create(wickr_buffer_t *secret,
                                                            wickr_cipher_t cipher,
                                                            uint32_t packets_per_evo_send,
                                                            uint32_t packets_per_evo_recv);

wickr_transport_root_key_t *wickr_transport_root_key_copy(const wickr_transport_root_key_t *root_key);

void wickr_transport_root_key_destroy(wickr_transport_root_key_t **root_key);

wickr_stream_key_t *wickr_transport_root_key_to_stream_key(const wickr_crypto_engine_t *engine,
                                                           const wickr_transport_root_key_t *root_key,
                                                           const wickr_buffer_t *salt,
                                                           const wickr_buffer_t *stream_id,
                                                           wickr_stream_direction direction);

#endif /* transport_root_key_h */
