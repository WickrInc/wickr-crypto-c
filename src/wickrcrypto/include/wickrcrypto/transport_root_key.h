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
