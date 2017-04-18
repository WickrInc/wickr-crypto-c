/*
 * Copyright © 2012-2017 Wickr Inc.  All rights reserved.
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

#ifndef stream_cipher_h
#define stream_cipher_h

#include "crypto_engine.h"
#include "stream_iv.h"

#define PACKET_PER_EVO_MIN 64
#define PACKET_PER_EVO_MAX 32768

typedef enum { STREAM_DIRECTION_ENCODE, STREAM_DIRECTION_DECODE } wickr_stream_direction;

struct wickr_stream_key {
    wickr_cipher_key_t *cipher_key;
    wickr_buffer_t *evolution_key;
    uint32_t packets_per_evolution;
};

typedef struct wickr_stream_key wickr_stream_key_t;

struct wickr_stream_ctx {
    wickr_crypto_engine_t engine;
    wickr_stream_key_t *key;
    wickr_stream_iv_t *iv_factory;
    uint64_t last_seq;
    wickr_stream_direction direction;
};

typedef struct wickr_stream_ctx wickr_stream_ctx_t;

wickr_stream_key_t *wickr_stream_key_create(wickr_cipher_key_t *cipher_key, wickr_buffer_t *evolution_key, uint32_t packets_per_evolution);
wickr_stream_key_t *wickr_stream_key_create_rand(const wickr_crypto_engine_t engine, wickr_cipher_t cipher, uint32_t packets_per_evolution);
wickr_stream_key_t *wickr_stream_key_copy(const wickr_stream_key_t *stream_key);
wickr_buffer_t *wickr_stream_key_serialize(const wickr_stream_key_t *key);
wickr_stream_key_t *wickr_stream_key_create_from_buffer(const wickr_buffer_t *buffer);
void wickr_stream_key_destroy(wickr_stream_key_t **stream_key);

wickr_stream_ctx_t *wickr_stream_ctx_create(const wickr_crypto_engine_t engine, wickr_stream_key_t *stream_key, wickr_stream_direction direction);
wickr_stream_ctx_t *wickr_stream_ctx_copy(wickr_stream_ctx_t *ctx);
wickr_cipher_result_t *wickr_stream_ctx_encode(wickr_stream_ctx_t *ctx, const wickr_buffer_t *data, uint64_t seq_num);
wickr_buffer_t *wickr_stream_ctx_decode(wickr_stream_ctx_t *ctx, const wickr_cipher_result_t *data, uint64_t seq_num);
void wickr_stream_ctx_destroy(wickr_stream_ctx_t **ctx);

#endif /* stream_cipher_h */
