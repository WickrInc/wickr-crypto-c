//
//  stream_iv.c
//  Crypto
//
//  Created by Tom Leavy on 4/18/17.
//
//

#include "stream_iv.h"
#include "memory.h"

wickr_stream_iv_t *wickr_stream_iv_create(const wickr_crypto_engine_t engine, wickr_cipher_t cipher)
{
    
    wickr_buffer_t *seed = engine.wickr_crypto_engine_crypto_random(DIGEST_SHA_512.size);
    
    if (!seed) {
        return NULL;
    }
    
    wickr_stream_iv_t *new_iv = wickr_alloc_zero(sizeof(wickr_stream_iv_t));
    
    if (!new_iv) {
        wickr_buffer_destroy(&seed);
        return NULL;
    }
    
    new_iv->cipher = cipher;
    new_iv->gen_count = 0;
    new_iv->seed = seed;
    new_iv->engine = engine;
    
    return new_iv;
}

wickr_stream_iv_t *wickr_stream_iv_copy(const wickr_stream_iv_t *iv)
{
    if (!iv) {
        return NULL;
    }
    
    wickr_buffer_t *seed_copy = wickr_buffer_copy(iv->seed);
    
    if (!seed_copy) {
        return NULL;
    }
    
    wickr_stream_iv_t *copy_iv = wickr_alloc_zero(sizeof(wickr_stream_iv_t));
    
    if (!copy_iv) {
        wickr_buffer_destroy(&seed_copy);
        return NULL;
    }
    
    copy_iv->engine = iv->engine;
    copy_iv->cipher = iv->cipher;
    copy_iv->gen_count = iv->gen_count;
    copy_iv->seed = seed_copy;
    
    return copy_iv;
}

void wickr_stream_iv_destroy(wickr_stream_iv_t **iv)
{
    if (!iv || !*iv) {
        return;
    }
    
    wickr_buffer_destroy(&(*iv)->seed);
    wickr_free(*iv);
    *iv = NULL;
}

wickr_buffer_t *wickr_stream_iv_generate(wickr_stream_iv_t *iv)
{
    if (!iv) {
        return NULL;
    }
    
    wickr_buffer_t seq_buffer = { sizeof(uint64_t), (uint8_t *)&iv->gen_count };
    wickr_buffer_t *iv_buffer = iv->engine.wickr_crypto_engine_hmac_create(&seq_buffer, iv->seed, DIGEST_SHA_512);
    
    if (!iv_buffer) {
        return NULL;
    }
    
    iv_buffer->length = iv->cipher.iv_len;
    iv->gen_count++;
    
    return iv_buffer;
}
