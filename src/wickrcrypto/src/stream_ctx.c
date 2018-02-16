
#include "stream_ctx.h"
#include "memory.h"
#include "stream.pb-c.h"
#include "private/stream_key_priv.h"

wickr_stream_ctx_t *wickr_stream_ctx_create(const wickr_crypto_engine_t engine, wickr_stream_key_t *stream_key, wickr_stream_direction direction)
{
    if (!stream_key || !stream_key->cipher_key->cipher.is_authenticated) {
        return NULL;
    }
    
    wickr_stream_iv_t *iv_factory = NULL;
    
    if (direction == STREAM_DIRECTION_ENCODE) {
        iv_factory = wickr_stream_iv_create(engine, stream_key->cipher_key->cipher);
        
        if (!iv_factory) {
            return NULL;
        }
    }
    
    wickr_stream_ctx_t *stream_cipher = wickr_alloc_zero(sizeof(wickr_stream_ctx_t));
    
    if (!stream_cipher) {
        return NULL;
    }
    
    stream_cipher->engine = engine;
    stream_cipher->key = stream_key;
    stream_cipher->last_seq = 0;
    stream_cipher->direction = direction;
    stream_cipher->iv_factory = iv_factory;
    stream_cipher->ref_count = 1;
    
    return stream_cipher;
}

wickr_stream_ctx_t *wickr_stream_ctx_copy(const wickr_stream_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    
    wickr_stream_key_t *key_copy = wickr_stream_key_copy(ctx->key);
    
    if (!key_copy) {
        return NULL;
    }
    
    wickr_stream_iv_t *iv_copy = wickr_stream_iv_copy(ctx->iv_factory);
    
    if (!iv_copy && ctx->direction == STREAM_DIRECTION_ENCODE) {
        wickr_stream_key_destroy(&key_copy);
        return NULL;
    }
    
    wickr_stream_ctx_t *stream_cipher = wickr_alloc_zero(sizeof(wickr_stream_ctx_t));
    
    if (!stream_cipher) {
        wickr_stream_key_destroy(&key_copy);
        wickr_stream_iv_destroy(&iv_copy);
        return NULL;
    }
    
    stream_cipher->engine = ctx->engine;
    stream_cipher->key = key_copy;
    stream_cipher->last_seq = ctx->last_seq;
    stream_cipher->direction = ctx->direction;
    stream_cipher->iv_factory = iv_copy;
    stream_cipher->ref_count = 1;
    
    return stream_cipher;
}

bool __wickr_stream_ctx_ref_down(wickr_stream_ctx_t *ctx)
{
    if (ctx->ref_count != 0) {
        ctx->ref_count -= 1;
    }
    
    return ctx->ref_count == 0;
}

bool wickr_stream_ctx_ref_up(wickr_stream_ctx_t *ctx)
{
    if (!ctx || ctx->ref_count == SIZE_MAX) {
        return false;
    }
    
    ctx->ref_count += 1;
    
    return true;
}

static wickr_stream_key_t *__wickr_stream_key_create_with_evo_buffer(wickr_stream_key_t *old_key, wickr_buffer_t *evo_buffer)
{
    if (!old_key || !evo_buffer) {
        return NULL;
    }
    
    wickr_buffer_t *new_crypto_key = wickr_buffer_copy_section(evo_buffer, 0, DIGEST_SHA_512.size / 2);
    
    if (!new_crypto_key) {
        return NULL;
    }
    
    wickr_buffer_t *new_evo_key = wickr_buffer_copy_section(evo_buffer, DIGEST_SHA_512.size / 2, DIGEST_SHA_512.size / 2);
    
    if (!new_evo_key) {
        wickr_buffer_destroy(&new_crypto_key);
        return NULL;
    }
    
    wickr_cipher_key_t *cipher_key = wickr_cipher_key_create(old_key->cipher_key->cipher, new_crypto_key);
    
    if (!cipher_key) {
        wickr_buffer_destroy(&new_crypto_key);
        wickr_buffer_destroy(&new_evo_key);
        return NULL;
    }
    
    wickr_stream_key_t *new_key = wickr_stream_key_create(cipher_key, new_evo_key, old_key->packets_per_evolution);
    
    if (!new_key) {
        wickr_cipher_key_destroy(&cipher_key);
        wickr_buffer_destroy(&new_evo_key);
        return NULL;
    }
    
    return new_key;
}

static bool __wickr_stream_ctx_evolove_key_material(wickr_stream_ctx_t *encoder, uint64_t seq_num)
{
    if (!encoder) {
        return false;
    }
    
    uint64_t curr_evo = encoder->last_seq / encoder->key->packets_per_evolution;
    uint64_t seq_evo = seq_num / encoder->key->packets_per_evolution;

    if (seq_evo < curr_evo) {
        return false;
    }
    
    if (seq_evo == curr_evo) {
        return true;
    }
    
    wickr_stream_key_t *curr_key = wickr_stream_key_copy(encoder->key);
    
    if (!curr_key) {
        return false;
    }
    
    while (curr_evo != seq_evo) {
        
        wickr_buffer_t *evo_buffer = encoder->engine.wickr_crypto_engine_hmac_create(curr_key->cipher_key->key_data,
                                                                                      curr_key->evolution_key,
                                                                                      DIGEST_SHA_512);
        
        if (!evo_buffer) {
            wickr_stream_key_destroy(&curr_key);
            return false;
        }
        
        wickr_stream_key_t *new_key = __wickr_stream_key_create_with_evo_buffer(curr_key, evo_buffer);
        wickr_stream_key_destroy(&curr_key);
        wickr_buffer_destroy(&evo_buffer);

        if (!new_key) {
            return false;
        }
        
        curr_key = new_key;
        curr_evo++;
    }
    
    wickr_stream_key_destroy(&encoder->key);
    encoder->key = curr_key;
    
    return true;
}

wickr_cipher_result_t *wickr_stream_ctx_encode(wickr_stream_ctx_t *ctx, const wickr_buffer_t *data, const wickr_buffer_t *aad, uint64_t seq_num)
{
    if (!data || seq_num <= ctx->last_seq || ctx->direction != STREAM_DIRECTION_ENCODE) {
        return NULL;
    }
    
    wickr_buffer_t *iv = wickr_stream_iv_generate(ctx->iv_factory);
    
    if (!iv) {
        return NULL;
    }
    
    if (!__wickr_stream_ctx_evolove_key_material(ctx, seq_num)) {
        wickr_buffer_destroy(&iv);
        return NULL;
    }
    
    wickr_cipher_result_t *encrypt_result = ctx->engine.wickr_crypto_engine_cipher_encrypt(data, aad, ctx->key->cipher_key, iv);
    wickr_buffer_destroy(&iv);
    
    ctx->last_seq = seq_num;
    
    return encrypt_result;
}

wickr_buffer_t *wickr_stream_ctx_decode(wickr_stream_ctx_t *ctx, const wickr_cipher_result_t *data, const wickr_buffer_t *aad, uint64_t seq_num)
{
    if (!data || seq_num <= ctx->last_seq || ctx->direction != STREAM_DIRECTION_DECODE) {
        return NULL;
    }
    
    if (!__wickr_stream_ctx_evolove_key_material(ctx, seq_num)) {
        return NULL;
    }
    
    wickr_buffer_t *decrypt_result = ctx->engine.wickr_crypto_engine_cipher_decrypt(data, aad, ctx->key->cipher_key, true);
    
    ctx->last_seq = seq_num;
    
    return decrypt_result;
}

void wickr_stream_ctx_destroy(wickr_stream_ctx_t **ctx)
{
    if (!ctx || !*ctx) {
        return;
    }
    
    if (!__wickr_stream_ctx_ref_down(*ctx)) {
        return;
    }
    
    wickr_stream_key_destroy(&(*ctx)->key);
    wickr_stream_iv_destroy(&(*ctx)->iv_factory);
    wickr_free(*ctx);
    *ctx = NULL;
}
