
#include "test_stream_cipher.h"
#include "stream_cipher.h"
#include "test_util.h"

static bool __wickr_stream_key_is_equal(wickr_stream_key_t *k1, wickr_stream_key_t *k2)
{
    if (!k1 || !k2) {
        return false;
    }
    
    if (!wickr_buffer_is_equal(k1->evolution_key, k2->evolution_key, NULL)) {
        return false;
    }
    
    if (!wickr_buffer_is_equal(k1->cipher_key->key_data, k2->cipher_key->key_data, NULL)) {
        return false;
    }
    
    if (k1->packets_per_evolution != k2->packets_per_evolution) {
        return false;
    }
    
    return true;
}

DESCRIBE(wickr_stream_key, "stream cipher key")
{
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();

    IT("requires a cipher key and evolution key")
    {
        wickr_cipher_key_t *cipher_key = engine.wickr_crypto_engine_cipher_key_random(CIPHER_AES256_GCM);
        wickr_buffer_t *evo_key = engine.wickr_crypto_engine_crypto_random(CIPHER_AES256_GCM.key_len);
        
        SHOULD_BE_NULL(wickr_stream_key_create(NULL, NULL, 0));
        SHOULD_BE_NULL(wickr_stream_key_create(NULL, evo_key, 32));
        SHOULD_BE_NULL(wickr_stream_key_create(cipher_key, NULL, 32));
        SHOULD_BE_NULL(wickr_stream_key_create(cipher_key, evo_key, 0));
        SHOULD_BE_NULL(wickr_stream_key_create(cipher_key, evo_key, PACKET_PER_EVO_MIN - 1));
        SHOULD_BE_NULL(wickr_stream_key_create(cipher_key, evo_key, PACKET_PER_EVO_MAX + 1));

        
        wickr_cipher_key_destroy(&cipher_key);
        wickr_buffer_destroy(&evo_key);
    }
    END_IT
    
    wickr_stream_key_t *stream_key = wickr_stream_key_create_rand(engine, CIPHER_AES256_GCM, PACKET_PER_EVO_MIN + 1);
    SHOULD_NOT_BE_NULL(stream_key);
    SHOULD_EQUAL(PACKET_PER_EVO_MIN + 1, stream_key->packets_per_evolution);
    
    IT("can be copied")
    {
        wickr_stream_key_t *copy_key = wickr_stream_key_copy(stream_key);
        SHOULD_NOT_BE_NULL(copy_key);
        SHOULD_BE_TRUE(__wickr_stream_key_is_equal(copy_key, stream_key));
        wickr_stream_key_destroy(&copy_key);
    }
    END_IT
    
    IT("can be created randomly")
    {
        wickr_stream_key_t *rand = stream_key;
        
        bool has_match = false;
        
        for (int i = 0; i < 1000; i++) {
            
            wickr_stream_key_t *another_rand = wickr_stream_key_create_rand(engine, CIPHER_AES256_GCM, rand->packets_per_evolution);
            
            if (wickr_buffer_is_equal(another_rand->evolution_key, rand->evolution_key, NULL) ||
                wickr_buffer_is_equal(another_rand->cipher_key->key_data, rand->cipher_key->key_data, NULL)) {
                has_match = true;
                break;
            }
            
            wickr_stream_key_destroy(&another_rand);
        }
        
        SHOULD_BE_FALSE(has_match);
        
    }
    END_IT
    
    IT("can be serialized and deserialized")
    {
        wickr_buffer_t *serialized = wickr_stream_key_serialize(stream_key);
        SHOULD_NOT_BE_NULL(serialized);
        
        wickr_stream_key_t *restored = wickr_stream_key_create_from_buffer(serialized);
        SHOULD_NOT_BE_NULL(restored);
        
        SHOULD_BE_TRUE(__wickr_stream_key_is_equal(stream_key, restored));
        
        wickr_buffer_destroy(&serialized);
        wickr_stream_key_destroy(&restored);
    }
    END_IT
    
    wickr_stream_key_destroy(&stream_key);
}
END_DESCRIBE

static void __test_encode_decode_evolution(wickr_stream_ctx_t *enc, wickr_stream_ctx_t *dec, uint64_t test_packet_num, bool should_evolove)
{
    wickr_stream_key_t *old_encode_key = wickr_stream_key_copy(enc->key);
    wickr_stream_key_t *old_decode_key = wickr_stream_key_copy(dec->key);
    
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    
    wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(1024);
    SHOULD_NOT_BE_NULL(test_data);
    
    wickr_cipher_result_t *encode = wickr_stream_ctx_encode(enc, test_data, NULL, test_packet_num);
    
    
    SHOULD_NOT_BE_NULL(encode);
    SHOULD_BE_FALSE(wickr_buffer_is_equal(encode->cipher_text, test_data, NULL));
    SHOULD_EQUAL(test_packet_num, enc->last_seq);
    
    if (should_evolove) {
        SHOULD_BE_FALSE(wickr_buffer_is_equal(enc->key->cipher_key->key_data, old_encode_key->cipher_key->key_data, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(enc->key->evolution_key, old_encode_key->evolution_key, NULL));
    }
    else {
        SHOULD_BE_TRUE(wickr_buffer_is_equal(enc->key->cipher_key->key_data, old_encode_key->cipher_key->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(enc->key->evolution_key, old_encode_key->evolution_key, NULL));
    }
    
    SHOULD_BE_NULL(wickr_stream_ctx_decode(dec, encode, NULL, 1));
    
    wickr_buffer_t *decode = wickr_stream_ctx_decode(dec, encode, NULL, test_packet_num);
    SHOULD_NOT_BE_NULL(decode);
    SHOULD_EQUAL(test_packet_num, dec->last_seq);
    
    SHOULD_BE_TRUE(wickr_buffer_is_equal(test_data, decode, NULL));
    
    if (should_evolove) {
        SHOULD_BE_FALSE(wickr_buffer_is_equal(dec->key->cipher_key->key_data, old_decode_key->cipher_key->key_data, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(dec->key->evolution_key, old_decode_key->evolution_key, NULL));
    }
    else {
        SHOULD_BE_TRUE(wickr_buffer_is_equal(enc->key->cipher_key->key_data, old_decode_key->cipher_key->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(enc->key->evolution_key, old_decode_key->evolution_key, NULL));
    }
    
    wickr_cipher_result_destroy(&encode);
    wickr_buffer_destroy(&test_data);
    wickr_buffer_destroy(&decode);
    wickr_stream_key_destroy(&old_decode_key);
    wickr_stream_key_destroy(&old_encode_key);
}

DESCRIBE(wickr_stream_cipher, "an stream of ciphered content")
{
    uint32_t test_evolution = PACKET_PER_EVO_MIN;
    
    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    wickr_stream_key_t *test_key = wickr_stream_key_create_rand(engine, CIPHER_AES256_GCM, test_evolution);
    
    IT("should be able to create a encode context")
    {
        SHOULD_BE_NULL(wickr_stream_ctx_create(engine, NULL, STREAM_DIRECTION_ENCODE));
        
        wickr_stream_ctx_t *ctx = wickr_stream_ctx_create(engine, wickr_stream_key_copy(test_key), STREAM_DIRECTION_ENCODE);
        SHOULD_NOT_BE_NULL(ctx);
        SHOULD_NOT_BE_NULL(ctx->iv_factory);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_key->cipher_key->key_data, ctx->key->cipher_key->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_key->evolution_key, ctx->key->evolution_key, NULL));
        SHOULD_EQUAL(STREAM_DIRECTION_ENCODE, ctx->direction);
        SHOULD_EQUAL(0, ctx->last_seq);
        
        wickr_stream_ctx_destroy(&ctx);
    }
    END_IT
    
    IT("should be able to create a decode context")
    {
        SHOULD_BE_NULL(wickr_stream_ctx_create(engine, NULL, STREAM_DIRECTION_DECODE));
        
        wickr_stream_ctx_t *ctx = wickr_stream_ctx_create(engine, wickr_stream_key_copy(test_key), STREAM_DIRECTION_DECODE);
        SHOULD_NOT_BE_NULL(ctx);
        SHOULD_BE_NULL(ctx->iv_factory);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_key->cipher_key->key_data, ctx->key->cipher_key->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_key->evolution_key, ctx->key->evolution_key, NULL));

        SHOULD_EQUAL(STREAM_DIRECTION_DECODE, ctx->direction);
        SHOULD_EQUAL(0, ctx->last_seq);
        
        wickr_stream_ctx_destroy(&ctx);
    }
    END_IT
    
    wickr_stream_ctx_t *enc = wickr_stream_ctx_create(engine, wickr_stream_key_copy(test_key), STREAM_DIRECTION_ENCODE);
    wickr_stream_ctx_t *dec = wickr_stream_ctx_create(engine, wickr_stream_key_copy(test_key), STREAM_DIRECTION_DECODE);
    
    IT("should allow transfer of encrypted packets between encode and decode contexts")
    {
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(1024);
        SHOULD_NOT_BE_NULL(test_data);
        
        wickr_cipher_result_t *encode = wickr_stream_ctx_encode(enc, test_data, NULL, 1);
        SHOULD_NOT_BE_NULL(encode);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(encode->cipher_text, test_data, NULL));
        SHOULD_EQUAL(1, enc->last_seq);
        
        wickr_buffer_t *decode = wickr_stream_ctx_decode(dec, encode, NULL, 1);
        SHOULD_NOT_BE_NULL(decode);
        SHOULD_EQUAL(1, dec->last_seq);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_data, decode, NULL));
        
        wickr_buffer_destroy(&test_data);
        wickr_buffer_destroy(&decode);
        
        wickr_stream_key_t *rand_key = wickr_stream_key_create_rand(engine, CIPHER_AES256_GCM, test_evolution);
        wickr_stream_ctx_t *bad_dec = wickr_stream_ctx_create(engine, rand_key, STREAM_DIRECTION_DECODE);
        
        wickr_buffer_t *bad_decode = wickr_stream_ctx_decode(bad_dec, encode, NULL, 1);
        SHOULD_BE_NULL(bad_decode);
        wickr_stream_ctx_destroy(&bad_dec);
        wickr_cipher_result_destroy(&encode);
    }
    END_IT
    
    /* Reset seq number to do another test */
    enc->last_seq = 0;
    dec->last_seq = 0;
    
    IT("should allow transfer of encrypted packeets that also authenticates additional data")
    {
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(1024);
        wickr_buffer_t *test_aad = engine.wickr_crypto_engine_crypto_random(64);
        
        SHOULD_NOT_BE_NULL(test_data);
        
        wickr_cipher_result_t *encode = wickr_stream_ctx_encode(enc, test_data, test_aad, 1);
        SHOULD_NOT_BE_NULL(encode);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(encode->cipher_text, test_data, NULL));
        SHOULD_EQUAL(1, enc->last_seq);
        
        wickr_buffer_t *decode = wickr_stream_ctx_decode(dec, encode, test_aad, 1);
        SHOULD_NOT_BE_NULL(decode);
        SHOULD_EQUAL(1, dec->last_seq);
        
        dec->last_seq = 0;
        SHOULD_BE_NULL(wickr_stream_ctx_decode(dec, encode, NULL, 1));
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_data, decode, NULL));
        
        wickr_buffer_destroy(&test_aad);
        wickr_buffer_destroy(&test_data);
        wickr_buffer_destroy(&decode);
        wickr_cipher_result_destroy(&encode);
    }
    END_IT
    
    IT("should be evoloving the key based on the evolution count of the key")
    {
        __test_encode_decode_evolution(enc, dec, test_evolution - 1, false);
        __test_encode_decode_evolution(enc, dec, test_evolution, true);
        __test_encode_decode_evolution(enc, dec, test_evolution + 1, false);
        __test_encode_decode_evolution(enc, dec, test_evolution * 2 - 1, false);
        __test_encode_decode_evolution(enc, dec, test_evolution * 2, true);
        __test_encode_decode_evolution(enc, dec, test_evolution * 2 + 1, false);
        
        wickr_stream_ctx_t *enc_copy = wickr_stream_ctx_copy(enc);
        SHOULD_NOT_BE_NULL(enc_copy);
        
        wickr_stream_ctx_t *dec_copy = wickr_stream_ctx_copy(dec);
        SHOULD_NOT_BE_NULL(dec_copy);
        
        __test_encode_decode_evolution(enc_copy, dec_copy, test_evolution * 3, true);
        __test_encode_decode_evolution(enc, dec, test_evolution * 10, true);
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(dec->key->cipher_key->key_data, dec_copy->key->cipher_key->key_data, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(dec->key->evolution_key, dec_copy->key->evolution_key, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(enc->key->cipher_key->key_data, enc_copy->key->cipher_key->key_data, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(enc->key->evolution_key, enc_copy->key->evolution_key, NULL));
        
        wickr_stream_ctx_destroy(&enc_copy);
        wickr_stream_ctx_destroy(&dec_copy);
    }
    END_IT
    
    wickr_stream_ctx_destroy(&enc);
    wickr_stream_ctx_destroy(&dec);
    wickr_stream_key_destroy(&test_key);
    
}
END_DESCRIBE

DESCRIBE(wickr_stream_iv, "stream cipher iv generation")
{
    
    wickr_stream_iv_t *iv = NULL;
    
    IT("can be created and copied")
    {
        wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
        iv = wickr_stream_iv_create(engine, CIPHER_AES256_GCM);
        SHOULD_NOT_BE_NULL(iv);
        
        wickr_stream_iv_t *iv_copy = wickr_stream_iv_copy(iv);
        SHOULD_NOT_BE_NULL(iv_copy);
        
        wickr_stream_iv_destroy(&iv_copy);
        SHOULD_BE_NULL(iv_copy);
    }
    END_IT
    
    IT("should generate different results for each generation")
    {
        wickr_buffer_t *one_iv = wickr_stream_iv_generate(iv);
        SHOULD_NOT_BE_NULL(one_iv);
        SHOULD_EQUAL(one_iv->length, iv->cipher.iv_len);
        
        bool has_match = false;
        
        for (int i = 0; i < 1000; i++) {
            wickr_buffer_t *another_iv = wickr_stream_iv_generate(iv);
            if (wickr_buffer_is_equal(another_iv, one_iv, NULL)) {
                has_match = true;
                break;
            }
            wickr_buffer_destroy(&another_iv);
        }
        
        SHOULD_BE_FALSE(has_match);
        
        wickr_buffer_destroy(&one_iv);
    }
    END_IT
    
    wickr_stream_iv_destroy(&iv);
    
}
END_DESCRIBE
