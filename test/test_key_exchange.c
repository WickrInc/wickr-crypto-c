
#include "test_key_exchange.h"
#include "key_exchange.h"

static void test_exchange_equality(wickr_key_exchange_t *ex_a, wickr_key_exchange_t *ex_b)
{
    SHOULD_BE_TRUE(wickr_buffer_is_equal(ex_a->exchange_id, ex_b->exchange_id, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(ex_a->exchange_ciphertext->cipher_text, ex_b->exchange_ciphertext->cipher_text, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(ex_a->exchange_ciphertext->iv, ex_b->exchange_ciphertext->iv, NULL));
    SHOULD_EQUAL(ex_a->exchange_ciphertext->cipher.cipher_id, ex_a->exchange_ciphertext->cipher.cipher_id);
    SHOULD_EQUAL(ex_a->key_id, ex_b->key_id);
}

static void test_exchange_set_equality(wickr_key_exchange_set_t *exs_a, wickr_key_exchange_set_t *exs_b)
{
    SHOULD_BE_TRUE(wickr_buffer_is_equal(exs_a->sender_pub->pub_data, exs_b->sender_pub->pub_data, NULL));
    SHOULD_EQUAL(exs_a->sender_pub->curve.identifier, exs_b->sender_pub->curve.identifier);
    
    SHOULD_EQUAL(wickr_array_get_item_count(exs_a->exchanges), wickr_array_get_item_count(exs_b->exchanges));
    
    for (uint32_t i = 0; i < wickr_array_get_item_count(exs_a->exchanges); i++) {
        
        wickr_key_exchange_t *one_ex_a = wickr_array_fetch_item(exs_a->exchanges, i, false);
        wickr_key_exchange_t *one_ex_b = wickr_array_fetch_item(exs_b->exchanges, i, false);
        
        test_exchange_equality(one_ex_a, one_ex_b);
    }
}

static wickr_key_exchange_t *generate_random_exchange()
{
    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    wickr_buffer_t *test_identifier = engine.wickr_crypto_engine_crypto_random(32);
    
    wickr_cipher_result_t *test_exchange_data = wickr_cipher_result_create(CIPHER_AES256_GCM,
                                                                           engine.wickr_crypto_engine_crypto_random(CIPHER_AES256_GCM.iv_len),
                                                                           engine.wickr_crypto_engine_crypto_random(32),
                                                                           engine.wickr_crypto_engine_crypto_random(CIPHER_AES256_GCM.auth_tag_len));
    
    uint64_t test_key_id = rand() % (UINT64_MAX - 1) + 1;
    
    return wickr_key_exchange_create(test_identifier, test_key_id, test_exchange_data);
}

DESCRIBE(key_exchange, "key exchange")
{
    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();

    wickr_buffer_t *test_identifier = engine.wickr_crypto_engine_crypto_random(32);
    wickr_cipher_result_t *test_exchange_data = wickr_cipher_result_create(CIPHER_AES256_GCM,
                                                                           engine.wickr_crypto_engine_crypto_random(CIPHER_AES256_GCM.iv_len),
                                                                           engine.wickr_crypto_engine_crypto_random(32),
                                                                           engine.wickr_crypto_engine_crypto_random(CIPHER_AES256_GCM.auth_tag_len));
    uint64_t test_key_id = 10000;
    
    wickr_key_exchange_t *test_exchange = NULL;
    
    IT("can be created from it's components")
    {
        SHOULD_BE_NULL(wickr_key_exchange_create(NULL, test_key_id, NULL));
        SHOULD_BE_NULL(wickr_key_exchange_create(NULL, test_key_id, test_exchange_data));
        SHOULD_BE_NULL(wickr_key_exchange_create(test_identifier, test_key_id, NULL));
        
        test_exchange = wickr_key_exchange_create(test_identifier, test_key_id, test_exchange_data);
        SHOULD_NOT_BE_NULL(test_exchange);
        
        SHOULD_EQUAL(test_identifier, test_exchange->exchange_id);
        SHOULD_EQUAL(test_exchange_data, test_exchange->exchange_ciphertext);
        SHOULD_EQUAL(test_key_id, test_exchange->key_id);
    }
    END_IT
    
    IT("can be copied")
    {
        SHOULD_BE_NULL(wickr_key_exchange_copy(NULL));
        
        wickr_key_exchange_t *copy = wickr_key_exchange_copy(test_exchange);
        SHOULD_NOT_BE_NULL(copy);
        
        test_exchange_equality(test_exchange, copy);
        
        wickr_key_exchange_destroy(&copy);
    }
    END_IT
    
    wickr_key_exchange_destroy(&test_exchange);
    SHOULD_BE_NULL(test_exchange);
    
}
END_DESCRIBE

DESCRIBE(key_exchange_set, "key exchange set")
{
    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    wickr_key_exchange_set_t *test_exchange_set = NULL;
    
    uint32_t num_exchanges = rand() % (50 - 5) + 5;
    
    wickr_exchange_array_t *test_exchange_array = wickr_exchange_array_new(num_exchanges);
    SHOULD_NOT_BE_NULL(test_exchange_array);
    
    for (uint32_t i = 0; i < num_exchanges; i++) {
        bool res = wickr_exchange_array_set_item(test_exchange_array, i, generate_random_exchange());
        SHOULD_BE_TRUE(res);
    }
    
    wickr_ec_key_t *test_pub_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    wickr_buffer_destroy(&test_pub_key->pri_data);
    
    SHOULD_NOT_BE_NULL(test_pub_key);
    
    IT("can be created from it's components")
    {
        SHOULD_BE_NULL(wickr_key_exchange_set_create(NULL, NULL));
        SHOULD_BE_NULL(wickr_key_exchange_set_create(NULL, test_exchange_array));
        SHOULD_BE_NULL(wickr_key_exchange_set_create(test_pub_key, NULL));
        
        test_exchange_set = wickr_key_exchange_set_create(test_pub_key, test_exchange_array);
        SHOULD_NOT_BE_NULL(test_exchange_set);
        
        SHOULD_EQUAL(test_exchange_set->exchanges, test_exchange_array);
        SHOULD_EQUAL(test_exchange_set->sender_pub, test_pub_key);
    }
    END_IT
    
    IT("can be copied")
    {
        SHOULD_BE_NULL(wickr_key_exchange_set_copy(NULL));
        
        wickr_key_exchange_set_t *copy = wickr_key_exchange_set_copy(test_exchange_set);
        test_exchange_set_equality(copy, test_exchange_set);
        
        wickr_key_exchange_set_destroy(&copy);
    }
    END_IT
    
    IT("can be searched for a particular exchange")
    {
        uint32_t rand_index = rand() % (num_exchanges - 5) + 5;
        
        wickr_buffer_t *search_id = wickr_exchange_array_fetch_item(test_exchange_array, rand_index)->exchange_id;
        SHOULD_NOT_BE_NULL(search_id);
        
        wickr_key_exchange_t *found_exchange = wickr_key_exchange_set_find(test_exchange_set, search_id);
        SHOULD_NOT_BE_NULL(found_exchange);
        
        test_exchange_equality(found_exchange, wickr_exchange_array_fetch_item(test_exchange_array, rand_index));
        wickr_key_exchange_destroy(&found_exchange);
    }
    END_IT
    
    IT("can be serialized")
    {
        SHOULD_BE_NULL(wickr_key_exchange_set_serialize(NULL));
        wickr_buffer_t *test_serialized_data = wickr_key_exchange_set_serialize(test_exchange_set);
        SHOULD_NOT_BE_NULL(test_serialized_data);
        
        wickr_key_exchange_set_t *restored = wickr_key_exchange_set_create_from_buffer(&engine, test_serialized_data);
        test_exchange_set_equality(restored, test_exchange_set);
        
        wickr_buffer_destroy(&test_serialized_data);
        wickr_key_exchange_set_destroy(&restored);
    }
    END_IT
    
    wickr_key_exchange_set_destroy(&test_exchange_set);
    SHOULD_BE_NULL(test_exchange_set);
}
END_DESCRIBE
