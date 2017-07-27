
#include "test_stream_info.h"
#include "stream_info.h"

DESCRIBE(wickr_stream_info, "stream info tests")
{
    wickr_stream_info_t *test_info = NULL;
    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    
    IT("can be created with the required fields")
    {
        SHOULD_BE_NULL(wickr_stream_info_create(NULL, NULL));
        
        wickr_stream_key_t *test_key = wickr_stream_key_create_rand(engine, CIPHER_AES256_GCM, 512);
        wickr_buffer_t *user_data = engine.wickr_crypto_engine_crypto_random(32);
        SHOULD_NOT_BE_NULL(test_key);
        SHOULD_NOT_BE_NULL(user_data);
        
        SHOULD_BE_NULL(wickr_stream_info_create(NULL, user_data));
        
        wickr_stream_key_t *test_key_copy = wickr_stream_key_copy(test_key);
        SHOULD_NOT_BE_NULL(test_key_copy);
        
        wickr_stream_info_t *info_no_user_data = wickr_stream_info_create(test_key_copy, NULL);
        SHOULD_NOT_BE_NULL(info_no_user_data);
        SHOULD_EQUAL(test_key_copy, info_no_user_data->key);
        
        wickr_stream_info_destroy(&info_no_user_data);
        
        test_info = wickr_stream_info_create(test_key, user_data);
        SHOULD_NOT_BE_NULL(test_info);
        SHOULD_EQUAL(test_key, test_info->key);
        SHOULD_EQUAL(user_data, test_info->user_data);
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_stream_info_t *copy = wickr_stream_info_copy(test_info);
        SHOULD_NOT_BE_NULL(copy);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->user_data, test_info->user_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->key->evolution_key, test_info->key->evolution_key, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->key->cipher_key->key_data, test_info->key->cipher_key->key_data, NULL));
        SHOULD_EQUAL(copy->key->packets_per_evolution, test_info->key->packets_per_evolution);
        
        wickr_stream_info_destroy(&copy);
    }
    END_IT
    
    IT("can be serialized / deserialized")
    {
        wickr_buffer_t *serialized = wickr_stream_info_serialize(test_info);
        SHOULD_NOT_BE_NULL(serialized);
        
        wickr_stream_info_t *info = wickr_stream_info_create_from_buffer(serialized);
        SHOULD_NOT_BE_NULL(info);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(info->user_data, test_info->user_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(info->key->evolution_key, test_info->key->evolution_key, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(info->key->cipher_key->key_data, test_info->key->cipher_key->key_data, NULL));
        SHOULD_EQUAL(info->key->packets_per_evolution, test_info->key->packets_per_evolution);
        
        wickr_buffer_destroy(&serialized);
        wickr_stream_info_destroy(&info);
    }
    END_IT
    
    IT("can be serialized / deserialized (No user info)")
    {
        wickr_buffer_destroy(&test_info->user_data);
        
        wickr_buffer_t *serialized = wickr_stream_info_serialize(test_info);
        SHOULD_NOT_BE_NULL(serialized);
        
        wickr_stream_info_t *info = wickr_stream_info_create_from_buffer(serialized);
        SHOULD_NOT_BE_NULL(info);
        
        SHOULD_BE_NULL(info->user_data);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(info->key->evolution_key, test_info->key->evolution_key, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(info->key->cipher_key->key_data, test_info->key->cipher_key->key_data, NULL));
        SHOULD_EQUAL(info->key->packets_per_evolution, test_info->key->packets_per_evolution);
        
        wickr_buffer_destroy(&serialized);
        wickr_stream_info_destroy(&info);
    }
    END_IT
    
    wickr_stream_info_destroy(&test_info);
    SHOULD_BE_NULL(test_info);
}
END_DESCRIBE
