
#include "test_storage_keys.h"
#include "storage.h"

DESCRIBE(wickr_storage_keys, "Wickr Storage Keys")
{
    wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();
    wickr_cipher_key_t *test_local_key = test_engine.wickr_crypto_engine_cipher_key_random(CIPHER_AES256_GCM);
    wickr_cipher_key_t *test_remote_key = test_engine.wickr_crypto_engine_cipher_key_random(CIPHER_AES256_GCM);
    
    wickr_storage_keys_t *test_keys = NULL;

    IT("can be created from components")
    {
        SHOULD_BE_NULL(wickr_storage_keys_create(NULL, test_remote_key));
        SHOULD_BE_NULL(wickr_storage_keys_create(test_local_key, NULL));

        test_keys = wickr_storage_keys_create(test_local_key, test_remote_key);
        SHOULD_NOT_BE_NULL(test_keys);
        SHOULD_EQUAL(test_keys->local, test_local_key);
        SHOULD_EQUAL(test_keys->remote, test_remote_key);
    }
    END_IT
    
    IT("can be copied")
    {
        SHOULD_BE_NULL(wickr_storage_keys_copy(NULL));
        
        wickr_storage_keys_t *copy_keys = wickr_storage_keys_copy(test_keys);
        SHOULD_NOT_BE_NULL(copy_keys);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_keys->local->key_data,
                                              test_keys->local->key_data,
                                              NULL));
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_keys->remote->key_data,
                                              test_keys->remote->key_data,
                                              NULL));
        
        wickr_storage_keys_destroy(&copy_keys);
    }
    END_IT
    
    IT("can be serialized")
    {
        SHOULD_BE_NULL(wickr_storage_keys_serialize(NULL));
        SHOULD_BE_NULL(wickr_storage_keys_create_from_buffer(NULL));
        
        wickr_buffer_t *serialized = wickr_storage_keys_serialize(test_keys);
        SHOULD_NOT_BE_NULL(serialized);
        
        wickr_storage_keys_t *deserialized_keys = wickr_storage_keys_create_from_buffer(serialized);
        SHOULD_NOT_BE_NULL(deserialized_keys);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized_keys->local->key_data,
                                             test_keys->local->key_data,
                                             NULL));
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized_keys->remote->key_data,
                                             test_keys->remote->key_data,
                                             NULL));
        
        wickr_buffer_destroy(&serialized);
        wickr_storage_keys_destroy(&deserialized_keys);
    }
    END_IT
    
    IT("will fail deserialization gracefully with bad input")
    {
        wickr_buffer_t *test_buffer = test_engine.wickr_crypto_engine_crypto_random(256);
        SHOULD_BE_NULL(wickr_storage_keys_create_from_buffer(test_buffer));
        
        wickr_buffer_destroy(&test_buffer);
    }
    END_IT
    
    wickr_storage_keys_destroy(&test_keys);
    SHOULD_BE_NULL(test_keys);
}
END_DESCRIBE
