
#include "test_ec_key.h"
#include "eckey.h"
#include "crypto_engine.h"
#include "string.h"

DESCRIBE(wickr_ec_key, "ec key data structure")
{
    /* Not using real key data since these tests are meant only to test the ec_key data structure */
    wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();
    
    wickr_buffer_t *random_pub_data = test_engine.wickr_crypto_engine_crypto_random(32);
    wickr_buffer_t *random_pri_data = test_engine.wickr_crypto_engine_crypto_random(32);
    wickr_ec_curve_t test_curve = { 32, 64, 128 };
    
    wickr_ec_key_t *test_key = wickr_ec_key_create(test_curve, random_pub_data, random_pri_data);
    
    IT("can be created with pub and pri data")
    {
        SHOULD_NOT_BE_NULL(test_key);
        
        SHOULD_BE_TRUE(memcmp(&test_key->curve,&test_curve, sizeof(wickr_ec_curve_t)) == 0)

        SHOULD_EQUAL(test_key->pub_data, random_pub_data);
        SHOULD_EQUAL(test_key->pri_data, random_pri_data);

        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_key->pub_data, random_pub_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_key->pri_data, random_pri_data, NULL));
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_ec_key_t *key_copy = wickr_ec_key_copy(test_key);
        SHOULD_NOT_BE_NULL(key_copy);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_key->pub_data, key_copy->pub_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_key->pri_data, key_copy->pri_data, NULL));
        SHOULD_BE_TRUE(memcmp(&test_key->curve, &key_copy->curve, sizeof(wickr_ec_curve_t)) == 0);
        
        wickr_ec_key_destroy(&key_copy);
    }
    END_IT
    
    IT("can provide a fixed length public key, if the key data is shorter than the max length")
    {
        wickr_buffer_t *fixed_len_pub = wickr_ec_key_get_pubdata_fixed_len(test_key);
        SHOULD_NOT_BE_NULL(fixed_len_pub);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(fixed_len_pub, test_key->pub_data, NULL));
        
        wickr_buffer_t *section = wickr_buffer_copy_section(fixed_len_pub, 0, test_key->pub_data->length);
        SHOULD_NOT_BE_NULL(section);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(section, test_key->pub_data, NULL));
        
        wickr_buffer_destroy(&section);
        
        wickr_buffer_t *expected_zero = wickr_buffer_create_empty_zero(test_curve.max_pub_size - test_key->pub_data->length);
        wickr_buffer_t *zero_section = wickr_buffer_copy_section(fixed_len_pub, test_key->pub_data->length,
                                                                 test_curve.max_pub_size - test_key->pub_data->length);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(expected_zero, zero_section, NULL));
        
        wickr_buffer_destroy(&expected_zero);
        wickr_buffer_destroy(&zero_section);
        wickr_buffer_destroy(&fixed_len_pub);
    }
    END_IT
    
    IT("can provide a fixed length key if the key data is the same length as the max length")
    {
        test_key->curve.max_pub_size = test_key->pub_data->length;
        
        wickr_buffer_t *fixed_len_pub = wickr_ec_key_get_pubdata_fixed_len(test_key);
        
        /* Pointer should be different, but contain the same data */
        SHOULD_NOT_EQUAL(fixed_len_pub, test_key->pub_data);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(fixed_len_pub, test_key->pub_data, NULL));
        
        wickr_buffer_destroy(&fixed_len_pub);
    }
    END_IT
    
    IT("will fail if the key data is larger than the max length")
    {
        test_key->pub_data->length += 1;
        SHOULD_BE_NULL(wickr_ec_key_get_pubdata_fixed_len(test_key));
    }
    END_IT
    
    wickr_ec_key_destroy(&test_key);
    SHOULD_BE_NULL(test_key);
}
END_DESCRIBE
