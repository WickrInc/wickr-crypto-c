
#include "test_fingerprint.h"
#include "crypto_engine.h"
#include "fingerprint.h"
#include "string.h"
#include "util.h"
#include "b32.h"

typedef wickr_buffer_t *(*wickr_fingerprint_encode_func)(const wickr_fingerprint_t *, wickr_fingerprint_output);

static void __test_fingerprint_encoding(const wickr_fingerprint_t *test_fingerprint,
                                        const wickr_buffer_t *expected,
                                        wickr_fingerprint_encode_func test_encode_func)
{
    
    wickr_buffer_t *long_fingerprint = test_encode_func(test_fingerprint, FINGERPRINT_OUTPUT_LONG);
    wickr_buffer_t *short_fingerprint = test_encode_func(test_fingerprint, FINGERPRINT_OUTPUT_SHORT);
    
    SHOULD_BE_TRUE(wickr_buffer_is_equal(expected, long_fingerprint, NULL));
    
    /* Shorten expected buffer to test short encoding */
    wickr_buffer_t *expected_short = wickr_buffer_copy_section(expected, 0, expected->length / 2);
    
    SHOULD_BE_TRUE(wickr_buffer_is_equal(expected_short, short_fingerprint, NULL));
    
    wickr_buffer_destroy(&expected_short);
    wickr_buffer_destroy(&long_fingerprint);
    wickr_buffer_destroy(&short_fingerprint);
}

DESCRIBE(wickr_fingerprint, "fingerprints")
{
    wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();
    
    wickr_buffer_t *rnd_data = test_engine.wickr_crypto_engine_crypto_random(32);
    SHOULD_NOT_BE_NULL(rnd_data);
    
    wickr_fingerprint_t *test_fingerprint = wickr_fingerprint_create(WICKR_FINGERPRINT_TYPE_SHA512, rnd_data);
    
    IT("can be created with raw fingerprint data")
    {
        SHOULD_EQUAL(test_fingerprint->type, WICKR_FINGERPRINT_TYPE_SHA512);
        SHOULD_BE_NULL(wickr_fingerprint_create(WICKR_FINGERPRINT_TYPE_SHA512, NULL));
        SHOULD_NOT_BE_NULL(test_fingerprint);
        SHOULD_EQUAL(test_fingerprint->data, rnd_data);
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_fingerprint_t *copy = wickr_fingerprint_copy(test_fingerprint);
        SHOULD_NOT_BE_NULL(copy);
        SHOULD_EQUAL(test_fingerprint->type, copy->type);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_fingerprint->data, copy->data, NULL));
        wickr_fingerprint_destroy(&copy);
    }
    END_IT
    
    IT("can be represented in hex")
    {
        wickr_buffer_t *expected_hex = getHexStringFromData(test_fingerprint->data);
        __test_fingerprint_encoding(test_fingerprint, expected_hex, wickr_fingerprint_get_hex);
        wickr_buffer_destroy(&expected_hex);
    }
    END_IT
    
    IT("can be represented in base32")
    {
        wickr_buffer_t *expected_b32 = base32_encode(test_fingerprint->data);
        __test_fingerprint_encoding(test_fingerprint, expected_b32, wickr_fingerprint_get_b32);
        wickr_buffer_destroy(&expected_b32);
    }
    END_IT
    
    wickr_fingerprint_destroy(&test_fingerprint);
    SHOULD_BE_NULL(test_fingerprint);
}
END_DESCRIBE

DESCRIBE(wickr_fingerprint_generation, "unilateral fingerprint")
{
    wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();
    wickr_buffer_t *test_identifier = test_engine.wickr_crypto_engine_crypto_random(32);
    wickr_ec_key_t *test_key = test_engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    
    SHOULD_NOT_BE_NULL(test_identifier);
    SHOULD_NOT_BE_NULL(test_key);
    
    wickr_fingerprint_t *test_fingerprint = wickr_fingerprint_gen(test_engine,
                                                                  test_key,
                                                                  test_identifier,
                                                                  WICKR_FINGERPRINT_TYPE_SHA512);
    
    IT("can generate a SHA512 length fingerprint")
    {
        SHOULD_NOT_BE_NULL(test_fingerprint);
        SHOULD_NOT_BE_NULL(test_fingerprint->data)
        SHOULD_EQUAL(test_fingerprint->data->length, DIGEST_SHA_512.size);
        
        SHOULD_BE_NULL(wickr_fingerprint_gen(test_engine, NULL, NULL, WICKR_FINGERPRINT_TYPE_SHA512));
        SHOULD_BE_NULL(wickr_fingerprint_gen(test_engine, test_key,
                                             NULL, WICKR_FINGERPRINT_TYPE_SHA512));
        SHOULD_BE_NULL(wickr_fingerprint_gen(test_engine, NULL,
                                             test_identifier, WICKR_FINGERPRINT_TYPE_SHA512));
        SHOULD_BE_NULL(wickr_fingerprint_gen(test_engine, test_key,
                                             test_identifier, 1));
    }
    END_IT
    
    IT("generates fingerprints that are unique per key")
    {
        wickr_ec_key_t *test_key2 = test_engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        SHOULD_NOT_BE_NULL(test_key2);
        
        wickr_fingerprint_t *test_fingerprint_key2 = wickr_fingerprint_gen(test_engine,
                                                                           test_key2,
                                                                           test_identifier,
                                                                           WICKR_FINGERPRINT_TYPE_SHA512);
        
        SHOULD_NOT_BE_NULL(test_fingerprint_key2);
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(test_fingerprint_key2->data, test_fingerprint->data, NULL));
        
        wickr_fingerprint_destroy(&test_fingerprint_key2);
        wickr_ec_key_destroy(&test_key2);
    }
    END_IT
    
    IT("generates fingerprints that are only based on the public part of the key")
    {
        wickr_ec_key_t *pub_only_key = wickr_ec_key_copy(test_key);
        wickr_buffer_destroy(&pub_only_key->pri_data);
        
        SHOULD_NOT_BE_NULL(pub_only_key);
        SHOULD_BE_NULL(pub_only_key->pri_data);
        
        wickr_fingerprint_t *pub_only_fingerprint = wickr_fingerprint_gen(test_engine, pub_only_key, test_identifier, WICKR_FINGERPRINT_TYPE_SHA512);
        
        SHOULD_NOT_BE_NULL(pub_only_fingerprint);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(pub_only_fingerprint->data, test_fingerprint->data, NULL));
        
        wickr_fingerprint_destroy(&pub_only_fingerprint);
        wickr_ec_key_destroy(&pub_only_key);
    }
    END_IT
    
    IT("generates fingerprints that are unique per identifier")
    {
        wickr_buffer_t *identifier2 = test_engine.wickr_crypto_engine_crypto_random(32);
        SHOULD_NOT_BE_NULL(identifier2);
        
        wickr_fingerprint_t *test_fingerprint_id2 = wickr_fingerprint_gen(test_engine, test_key, identifier2, WICKR_FINGERPRINT_TYPE_SHA512);
        SHOULD_NOT_BE_NULL(test_fingerprint_id2);
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(test_fingerprint_id2->data, test_fingerprint->data, NULL));
        
        wickr_fingerprint_destroy(&test_fingerprint_id2);
        wickr_buffer_destroy(&identifier2);
    }
    END_IT
    
    wickr_buffer_destroy(&test_identifier);
    wickr_ec_key_destroy(&test_key);
    wickr_fingerprint_destroy(&test_fingerprint);
    
}
END_DESCRIBE

static wickr_fingerprint_t *__wickr_fingerprint_gen_random(wickr_crypto_engine_t engine)
{
    wickr_buffer_t *identifier = engine.wickr_crypto_engine_crypto_random(32);
    wickr_ec_key_t *key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    
    SHOULD_NOT_BE_NULL(identifier);
    SHOULD_NOT_BE_NULL(key);
    
    
    wickr_fingerprint_t *fingerprint = wickr_fingerprint_gen(engine, key,
                                                                    identifier, WICKR_FINGERPRINT_TYPE_SHA512);
    
    SHOULD_NOT_BE_NULL(fingerprint);
    
    wickr_buffer_destroy(&identifier);
    wickr_ec_key_destroy(&key);
    
    return fingerprint;
}

DESCRIBE(wickr_fingerprint_bilateral_generation, "bilateral fingerprint")
{
    wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();

    wickr_fingerprint_t *test_fingerprint_a = __wickr_fingerprint_gen_random(test_engine);
    wickr_fingerprint_t *test_fingerprint_b = __wickr_fingerprint_gen_random(test_engine);
    
    wickr_fingerprint_t *test_bilateral_fingerprint = wickr_fingerprint_gen_bilateral(test_engine,
                                                                                      test_fingerprint_a,
                                                                                      test_fingerprint_b,
                                                                                      WICKR_FINGERPRINT_TYPE_SHA512);

    IT("can be generated from two existing fingerprints")
    {
        SHOULD_NOT_BE_NULL(test_bilateral_fingerprint);
        SHOULD_NOT_BE_NULL(test_bilateral_fingerprint->data)
        SHOULD_EQUAL(test_bilateral_fingerprint->data->length, DIGEST_SHA_512.size);
        
        SHOULD_BE_NULL(wickr_fingerprint_gen_bilateral(test_engine, NULL, NULL, WICKR_FINGERPRINT_TYPE_SHA512));
        SHOULD_BE_NULL(wickr_fingerprint_gen_bilateral(test_engine, test_fingerprint_a,
                                                       NULL, WICKR_FINGERPRINT_TYPE_SHA512));
        SHOULD_BE_NULL(wickr_fingerprint_gen_bilateral(test_engine, NULL,
                                                       test_fingerprint_b, WICKR_FINGERPRINT_TYPE_SHA512));
    }
    END_IT
    
    IT("should generate fingerprints that are not dependent on input order")
    {
        wickr_fingerprint_t *test_bilateral_fingerprint2 = wickr_fingerprint_gen_bilateral(test_engine,
                                                                                           test_fingerprint_b,
                                                                                           test_fingerprint_a,
                                                                                           WICKR_FINGERPRINT_TYPE_SHA512);
        SHOULD_NOT_BE_NULL(test_bilateral_fingerprint2);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_bilateral_fingerprint->data, test_bilateral_fingerprint2->data, NULL));
        
        wickr_fingerprint_destroy(&test_bilateral_fingerprint2);
    }
    END_IT
    
    IT("should generate fingerprints that are unique per inputs provided")
    {
        wickr_fingerprint_t *test_fingerprint_c = __wickr_fingerprint_gen_random(test_engine);
        SHOULD_NOT_BE_NULL(test_fingerprint_c);
        
        wickr_fingerprint_t *test_bilateral_ac = wickr_fingerprint_gen_bilateral(test_engine,
                                                                                 test_fingerprint_a,
                                                                                 test_fingerprint_c,
                                                                                 WICKR_FINGERPRINT_TYPE_SHA512);
        
        SHOULD_NOT_BE_NULL(test_bilateral_ac);
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(test_bilateral_ac->data, test_bilateral_fingerprint->data, NULL));
        
        wickr_fingerprint_destroy(&test_fingerprint_c);
        wickr_fingerprint_destroy(&test_bilateral_ac);
    }
    END_IT
    
    IT("should fail to generate a fingerprint if the input fingerprints are not of the same type")
    {
        wickr_fingerprint_t *test_fingerprint_c = __wickr_fingerprint_gen_random(test_engine);
        test_fingerprint_c->type = 1;
        
        SHOULD_BE_NULL(wickr_fingerprint_gen_bilateral(test_engine,
                                                       test_fingerprint_a,
                                                       test_fingerprint_c,
                                                       WICKR_FINGERPRINT_TYPE_SHA512));
        
        test_fingerprint_c->type = WICKR_FINGERPRINT_TYPE_SHA512;
        test_fingerprint_c->data->length--;
        
        SHOULD_BE_NULL(wickr_fingerprint_gen_bilateral(test_engine,
                                                       test_fingerprint_a,
                                                       test_fingerprint_c,
                                                       WICKR_FINGERPRINT_TYPE_SHA512));
        
        wickr_fingerprint_destroy(&test_fingerprint_c);
    }
    END_IT
    
    wickr_fingerprint_destroy(&test_fingerprint_a);
    wickr_fingerprint_destroy(&test_fingerprint_b);
    wickr_fingerprint_destroy(&test_bilateral_fingerprint);
}
END_DESCRIBE
