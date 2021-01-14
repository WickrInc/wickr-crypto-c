
#include "test_ec_kyber_hybrid.h"
#include "ec_kyber_hybrid.h"
#include "eckey.h"
#include "kyber_engine.h"
#include <string.h>
#include "openssl_suite.h"
#include "test_ec_key.h"

wickr_ec_key_t *mock_key_import_type_change(const wickr_buffer_t *buffer, bool is_private)
{
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    wickr_ec_key_t *rand_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    rand_key->curve.identifier = 255;
    return rand_key;
}

DESCRIBE(wickr_ec_key_hybrid, "pq hybrid extentions for ec keys")
{
    wickr_ec_key_t *test_key = NULL;
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    wickr_ec_key_t *test_p521_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    wickr_kyber_keypair_t *test_kyber_key = wickr_kyber_engine_random_keypair(&wickr_kyber_engine_default, KYBER_MODE_1024);
    
    IT("can be created from components")
    {        
        SHOULD_BE_NULL(wickr_ec_key_hybrid_create_with_components(NULL, NULL));
        SHOULD_BE_NULL(wickr_ec_key_hybrid_create_with_components(NULL, test_kyber_key));
        SHOULD_BE_NULL(wickr_ec_key_hybrid_create_with_components(test_p521_key, NULL));
        
        test_key = wickr_ec_key_hybrid_create_with_components(test_p521_key, test_kyber_key);
        SHOULD_NOT_BE_NULL(test_key);
        SHOULD_NOT_BE_NULL(test_key->pub_data);
        SHOULD_NOT_BE_NULL(test_key->pri_data);
        SHOULD_BE_TRUE(memcmp(&EC_CURVE_P521_KYBER_HYBRID, &test_key->curve, sizeof(wickr_ec_curve_t)) == 0);
    }
    END_IT
    
    IT("should fail creation if there is no defined combination of curve + kyber types")
    {
        wickr_ec_key_t *ec_copy = wickr_ec_key_copy(test_p521_key);
        wickr_kyber_keypair_t *kyber_copy = wickr_kyber_keypair_copy(test_kyber_key);
        
        ec_copy->curve.identifier = 255;
        
        SHOULD_BE_NULL(wickr_ec_key_hybrid_create_with_components(ec_copy, kyber_copy));
        
        ec_copy->curve.identifier = EC_CURVE_ID_NIST_P521;
        kyber_copy->mode.identifier = 255;
        
        SHOULD_BE_NULL(wickr_ec_key_hybrid_create_with_components(ec_copy, kyber_copy));
        
        wickr_ec_key_destroy(&ec_copy);
        wickr_kyber_keypair_destroy(&kyber_copy);
    }
    END_IT
    
    IT("can extract the underlying ec keypair from the hybrid keypair")
    {
        wickr_ec_key_t *extracted = wickr_ec_key_hybrid_get_ec_keypair(test_key, openssl_ec_key_import);
        SHOULD_NOT_EQUAL(extracted, test_p521_key);
        SHOULD_BE_TRUE(ec_key_is_equal(extracted, test_p521_key));
        wickr_ec_key_destroy(&extracted);
    }
    END_IT
    
    IT("will fail to extract the underlying ec keypair if it is the wrong type")
    {
        wickr_ec_key_t *copy = wickr_ec_key_copy(test_key);
        
        /* Wrong EC Type */
        SHOULD_BE_NULL(wickr_ec_key_hybrid_get_ec_keypair(copy, mock_key_import_type_change));
        
        /* Wrong overall type */
        copy->curve.identifier = 5;
        SHOULD_BE_NULL(wickr_ec_key_hybrid_get_ec_keypair(copy, openssl_ec_key_import));
        
        wickr_ec_key_destroy(&copy);
    }
    END_IT
    
    IT("will fail to extract the underlying ec keypair if the data provided is corrupted")
    {
        wickr_ec_key_t *copy = wickr_ec_key_copy(test_key);
        copy->pub_data->length = 32;
        copy->pri_data->length = 32;
        
        SHOULD_BE_NULL(wickr_ec_key_hybrid_get_ec_keypair(copy, openssl_ec_key_import));
        
        copy->pub_data->length = 1500;
        copy->pub_data->length = 1500;
        
        SHOULD_BE_NULL(wickr_ec_key_hybrid_get_ec_keypair(copy, openssl_ec_key_import));
        wickr_ec_key_destroy(&copy);
    }
    END_IT
    
    IT("can extract the underlying public kyber key from the hybrid keypair")
    {
        wickr_ec_key_t *copy = wickr_ec_key_copy(test_key);

        /* Test with private data */
        wickr_kyber_pub_key_t *pub_key = wickr_ec_key_hybrid_get_kyber_pub(copy);
        SHOULD_NOT_BE_NULL(pub_key);
        //TODO: TEST PUB KEY EQUALITY
        
        wickr_kyber_pub_key_destroy(&pub_key);
        
        /* Test without private data */
        wickr_buffer_destroy(&copy->pri_data);
        
        pub_key = wickr_ec_key_hybrid_get_kyber_pub(copy);
        //TODO: TEST PUB KEY EQUALITY
        wickr_kyber_pub_key_destroy(&pub_key);
        wickr_ec_key_destroy(&copy);
    }
    END_IT
    
    IT("will fail to extract the underlying public kyber key if it is the wrong type")
    {
        wickr_ec_key_t *copy = wickr_ec_key_copy(test_key);
        copy->pub_data->bytes[HYBRID_IDENTIFIER_SIZE] = 255;
        SHOULD_BE_NULL(wickr_ec_key_hybrid_get_kyber_pub(copy));
        wickr_ec_key_destroy(&copy);
    }
    END_IT
    
    IT("will fail to extract the underlying public kyber key if the data provided is corrupted")
    {
        wickr_ec_key_t *copy = wickr_ec_key_copy(test_key);
        copy->pub_data->length = 16;
        SHOULD_BE_NULL(wickr_ec_key_hybrid_get_kyber_pub(copy));
        wickr_ec_key_destroy(&copy);
    }
    END_IT
    
    IT("can extract the underlying private kyber key from the hybrid keypair")
    {
        wickr_ec_key_t *copy = wickr_ec_key_copy(test_key);

        /* Test with private data */
        wickr_kyber_secret_key_t *secret_key = wickr_ec_key_hybrid_get_kyber_pri(copy);
        SHOULD_NOT_BE_NULL(secret_key);
        //TODO: TEST PRI KEY EQUALITY
        
        wickr_kyber_secret_key_destroy(&secret_key);
        
        /* Test without pub data */
        wickr_buffer_destroy(&copy->pub_data);
        
        secret_key = wickr_ec_key_hybrid_get_kyber_pri(copy);
        //TODO: TEST PRI KEY EQUALITY
        wickr_kyber_secret_key_destroy(&secret_key);
        wickr_ec_key_destroy(&copy);
    }
    END_IT
    
    IT("will fail to extract the underlying private kyber key if it is the wrong type")
    {
        wickr_ec_key_t *copy = wickr_ec_key_copy(test_key);
        copy->pri_data->bytes[HYBRID_IDENTIFIER_SIZE] = 255;
        SHOULD_BE_NULL(wickr_ec_key_hybrid_get_kyber_pri(copy));
        wickr_ec_key_destroy(&copy);
    }
    END_IT
    
    IT("will fail to extract the underlying private kyber key if the data provided is corrupted")
    {
        wickr_ec_key_t *copy = wickr_ec_key_copy(test_key);
        copy->pri_data->length = 16;
        SHOULD_BE_NULL(wickr_ec_key_hybrid_get_kyber_pri(copy));
        wickr_ec_key_destroy(&copy);
    }
    END_IT
    
    wickr_ec_key_destroy(&test_key);
}
END_DESCRIBE
