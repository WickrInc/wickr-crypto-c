
#include "test_encoder_result.h"
#include "encoder_result.h"

DESCRIBE(wickr_encoder_result, "wickr_encoder_result")
{
    wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();
    
    /* Test packet key */
    wickr_cipher_key_t *test_packet_key = test_engine.wickr_crypto_engine_cipher_key_random(CIPHER_AES256_GCM);
    
    /* Test packet */
    wickr_buffer_t *test_content = test_engine.wickr_crypto_engine_crypto_random(32);
    wickr_ec_key_t *test_signing_key = test_engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    wickr_ecdsa_result_t *test_signature = test_engine.wickr_crypto_engine_ec_sign(test_signing_key, test_content, DIGEST_SHA_512);
    
    wickr_packet_t *test_packet = wickr_packet_create(CURRENT_PACKET_VERSION, test_content, test_signature);
    
    /* Test Encoder Result */
    wickr_encoder_result_t *test_encoder_result;
    
    IT("can be created from it's components")
    {
        /* Negative cases */
        SHOULD_BE_NULL(wickr_encoder_result_create(NULL, NULL));
        SHOULD_BE_NULL(wickr_encoder_result_create(NULL, test_packet));
        SHOULD_BE_NULL(wickr_encoder_result_create(test_packet_key, NULL));
        
        /* Positive case */
        test_encoder_result = wickr_encoder_result_create(test_packet_key, test_packet);
        
        SHOULD_EQUAL(test_encoder_result->packet, test_packet);
        SHOULD_EQUAL(test_encoder_result->packet_key, test_packet_key);
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_encoder_result_t *copy_result = wickr_encoder_result_copy(test_encoder_result);
        SHOULD_NOT_EQUAL(copy_result, test_encoder_result);
        SHOULD_NOT_EQUAL(copy_result->packet, test_encoder_result->packet);
        SHOULD_NOT_EQUAL(copy_result->packet_key, test_encoder_result->packet_key);
        
        /* Packet key equality */
        SHOULD_EQUAL(copy_result->packet_key->cipher.cipher_id, test_encoder_result->packet_key->cipher.cipher_id);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_result->packet_key->key_data,
                                             test_encoder_result->packet_key->key_data, NULL));
        
        /* Packet equality */
        SHOULD_EQUAL(copy_result->packet->version, test_encoder_result->packet->version);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_result->packet->content,
                                             test_encoder_result->packet->content, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_result->packet->signature->sig_data,
                                             test_encoder_result->packet->signature->sig_data, NULL));
        SHOULD_EQUAL(copy_result->packet->signature->curve.identifier,
                     test_encoder_result->packet->signature->curve.identifier);
        SHOULD_EQUAL(copy_result->packet->signature->digest_mode.digest_id,
                     test_encoder_result->packet->signature->digest_mode.digest_id);
        
        /* Cleanup */
        wickr_encoder_result_destroy(&copy_result);
    }
    END_IT

    /* Cleanup */
    wickr_ec_key_destroy(&test_signing_key);
    wickr_encoder_result_destroy(&test_encoder_result);
    
    SHOULD_BE_NULL(test_encoder_result);
}
END_DESCRIBE
