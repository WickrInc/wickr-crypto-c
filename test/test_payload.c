
#include "test_payload.h"
#include "payload.h"

void test_payload_equality(const wickr_payload_t *p1, const wickr_payload_t *p2)
{
    SHOULD_BE_TRUE(wickr_buffer_is_equal(p1->body, p2->body, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(p1->meta->channel_tag, p2->meta->channel_tag, NULL));
    SHOULD_EQUAL(p1->meta->content_type, p2->meta->content_type);
    SHOULD_EQUAL(p1->meta->ephemerality_settings.bor, p2->meta->ephemerality_settings.bor);
    SHOULD_EQUAL(p1->meta->ephemerality_settings.ttl, p2->meta->ephemerality_settings.ttl);
}

DESCRIBE(wickr_payload, "wickr_payload")
{
    /* Test Metadata Generation */
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    wickr_buffer_t *test_tag = engine.wickr_crypto_engine_crypto_random(32);
    wickr_ephemeral_info_t test_settings = { .ttl = 1000, .bor = 1001 };
    uint16_t test_content = 128;
    
    wickr_packet_meta_t *test_packet_metadata = wickr_packet_meta_create(test_settings, test_tag, test_content);
    
    /* Test Body Generation */
    wickr_buffer_t *test_body = engine.wickr_crypto_engine_crypto_random(32);
    
    /* Test Payload Generation */
    wickr_payload_t *test_payload;
    
    IT("can be created from components")
    {
        /* Negative cases */
        SHOULD_BE_NULL(wickr_payload_create(NULL, NULL));
        SHOULD_BE_NULL(wickr_payload_create(NULL, test_body));
        SHOULD_BE_NULL(wickr_payload_create(test_packet_metadata, NULL));
        
        /* Positive case */
        test_payload = wickr_payload_create(test_packet_metadata, test_body);
        SHOULD_NOT_BE_NULL(test_payload);
        SHOULD_EQUAL(test_payload->body, test_body);
        SHOULD_EQUAL(test_payload->meta, test_packet_metadata);
    }
    END_IT
    
    IT("can be copied")
    {
        /* Positive case */
        wickr_payload_t *copy = wickr_payload_copy(test_payload);
        
        SHOULD_NOT_BE_NULL(copy);
        SHOULD_NOT_EQUAL(copy->body, test_payload->body);
        SHOULD_NOT_EQUAL(copy->meta, test_payload->meta);
        test_payload_equality(copy, test_payload);
        
        /* Negative case */
        SHOULD_BE_NULL(wickr_payload_copy(NULL));
        
        /* Cleanup */
        wickr_payload_destroy(&copy);
    }
    END_IT
    
    IT("can be serialized")
    {
        wickr_buffer_t *serialized = wickr_payload_serialize(test_payload);
        SHOULD_NOT_BE_NULL(serialized);
        
        /* Positive case */
        wickr_payload_t *restored = wickr_payload_create_from_buffer(serialized);
        SHOULD_NOT_BE_NULL(restored);
        test_payload_equality(test_payload, restored);

        /* Negative case */
        SHOULD_BE_NULL(wickr_payload_create_from_buffer(NULL));
        wickr_buffer_t *random_data = engine.wickr_crypto_engine_crypto_random(32);
        wickr_payload_t *not_restored = wickr_payload_create_from_buffer(random_data);
        SHOULD_BE_NULL(not_restored);
        
        /* Cleanup */
        wickr_buffer_destroy(&random_data);
        wickr_buffer_destroy(&serialized);
        wickr_payload_destroy(&restored);
    }
    END_IT
    
    IT("can be encrypted")
    {
        /* Positive case */
        wickr_cipher_key_t *key = engine.wickr_crypto_engine_cipher_key_random(CIPHER_AES256_GCM);
        wickr_cipher_result_t *ciphered = wickr_payload_encrypt(test_payload, &engine, key);
        
        wickr_payload_t *restored = wickr_payload_create_from_cipher(&engine, ciphered, key);
        SHOULD_NOT_BE_NULL(restored);
        test_payload_equality(restored, test_payload);
        
        /* Negative case */
        SHOULD_BE_NULL(wickr_payload_create_from_cipher(NULL, ciphered, key));
        SHOULD_BE_NULL(wickr_payload_create_from_cipher(&engine, NULL, key));
        SHOULD_BE_NULL(wickr_payload_create_from_cipher(&engine, ciphered, NULL));
        
        wickr_cipher_key_t *incorrect_key = engine.wickr_crypto_engine_cipher_key_random(CIPHER_AES256_GCM);
        SHOULD_BE_NULL(wickr_payload_create_from_cipher(&engine, ciphered, incorrect_key));
        
        /* Cleanup */
        wickr_cipher_result_destroy(&ciphered);
        wickr_cipher_key_destroy(&key);
        wickr_cipher_key_destroy(&incorrect_key);
        wickr_payload_destroy(&restored);
    }
    END_IT
    
    /* Cleanup */
    wickr_payload_destroy(&test_payload);
    SHOULD_BE_NULL(test_payload);
}

END_DESCRIBE
