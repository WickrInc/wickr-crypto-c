
#include "test_transport_root_key.h"
#include "test_stream_cipher.h"
#include "util.h"
#include <string.h>

bool wickr_transport_root_key_is_equal(wickr_transport_root_key_t *a, wickr_transport_root_key_t *b)
{
    if (!a || !b) {
        return false;
    }
    
    if (!wickr_buffer_is_equal(a->secret, b->secret, NULL)) {
        return false;
    }
    
    if (memcmp(&a->cipher, &b->cipher, sizeof(wickr_cipher_t)) != 0) {
        return false;
    }
    
    return a->packets_per_evo_recv == b->packets_per_evo_recv && a->packets_per_evo_send == b->packets_per_evo_send;
}

DESCRIBE(wickr_transport_root_key, "Wickr Transport Root Key")
{
    wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();
    wickr_cipher_t test_cipher = CIPHER_AES256_GCM;
    uint32_t test_packet_per_evo_send = 42;
    uint32_t test_packet_per_evo_recv = 43;
    
    IT("can be created with specific values")
    {
        /* Invalid values */
        SHOULD_BE_NULL(wickr_transport_root_key_create(NULL, test_cipher, 0, 0));
        
        /* Correct values */
        wickr_buffer_t *secret = test_engine.wickr_crypto_engine_crypto_random(32);
        
        wickr_transport_root_key_t *root_key = wickr_transport_root_key_create(secret, test_cipher,
                                                                               test_packet_per_evo_send, test_packet_per_evo_recv);
        SHOULD_NOT_BE_NULL(root_key);
        SHOULD_EQUAL(secret, root_key->secret);
        SHOULD_EQUAL(memcmp(&test_cipher, &root_key->cipher, sizeof(wickr_cipher_t)), 0);
        SHOULD_EQUAL(test_packet_per_evo_send, root_key->packets_per_evo_send);
        SHOULD_EQUAL(test_packet_per_evo_recv, root_key->packets_per_evo_recv);
        
        /* Cleanup */
        wickr_transport_root_key_destroy(&root_key);
    }
    END_IT
    
    wickr_transport_root_key_t *test_root_key = NULL;
    
    IT("can be created randomly")
    {
        test_root_key = wickr_transport_root_key_create_random(&test_engine, test_cipher,
                                                               test_packet_per_evo_send, test_packet_per_evo_recv);
        
        SHOULD_NOT_BE_NULL(test_root_key);
        SHOULD_EQUAL(memcmp(&test_cipher, &test_root_key->cipher, sizeof(wickr_cipher_t)), 0);
        SHOULD_EQUAL(test_packet_per_evo_send, test_root_key->packets_per_evo_send);
        SHOULD_EQUAL(test_packet_per_evo_recv, test_root_key->packets_per_evo_recv);
        
        wickr_transport_root_key_t *another_key = wickr_transport_root_key_create_random(&test_engine, test_cipher,
                                                                                         test_packet_per_evo_send,
                                                                                         test_packet_per_evo_recv);
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(test_root_key->secret, another_key->secret, NULL));
        
        /* Cleanup */
        wickr_transport_root_key_destroy(&another_key);
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_transport_root_key_t *copy = wickr_transport_root_key_copy(test_root_key);
        
        SHOULD_NOT_BE_NULL(copy);
        SHOULD_BE_TRUE(wickr_transport_root_key_is_equal(test_root_key, copy));
        
        /* Cleanup */
        wickr_transport_root_key_destroy(&copy);
    }
    END_IT
    
    IT("can be converted to a stream key based on direction")
    {
        wickr_buffer_t expected_stream_key_alice_hex = {
            .bytes = (uint8_t *)"60fa8e3da86528bf4d460f69db7258bc1259fd4cc0959acf6c25c0ee64bc107d",
            .length = 64
        };
        
        wickr_buffer_t *expected_stream_key_alice_data = getDataFromHexString(&expected_stream_key_alice_hex);
        
        wickr_buffer_t expected_stream_key_alice_evo_hex = {
            .bytes = (uint8_t *)"ddacaa7c5f112ad1056a7bec2b7881bb612a877f5bb8e3b3355fc9f3522476a1",
            .length = 64
        };
        
        wickr_buffer_t *expected_stream_key_alice_evo = getDataFromHexString(&expected_stream_key_alice_evo_hex);
        
        wickr_buffer_t expected_stream_key_bob_hex = {
            .bytes = (uint8_t *)"6d77a69acaa3629b4f943f01ddcb819fbfe5e76a6cc9161a02ae78e6a62037a9",
            .length = 64
        };
        
        wickr_buffer_t *expected_stream_key_bob_data = getDataFromHexString(&expected_stream_key_bob_hex);
        
        wickr_buffer_t expected_stream_key_bob_evo_hex = {
            .bytes = (uint8_t *)"1fbf505c77df3c7f2f5045f78631a1490a867bbf46c41f7c529621d87b6b516c",
            .length = 64
        };
        
        wickr_buffer_t *expected_stream_key_bob_evo = getDataFromHexString(&expected_stream_key_bob_evo_hex);

        
        wickr_buffer_t *key_data_buffer = wickr_buffer_create_empty_zero(32);
        
        /* Swap in the static secret buffer for testing purposes */
        wickr_buffer_destroy(&test_root_key->secret);
        test_root_key->secret = key_data_buffer;
        
        wickr_buffer_t *salt_alice = wickr_buffer_create((uint8_t *)"hello", 5);
        wickr_buffer_t *salt_bob = wickr_buffer_create((uint8_t *)"world", 5);
        wickr_buffer_t *stream_id_alice = wickr_buffer_create((uint8_t *)"alice", 5);
        wickr_buffer_t *stream_id_bob = wickr_buffer_create((uint8_t *)"bob", 3);
        
        wickr_stream_key_t *stream_key_alice = wickr_transport_root_key_to_stream_key(test_root_key,
                                                                                      &test_engine,
                                                                                      salt_alice,
                                                                                      stream_id_alice,
                                                                                      STREAM_DIRECTION_ENCODE);
        
        wickr_stream_key_t *stream_key_bob = wickr_transport_root_key_to_stream_key(test_root_key,
                                                                                    &test_engine,
                                                                                    salt_bob,
                                                                                    stream_id_bob,
                                                                                    STREAM_DIRECTION_DECODE);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(stream_key_alice->cipher_key->key_data, expected_stream_key_alice_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(stream_key_alice->evolution_key, expected_stream_key_alice_evo, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(stream_key_bob->cipher_key->key_data, expected_stream_key_bob_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(stream_key_bob->evolution_key, expected_stream_key_bob_evo, NULL));
        
        SHOULD_EQUAL(stream_key_alice->packets_per_evolution, test_packet_per_evo_send);
        SHOULD_EQUAL(stream_key_bob->packets_per_evolution, test_packet_per_evo_recv);
        SHOULD_EQUAL(stream_key_alice->cipher_key->cipher.cipher_id, test_cipher.cipher_id);
        SHOULD_EQUAL(stream_key_bob->cipher_key->cipher.cipher_id, test_cipher.cipher_id);
        
        SHOULD_BE_FALSE(wickr_stream_key_is_equal(stream_key_bob, stream_key_alice));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(stream_key_alice->evolution_key, stream_key_bob->evolution_key, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(stream_key_alice->cipher_key->key_data,
                                              stream_key_bob->cipher_key->key_data, NULL));
        
        /* Cleanup */
        wickr_buffer_destroy(&salt_alice);
        wickr_buffer_destroy(&salt_bob);
        wickr_buffer_destroy(&stream_id_alice);
        wickr_buffer_destroy(&stream_id_bob);
        wickr_buffer_destroy(&expected_stream_key_alice_data);
        wickr_buffer_destroy(&expected_stream_key_bob_data);
        wickr_buffer_destroy(&expected_stream_key_alice_evo);
        wickr_buffer_destroy(&expected_stream_key_bob_evo);
        wickr_stream_key_destroy(&stream_key_alice);
        wickr_stream_key_destroy(&stream_key_bob);
    }
    END_IT
    
    IT("can be destroyed")
    {
        wickr_transport_root_key_destroy(&test_root_key);
        SHOULD_BE_NULL(test_root_key);
    }
    END_IT
}
END_DESCRIBE
