
#include "test_transport_handshake.h"
#include "transport_handshake.h"
#include "test_stream_cipher.h"
#include "private/transport_handshake_priv.h"
#include <string.h>
#include "externs.h"

bool wickr_transport_handshake_res_is_equal(wickr_transport_handshake_res_t *a, wickr_transport_handshake_res_t *b)
{
    if (!a || !b) {
        return false;
    }
    
    bool local_key_is_equal = wickr_stream_key_is_equal(wickr_transport_handshake_res_get_local_key(a),
                                                        wickr_transport_handshake_res_get_local_key(b));
    
    bool remote_key_is_equal = wickr_stream_key_is_equal(wickr_transport_handshake_res_get_remote_key(a),
                                                         wickr_transport_handshake_res_get_remote_key(b));
    
    return local_key_is_equal && remote_key_is_equal;
}

DESCRIBE(wickr_transport_handshake_res, "Wickr Transport Handshake Result")
{
    wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();
    wickr_stream_key_t *test_local_key = wickr_stream_key_create_rand(test_engine, CIPHER_AES256_GCM, 32);
    wickr_stream_key_t *test_remote_key = wickr_stream_key_create_rand(test_engine, CIPHER_AES256_GCM, 32);
    
    SHOULD_NOT_BE_NULL(test_local_key);
    SHOULD_NOT_BE_NULL(test_remote_key);
    
    wickr_transport_handshake_res_t *test_result;
    
    IT("can be created")
    {
        /* Incorrect inputs */
        SHOULD_BE_NULL(wickr_transport_handshake_res_create(test_local_key, NULL));
        SHOULD_BE_NULL(wickr_transport_handshake_res_create(NULL, test_remote_key));
        test_result = wickr_transport_handshake_res_create(test_local_key, test_remote_key);
        SHOULD_NOT_BE_NULL(test_result);
    }
    END_IT
    
    IT("has getters for its properties")
    {
        /* Test bad inputs */
        SHOULD_BE_NULL(wickr_transport_handshake_res_get_remote_key(NULL));
        SHOULD_BE_NULL(wickr_transport_handshake_res_get_local_key(NULL));
        
        /* Getters */
        SHOULD_EQUAL(wickr_transport_handshake_res_get_local_key(test_result), test_local_key);
        SHOULD_EQUAL(wickr_transport_handshake_res_get_remote_key(test_result), test_remote_key);
    }
    END_IT
    
    IT("can be copied")
    {
        /* Test bad inputs */
        SHOULD_BE_NULL(wickr_transport_handshake_res_copy(NULL));
        
        /* Make a copy */
        wickr_transport_handshake_res_t *copy = wickr_transport_handshake_res_copy(test_result);
        SHOULD_NOT_BE_NULL(copy);
        SHOULD_BE_TRUE(wickr_transport_handshake_res_is_equal(copy, test_result));
        
        SHOULD_NOT_EQUAL(wickr_transport_handshake_res_get_remote_key(copy),
                         wickr_transport_handshake_res_get_remote_key(test_result));
        
        SHOULD_NOT_EQUAL(wickr_transport_handshake_res_get_local_key(copy),
                         wickr_transport_handshake_res_get_local_key(test_result));
        
        wickr_transport_handshake_res_destroy(&copy);
    }
    END_IT
    
    IT("can be destroyed")
    {
        wickr_transport_handshake_res_destroy(&test_result);
        SHOULD_BE_NULL(test_result);
    }
    END_IT
}
END_DESCRIBE

/* Handshake test data */
wickr_crypto_engine_t test_engine;
wickr_identity_chain_t *test_local_identity = NULL;
wickr_identity_chain_t *test_remote_identity = NULL;
wickr_buffer_t *test_user_data = NULL;

wickr_transport_handshake_t *test_handshake = NULL;
wickr_transport_handshake_t *test_receive_handshake = NULL;

wickr_identity_chain_t *last_identity_callback_identity = NULL;
wickr_buffer_t *last_user_data = NULL;

static void test_handshake_identity_callback(const wickr_transport_handshake_t *handshake,
                                             wickr_identity_chain_t *identity,
                                             void *user)
{
    wickr_identity_chain_destroy(&last_identity_callback_identity);
    last_identity_callback_identity = identity;
    last_user_data = user;
}

void reset_handshake_test_data()
{
    wickr_transport_handshake_destroy(&test_handshake);
    wickr_buffer_destroy(&test_user_data);
    
    test_engine = wickr_crypto_engine_get_default();
    test_local_identity = createIdentityChain("alice");
    test_remote_identity = createIdentityChain("bob");
    
    test_user_data = test_engine.wickr_crypto_engine_crypto_random(32);
    SHOULD_NOT_BE_NULL(test_local_identity);
    SHOULD_NOT_BE_NULL(test_remote_identity);
    SHOULD_NOT_BE_NULL(test_user_data);
    
    wickr_identity_chain_destroy(&last_identity_callback_identity);
    last_user_data = NULL;
}

void verify_handshake_packet(wickr_transport_packet_t *packet, wickr_identity_chain_t *id_chain)
{
    SHOULD_EQUAL(packet->meta.mac_type, TRANSPORT_MAC_TYPE_EC_P521);
    SHOULD_BE_TRUE(wickr_transport_packet_verify(packet, &test_engine, id_chain));
    SHOULD_EQUAL(packet->meta.body_type, TRANSPORT_PAYLOAD_TYPE_HANDSHAKE);
    SHOULD_EQUAL(packet->meta.body_meta.handshake.protocol_version, 1);
}

DESCRIBE(wickr_transport_handshake, "Wickr Transport Handshake")
{
    reset_handshake_test_data();
    
    IT("can be created with all available inputs")
    {
        test_handshake = wickr_transport_handshake_create(test_engine,
                                                          test_local_identity,
                                                          test_remote_identity,
                                                          test_handshake_identity_callback,
                                                          42,
                                                          test_user_data);
        
        SHOULD_NOT_BE_NULL(test_handshake);
        
        /* Local Identity Getter */
        const wickr_identity_chain_t *local_identity = wickr_transport_handshake_get_local_identity(test_handshake);
        SHOULD_EQUAL(local_identity, test_local_identity);
        
        /* Remote Identity Getter */
        const wickr_identity_chain_t *remote_identity = wickr_transport_handshake_get_remote_identity(test_handshake);
        SHOULD_EQUAL(remote_identity, test_remote_identity);
        
        /* User Data */
        const void *user_data = wickr_transport_handshake_get_user_data(test_handshake);
        SHOULD_EQUAL(user_data, test_user_data);
        
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_handshake),
                     TRANSPORT_HANDSHAKE_STATUS_UNKNOWN);
        
        /* Check private values */
        SHOULD_EQUAL(memcmp(&test_engine, &test_handshake->engine, sizeof(wickr_crypto_engine_t)), 0);
        SHOULD_EQUAL(test_handshake->identity_callback, test_handshake_identity_callback);
        SHOULD_EQUAL(test_handshake->is_initiator, false);
        SHOULD_EQUAL(test_handshake->protocol_version, 1);
        SHOULD_EQUAL(test_handshake->evo_count, 42);
        SHOULD_BE_NULL(test_handshake->root_key);
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_transport_handshake_t *copy_handshake = wickr_transport_handshake_copy(test_handshake);
        SHOULD_NOT_BE_NULL(copy_handshake);
        
        SHOULD_NOT_EQUAL(wickr_transport_handshake_get_local_identity(copy_handshake),
                         wickr_transport_handshake_get_local_identity(test_handshake));
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(wickr_transport_handshake_get_local_identity(copy_handshake)->node->identifier,
                                             wickr_transport_handshake_get_local_identity(test_handshake)->node->identifier,
                                             NULL));
        
        SHOULD_NOT_EQUAL(wickr_transport_handshake_get_remote_identity(copy_handshake),
                         wickr_transport_handshake_get_remote_identity(test_handshake));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(wickr_transport_handshake_get_remote_identity(copy_handshake)->root->identifier,
                                             wickr_transport_handshake_get_remote_identity(test_handshake)->root->identifier,
                                             NULL));
        
        SHOULD_EQUAL(wickr_transport_handshake_get_user_data(test_handshake),
                     wickr_transport_handshake_get_user_data(copy_handshake));
        
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_handshake),
                     wickr_transport_handshake_get_status(copy_handshake));
                
        /* Check private values */
        SHOULD_EQUAL(test_handshake->is_initiator, copy_handshake->is_initiator);
        SHOULD_EQUAL(test_handshake->protocol_version, copy_handshake->protocol_version);
        SHOULD_EQUAL(test_handshake->identity_callback, test_handshake_identity_callback);
        SHOULD_EQUAL(test_handshake->evo_count, copy_handshake->evo_count);
        SHOULD_EQUAL(memcmp(&copy_handshake->engine, &test_handshake->engine, sizeof(wickr_crypto_engine_t)), 0);
        
        /* Cleanup */
        wickr_transport_handshake_destroy(&copy_handshake);
    }
    END_IT
    
    reset_handshake_test_data();
    
    IT("can't be created without a local identity")
    {
        SHOULD_BE_NULL(wickr_transport_handshake_create(test_engine, NULL, test_remote_identity, 0, 42, NULL));
    }
    END_IT
    
    IT("can't be created if the evo count isn't > 0")
    {
        SHOULD_BE_NULL(wickr_transport_handshake_create(test_engine, test_local_identity, test_remote_identity, 0, 0, NULL));
    }
    END_IT
    
    IT("can be created without a remote identity and user data")
    {
        test_handshake = wickr_transport_handshake_create(test_engine,
                                                          test_local_identity,
                                                          NULL,
                                                          test_handshake_identity_callback,
                                                          42,
                                                          NULL);
        
        SHOULD_NOT_BE_NULL(test_handshake);
        
        /* Local Identity Getter */
        const wickr_identity_chain_t *local_identity = wickr_transport_handshake_get_local_identity(test_handshake);
        SHOULD_EQUAL(local_identity, test_local_identity);
        
        /* Remote Identity Getter */
        const wickr_identity_chain_t *remote_identity = wickr_transport_handshake_get_remote_identity(test_handshake);
        SHOULD_BE_NULL(remote_identity);
        
        /* User Data */
        const void *user_data = wickr_transport_handshake_get_user_data(test_handshake);
        SHOULD_BE_NULL(user_data);
        
        /* Check private values */
        SHOULD_EQUAL(memcmp(&test_engine, &test_handshake->engine, sizeof(wickr_crypto_engine_t)), 0);
        SHOULD_EQUAL(test_handshake->identity_callback, test_handshake_identity_callback);
        SHOULD_EQUAL(test_handshake->is_initiator, false);
        SHOULD_EQUAL(test_handshake->protocol_version, 1);
        SHOULD_BE_NULL(test_handshake->root_key);
    }
    END_IT
    
    wickr_identity_chain_destroy(&test_remote_identity);
    reset_handshake_test_data();
    
    /* Start packet to use for receive tests */
    wickr_transport_packet_t *start_packet = NULL;
    
    /* STARTING THE HANDSHAKE */
    
    IT("can be started")
    {
        /* Bad inputs */
        SHOULD_BE_NULL(wickr_transport_handshake_start(NULL));
        
        /* Good input */
        test_handshake = wickr_transport_handshake_create(test_engine,
                                                          test_local_identity,
                                                          test_remote_identity,
                                                          test_handshake_identity_callback,
                                                          42,
                                                          test_user_data);
        
        SHOULD_NOT_BE_NULL(test_handshake);
        
        /* Start the handshake */
        start_packet = wickr_transport_handshake_start(test_handshake);
        SHOULD_NOT_BE_NULL(start_packet);
        
        /* The resulting packet should be a handshake packet signed with the local private key */
        verify_handshake_packet(start_packet, test_local_identity);
        
        /* The handshake should now have an updated status */
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_handshake), TRANSPORT_HANDSHAKE_STATUS_IN_PROGRESS);
        SHOULD_NOT_BE_NULL(test_handshake->local_ephemeral_key);
        SHOULD_BE_NULL(test_handshake->root_key);
        
        /* Make sure the identity callback didn't fire */
        SHOULD_BE_NULL(last_user_data);
        SHOULD_BE_NULL(last_identity_callback_identity);
        
        /* The handshake should have recorded the packet internally */
        SHOULD_NOT_BE_NULL(wickr_array_fetch_item(test_handshake->packet_list, 0, false));
        SHOULD_EQUAL(test_handshake->is_initiator, true);
    }
    END_IT
    
    IT("can't be started again once it is in progress")
    {
        wickr_transport_handshake_t *copy = wickr_transport_handshake_copy(test_handshake);
        SHOULD_BE_NULL(wickr_transport_handshake_start(copy));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(copy), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        wickr_transport_handshake_destroy(&copy);
    }
    END_IT
    
    IT("can't be started if it is in a failure state")
    {
        wickr_transport_handshake_t *copy = wickr_transport_handshake_copy(test_handshake);
        copy->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        SHOULD_BE_NULL(wickr_transport_handshake_start(copy));
        wickr_transport_handshake_destroy(&copy);
    }
    END_IT
    
    /* RECEIVING A START PACKET */
    
    IT("will fail initialization the incoming packet is not signed by the specified remote identity")
    {
        /* We create the test receive handshake by swapping the local / remote identities */
        test_receive_handshake = wickr_transport_handshake_create(test_engine,
                                                                  wickr_identity_chain_copy(test_remote_identity),
                                                                  wickr_identity_chain_copy(test_local_identity),
                                                                  test_handshake_identity_callback,
                                                                  42,
                                                                  test_user_data);
        
        SHOULD_NOT_BE_NULL(test_receive_handshake);
        
        wickr_transport_packet_t *copy_start = wickr_transport_packet_copy(start_packet);
        
        /* Sign with the incorrect identity */
        wickr_identity_chain_t *incorrect = createIdentityChain("charlie");
        SHOULD_NOT_BE_NULL(incorrect);
        
        wickr_buffer_destroy(&copy_start->mac);
        SHOULD_BE_TRUE(wickr_transport_packet_sign(copy_start, &test_engine, incorrect));
        
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_receive_handshake, copy_start));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_receive_handshake), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        /* Cleanup */
        wickr_identity_chain_destroy(&incorrect);
        wickr_transport_packet_destroy(&copy_start);
    }
    END_IT
    
    wickr_transport_handshake_destroy(&test_receive_handshake);
    
    IT("will fail initialization if the incoming packet has been modified")
    {
        /* We create the test receive handshake by swapping the local / remote identities */
        test_receive_handshake = wickr_transport_handshake_create(test_engine,
                                                                  wickr_identity_chain_copy(test_remote_identity),
                                                                  wickr_identity_chain_copy(test_local_identity),
                                                                  test_handshake_identity_callback,
                                                                  42,
                                                                  test_user_data);
        
        wickr_transport_packet_t *copy_start = wickr_transport_packet_copy(start_packet);
        memset(copy_start->body->bytes, 42, 1);
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_receive_handshake, copy_start));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_receive_handshake), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        /* Cleanup */
        wickr_transport_packet_destroy(&copy_start);
    }
    END_IT
    
    wickr_transport_handshake_destroy(&test_receive_handshake);
    
    IT("will fail initialization if the incoming packet is not a handshake packet")
    {
        /* We create the test receive handshake by swapping the local / remote identities */
        test_receive_handshake = wickr_transport_handshake_create(test_engine,
                                                                  wickr_identity_chain_copy(test_remote_identity),
                                                                  wickr_identity_chain_copy(test_local_identity),
                                                                  test_handshake_identity_callback,
                                                                  42,
                                                                  test_user_data);
        
        wickr_transport_packet_t *copy_start = wickr_transport_packet_copy(start_packet);
        copy_start->meta.body_type = TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT;
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_receive_handshake, copy_start));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_receive_handshake), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        /* Cleanup */
        wickr_transport_packet_destroy(&copy_start);
    }
    END_IT
    
    wickr_transport_handshake_destroy(&test_receive_handshake);
    
    IT("will fail initialization if the incoming packet is the wrong protocol version")
    {
        /* We create the test receive handshake by swapping the local / remote identities */
        test_receive_handshake = wickr_transport_handshake_create(test_engine,
                                                                  wickr_identity_chain_copy(test_remote_identity),
                                                                  wickr_identity_chain_copy(test_local_identity),
                                                                  test_handshake_identity_callback,
                                                                  42,
                                                                  test_user_data);
        
        wickr_transport_packet_t *copy_start = wickr_transport_packet_copy(start_packet);
        copy_start->meta.body_meta.handshake.protocol_version = 2;
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_receive_handshake, copy_start));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_receive_handshake), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        /* Cleanup */
        wickr_transport_packet_destroy(&copy_start);
    }
    END_IT
    
    IT("will fail initialization if the handshake is already in a failure state")
    {
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_receive_handshake, start_packet));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_receive_handshake), TRANSPORT_HANDSHAKE_STATUS_FAILED);
    }
    END_IT
    
    wickr_transport_handshake_destroy(&test_receive_handshake);
    
    IT("can be initialized by an incoming start packet (with remote identity)")
    {
        /* We create the test receive handshake by swapping the local / remote identities */
        test_receive_handshake = wickr_transport_handshake_create(test_engine,
                                                                  wickr_identity_chain_copy(test_remote_identity),
                                                                  wickr_identity_chain_copy(test_local_identity),
                                                                  test_handshake_identity_callback,
                                                                  42,
                                                                  test_user_data);
        
        SHOULD_NOT_BE_NULL(test_receive_handshake);
        
        wickr_transport_packet_t *return_packet = wickr_transport_handshake_process(test_receive_handshake,
                                                                                    start_packet);
        
        SHOULD_NOT_BE_NULL(return_packet);
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_receive_handshake),
                     TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION);
        
        /* The resulting packet should be a handshake packet signed with the local private key */
        verify_handshake_packet(return_packet, test_remote_identity);
        
        /* The handshake should have set a root key because it is now pending finalization */
        SHOULD_NOT_BE_NULL(test_receive_handshake->root_key);
        
        /* The handshake should have recorded both packets internally */
        SHOULD_NOT_BE_NULL(wickr_array_fetch_item(test_receive_handshake->packet_list, 0, false));
        SHOULD_NOT_BE_NULL(wickr_array_fetch_item(test_receive_handshake->packet_list, 1, false));
        
        /* Verify the identity callback did not get called because the remote identity was configured */
        SHOULD_BE_NULL(last_user_data);
        SHOULD_BE_NULL(last_identity_callback_identity);
        
        SHOULD_EQUAL(test_receive_handshake->is_initiator, false);
        
        /* Cleanup */
        wickr_transport_packet_destroy(&return_packet);
        wickr_buffer_destroy(&last_user_data);
        wickr_identity_chain_destroy(&last_identity_callback_identity);
    }
    END_IT
    
    wickr_transport_handshake_destroy(&test_receive_handshake);
    
    /* HANDLING IDENTITY CALLBACKS FOR START PACKET */
    
    IT("can be initialized by an incoming start packet (without remote set)")
    {
        /* We create the test receive handshake by swapping the local / remote identities */
        test_receive_handshake = wickr_transport_handshake_create(test_engine,
                                                                  wickr_identity_chain_copy(test_remote_identity),
                                                                  NULL,
                                                                  test_handshake_identity_callback,
                                                                  42,
                                                                  test_user_data);
        
        SHOULD_NOT_BE_NULL(test_receive_handshake);
        
        wickr_transport_packet_t *return_packet = wickr_transport_handshake_process(test_receive_handshake,
                                                                                    start_packet);
        
        SHOULD_BE_NULL(return_packet);
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_receive_handshake),
                     TRANSPORT_HANDSHAKE_STATUS_PENDING_VERIFICATION);
        
        /* The handshake should have recorded the packet internally */
        SHOULD_NOT_BE_NULL(wickr_array_fetch_item(test_receive_handshake->packet_list, 0, false));
        
        /* Verify the identity callback was called because the remote identity was not set */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_receive_handshake->remote_identity->node->identifier,
                                             test_handshake->local_identity->node->identifier, NULL));
        SHOULD_EQUAL(last_user_data, test_user_data);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(last_identity_callback_identity->root->identifier,
                                             test_receive_handshake->remote_identity->root->identifier, NULL));
        
        SHOULD_EQUAL(test_receive_handshake->is_initiator, false);
    }
    END_IT
    
    wickr_buffer_destroy(&last_user_data);
    wickr_identity_chain_destroy(&last_identity_callback_identity);
    
    IT("can not process new packets while in the pending verification state")
    {
        wickr_transport_handshake_t *copy = wickr_transport_handshake_copy(test_receive_handshake);
        SHOULD_BE_NULL(wickr_transport_handshake_process(copy, start_packet));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(copy), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        wickr_transport_handshake_destroy(&copy);
    }
    END_IT
    
    wickr_transport_packet_destroy(&start_packet);
    wickr_transport_packet_t *return_packet = NULL;
    
    wickr_transport_handshake_t *test_identity_failure_handshake = wickr_transport_handshake_copy(test_receive_handshake);
    
    IT("will continue processing the prior packet upon identity validation")
    {
        return_packet = wickr_transport_handshake_verify_identity(test_receive_handshake, true);
        
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_receive_handshake),
                     TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION);
        
        /* The resulting packet should be a handshake packet signed with the local private key */
        verify_handshake_packet(return_packet, test_remote_identity);
        
        /* The handshake should have set a root key because it is now pending finalization */
        SHOULD_NOT_BE_NULL(test_receive_handshake->root_key);
        
        /* The handshake should have recorded the return packet internally */
        SHOULD_NOT_BE_NULL(wickr_array_fetch_item(test_receive_handshake->packet_list, 1, false));
    }
    END_IT
    
    IT("will move to failure case if the identity validation is reported as a failure")
    {
        SHOULD_BE_NULL(wickr_transport_handshake_verify_identity(test_identity_failure_handshake, false));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_identity_failure_handshake),
                     TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        /* The handshake should not have a root key because it failed */
        SHOULD_BE_NULL(test_identity_failure_handshake->root_key);
        
        /* The handshake should not allow identity verify after it is failed */
        SHOULD_BE_NULL(wickr_transport_handshake_verify_identity(test_identity_failure_handshake, true));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_identity_failure_handshake),
                     TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
    }
    END_IT
    
    wickr_transport_handshake_destroy(&test_identity_failure_handshake);
    
    /* RECEIVING THE RESPONSE PACKET */
    
    wickr_transport_handshake_t *test_error_handshake = wickr_transport_handshake_copy(test_handshake);
    SHOULD_NOT_BE_NULL(test_error_handshake);
        
    IT("will move into the pending finalization state after receiving a response to the start packet")
    {
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_handshake, return_packet));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_handshake),
                     TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION);
        
        /* The handshake should have set a root key because it is now pending finalization */
        SHOULD_NOT_BE_NULL(test_receive_handshake->root_key);
        
        /* Verify the identity callback did not get called because the remote identity was configured */
        SHOULD_BE_NULL(last_user_data);
        SHOULD_BE_NULL(last_identity_callback_identity);
        
        /* The handshake should have recorded the packet internally */
        SHOULD_NOT_BE_NULL(wickr_array_fetch_item(test_receive_handshake->packet_list, 1, false));
    }
    END_IT
    
    IT("will move to a failure state if the response to the start packet was not signed properly")
    {
        wickr_transport_handshake_t *test_error_copy = wickr_transport_handshake_copy(test_error_handshake);
        SHOULD_NOT_BE_NULL(test_error_copy);
        
        wickr_transport_packet_t *copy_return = wickr_transport_packet_copy(return_packet);
        
        /* Sign with the incorrect identity */
        wickr_identity_chain_t *incorrect = createIdentityChain("charlie");
        SHOULD_NOT_BE_NULL(incorrect);
        
        wickr_buffer_destroy(&copy_return->mac);
        SHOULD_BE_TRUE(wickr_transport_packet_sign(copy_return, &test_engine, incorrect));
        
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_error_copy, copy_return));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_error_copy), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        /* Cleanup */
        wickr_identity_chain_destroy(&incorrect);
        wickr_transport_packet_destroy(&copy_return);
        wickr_transport_handshake_destroy(&test_error_copy);
    }
    END_IT
    
    IT("will move to a failure state if the response to the start packet was modified in transit")
    {
        wickr_transport_handshake_t *test_error_copy = wickr_transport_handshake_copy(test_error_handshake);
        SHOULD_NOT_BE_NULL(test_error_copy);
        
        wickr_transport_packet_t *copy_return = wickr_transport_packet_copy(return_packet);
        memset(copy_return->body->bytes, 42, 1);
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_error_copy, copy_return));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_error_copy), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        /* Cleanup */
        wickr_transport_packet_destroy(&copy_return);
        wickr_transport_handshake_destroy(&test_error_copy);
    }
    END_IT
    
    IT("will move to a failure state if the response to the start packet is not a handshake packet")
    {
        wickr_transport_handshake_t *test_error_copy = wickr_transport_handshake_copy(test_error_handshake);
        SHOULD_NOT_BE_NULL(test_error_copy);
        
        wickr_transport_packet_t *copy_return = wickr_transport_packet_copy(return_packet);
        copy_return->meta.body_type = TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT;
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_error_copy, copy_return));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_error_copy), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        /* Will not allow processing while in a failure state */
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_error_copy, return_packet));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_error_copy), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        /* Cleanup */
        wickr_transport_packet_destroy(&copy_return);
        wickr_transport_handshake_destroy(&test_error_copy);
    }
    END_IT
    
    wickr_transport_handshake_destroy(&test_error_handshake);
    
    /* HANDLING IDENTITY CALLBACKS FOR RESPONSE PACKET */
    
    wickr_transport_handshake_t *test_identity_handshake = wickr_transport_handshake_create(test_engine,
                                                                                            wickr_identity_chain_copy(test_local_identity),
                                                                                            NULL,
                                                                                            test_handshake_identity_callback,
                                                                                            42,
                                                                                            test_user_data);
    
    wickr_transport_handshake_t *test_identity_handshake_receive = wickr_transport_handshake_create(test_engine,
                                                                                                    wickr_identity_chain_copy(test_remote_identity),
                                                                                                    wickr_identity_chain_copy(test_local_identity),
                                                                                                    test_handshake_identity_callback,
                                                                                                    42,
                                                                                                    test_user_data);
    
    SHOULD_NOT_BE_NULL(test_identity_handshake);
    SHOULD_NOT_BE_NULL(test_identity_handshake_receive);
    
    wickr_transport_packet_t *identity_start_packet = wickr_transport_handshake_start(test_identity_handshake);
    wickr_transport_packet_t *identity_return_packet = wickr_transport_handshake_process(test_identity_handshake_receive, identity_start_packet);
    
    SHOULD_NOT_BE_NULL(identity_start_packet);
    
    IT("will require a callback when receiving a response to the start packet if the identity was not specified in advance")
    {
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_identity_handshake, identity_return_packet));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_identity_handshake), TRANSPORT_HANDSHAKE_STATUS_PENDING_VERIFICATION);
        
        /* The handshake should have recorded the packet internally */
        SHOULD_NOT_BE_NULL(wickr_array_fetch_item(test_identity_handshake->packet_list, 1, false));
        
        /* Verify the identity callback was called because the remote identity was not set */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_identity_handshake_receive->remote_identity->node->identifier,
                                             test_identity_handshake->local_identity->node->identifier, NULL));
        SHOULD_EQUAL(last_user_data, test_user_data);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(last_identity_callback_identity->root->identifier,
                                             test_identity_handshake_receive->local_identity->root->identifier, NULL));
    }
    END_IT
    
    IT("will not allow finalization while in the pending verification state")
    {
        wickr_transport_handshake_t *copy = wickr_transport_handshake_copy(test_identity_handshake);
        SHOULD_NOT_BE_NULL(copy);
        
        SHOULD_BE_NULL(wickr_transport_handshake_finalize(copy));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(copy), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        wickr_transport_handshake_destroy(&copy);
    }
    END_IT
    
    IT("will move to the pending finalization state after a successful identity callback triggered by a response to a start packet")
    {
        wickr_transport_handshake_t *copy = wickr_transport_handshake_copy(test_identity_handshake);
        SHOULD_BE_NULL(wickr_transport_handshake_verify_identity(copy, true));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(copy),
                     TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION);
        
        /* The handshake should have set a root key because it is now pending finalization */
        SHOULD_NOT_BE_NULL(copy->root_key);
        
        wickr_transport_handshake_destroy(&copy);
    }
    END_IT
    
    IT("will move to the failure state after the identity callback triggered by a response to a start packet")
    {
        wickr_transport_handshake_t *copy = wickr_transport_handshake_copy(test_identity_handshake);
        SHOULD_BE_NULL(wickr_transport_handshake_verify_identity(copy, false));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(copy),
                     TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        /* Will not allow verification again after failure state */
        SHOULD_BE_NULL(wickr_transport_handshake_verify_identity(test_identity_handshake, true));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(copy),
                     TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        wickr_transport_handshake_destroy(&copy);
    }
    END_IT
    
    wickr_transport_packet_destroy(&identity_start_packet);
    wickr_transport_packet_destroy(&identity_return_packet);
    wickr_transport_handshake_destroy(&test_identity_handshake);
    wickr_transport_handshake_destroy(&test_identity_handshake_receive);
    
    /* FINALIZING THE HANDSHAKE */
    
    wickr_transport_handshake_res_t *initiator_result = NULL;
    wickr_transport_handshake_res_t *receiver_result = NULL;
    
    IT("should finalize the handshake and provide the proper stream keys")
    {
        /* Test bad input */
        SHOULD_BE_NULL(wickr_transport_handshake_finalize(NULL));
        
        /* Finalize both test handshakes */
        initiator_result = wickr_transport_handshake_finalize(test_handshake);
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_handshake), TRANSPORT_HANDSHAKE_STATUS_COMPLETE);
        
        receiver_result = wickr_transport_handshake_finalize(test_receive_handshake);
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_receive_handshake), TRANSPORT_HANDSHAKE_STATUS_COMPLETE);
        
        SHOULD_NOT_BE_NULL(initiator_result);
        SHOULD_NOT_BE_NULL(receiver_result);
        
        /* Make sure the two results mirror each other */
        
        SHOULD_BE_TRUE(wickr_stream_key_is_equal(wickr_transport_handshake_res_get_local_key(initiator_result),
                                                 wickr_transport_handshake_res_get_remote_key(receiver_result)));
        
        SHOULD_BE_TRUE(wickr_stream_key_is_equal(wickr_transport_handshake_res_get_remote_key(initiator_result),
                                                 wickr_transport_handshake_res_get_local_key(receiver_result)));
    }
    END_IT
    
    /* VERIFY RANDOMNESS */
    
    IT("will produce random key material each time the handshake happens between the same parties")
    {
        for (unsigned i = 0; i < 100; i++) {
            wickr_transport_handshake_t *alice = wickr_transport_handshake_create(test_engine,
                                                                                  wickr_identity_chain_copy(test_local_identity),
                                                                                  wickr_identity_chain_copy(test_remote_identity),
                                                                                  test_handshake_identity_callback,
                                                                                  42,
                                                                                  NULL);
            
            wickr_transport_handshake_t *bob = wickr_transport_handshake_create(test_engine,
                                                                                wickr_identity_chain_copy(test_remote_identity),
                                                                                wickr_identity_chain_copy(test_local_identity),
                                                                                test_handshake_identity_callback,
                                                                                42,
                                                                                NULL);
            
            SHOULD_NOT_BE_NULL(alice);
            SHOULD_NOT_BE_NULL(bob);
            
            wickr_transport_packet_t *start_packet = wickr_transport_handshake_start(alice);
            
            SHOULD_NOT_BE_NULL(start_packet);
            
            wickr_transport_packet_t *return_packet = wickr_transport_handshake_process(bob, start_packet);
            wickr_transport_packet_destroy(&start_packet);
            
            SHOULD_NOT_BE_NULL(return_packet);
            
            wickr_transport_handshake_process(alice, return_packet);
            wickr_transport_packet_destroy(&return_packet);
            
            wickr_transport_handshake_res_t *alice_result = wickr_transport_handshake_finalize(alice);
            wickr_transport_handshake_res_t *bob_result = wickr_transport_handshake_finalize(bob);
            
            SHOULD_BE_FALSE(wickr_stream_key_is_equal(wickr_transport_handshake_res_get_local_key(alice_result),
                                                      wickr_transport_handshake_res_get_local_key(initiator_result)));
            
            SHOULD_BE_FALSE(wickr_stream_key_is_equal(wickr_transport_handshake_res_get_local_key(bob_result),
                                                      wickr_transport_handshake_res_get_local_key(receiver_result)));
            
            wickr_transport_handshake_res_destroy(&alice_result);
            wickr_transport_handshake_res_destroy(&bob_result);
            
            wickr_transport_handshake_destroy(&alice);
            wickr_transport_handshake_destroy(&bob);
        }
    }
    END_IT
    
    wickr_transport_handshake_res_destroy(&initiator_result);
    wickr_transport_handshake_res_destroy(&receiver_result);
    
    IT("will not allow further processing after finalization")
    {
        /* Can't finalize again */
        SHOULD_BE_NULL(wickr_transport_handshake_finalize(test_receive_handshake));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_receive_handshake), TRANSPORT_HANDSHAKE_STATUS_FAILED);
        
        /* Can't process more packets */
        SHOULD_BE_NULL(wickr_transport_handshake_process(test_handshake, return_packet));
        SHOULD_EQUAL(wickr_transport_handshake_get_status(test_handshake), TRANSPORT_HANDSHAKE_STATUS_FAILED);
    }
    END_IT
    
    wickr_transport_packet_destroy(&return_packet);
    wickr_transport_packet_destroy(&start_packet);
    wickr_identity_chain_destroy(&last_identity_callback_identity);
    
    IT("can be destroyed")
    {
        wickr_transport_handshake_destroy(&test_handshake);
        wickr_transport_handshake_destroy(&test_receive_handshake);
        SHOULD_BE_NULL(test_handshake);
    }
    END_IT
}
END_DESCRIBE

