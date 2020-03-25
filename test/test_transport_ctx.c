
#include "test_transport_ctx.h"
#include "test_stream_cipher.h"
#include "transport_ctx.h"
#include "private/transport_priv.h"
#include "externs.h"
#include <string.h>

/* Alice Callbacks */

wickr_buffer_t *alice_last_tx = NULL;
wickr_buffer_t *alice_last_rx = NULL;
wickr_transport_status alice_last_status = TRANSPORT_HANDSHAKE_STATUS_UNKNOWN;
wickr_transport_error alice_last_error = TRANSPORT_ERROR_NONE;
wickr_identity_chain_t *alice_last_identity = NULL;

void wickr_transport_alice_tx_func(const wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    alice_last_tx = data;
}

void wickr_transport_alice_rx_func(const wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    alice_last_rx = data;
}

void wickr_transport_alice_state_change_func(const wickr_transport_ctx_t *ctx, wickr_transport_status status)
{
    alice_last_status = status;
    
    if (status == TRANSPORT_STATUS_ERROR) {
        alice_last_error = wickr_transport_ctx_get_last_error(ctx);
    }
}

void wickr_transport_alice_validate_identity_func(const wickr_transport_ctx_t *ctx, wickr_identity_chain_t *identity,
                                                   wickr_transport_validate_identity_callback on_complete)
{
    alice_last_identity = identity;
    on_complete(ctx, true);
}

void wickr_transport_alice_validate_identity_fail_func(const wickr_transport_ctx_t *ctx, wickr_identity_chain_t *identity,
                                                        wickr_transport_validate_identity_callback on_complete)
{
    alice_last_identity = identity;
    on_complete(ctx, false);
}

/* Bob Callbacks */

wickr_buffer_t *bob_last_tx = NULL;
wickr_buffer_t *bob_last_rx = NULL;
wickr_transport_status bob_last_status = TRANSPORT_STATUS_NONE;
wickr_transport_error bob_last_error = TRANSPORT_ERROR_NONE;
wickr_identity_chain_t *bob_last_identity = NULL;

void wickr_transport_bob_tx_func(const wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    bob_last_tx = data;
}

void wickr_transport_bob_rx_func(const wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    bob_last_rx = data;
}

void wickr_transport_bob_state_change_func(const wickr_transport_ctx_t *ctx, wickr_transport_status status)
{
    bob_last_status = status;
    
    if (status == TRANSPORT_STATUS_ERROR) {
        bob_last_error = wickr_transport_ctx_get_last_error(ctx);
    }
}

void wickr_transport_bob_validate_identity_func(const wickr_transport_ctx_t *ctx, wickr_identity_chain_t *identity,
                                                 wickr_transport_validate_identity_callback on_complete)
{
    bob_last_identity = identity;
    on_complete(ctx, true);
}

void wickr_transport_bob_validate_identity_fail_func(const wickr_transport_ctx_t *ctx, wickr_identity_chain_t *identity,
                                                      wickr_transport_validate_identity_callback on_complete)
{
    bob_last_identity = identity;
    on_complete(ctx, false);
}

void reset_callback_data() {
    /* Alice */
    wickr_buffer_destroy(&alice_last_rx);
    wickr_buffer_destroy(&alice_last_tx);
    alice_last_status = TRANSPORT_STATUS_NONE;
    alice_last_error = TRANSPORT_ERROR_NONE;
    wickr_identity_chain_destroy(&alice_last_identity);
    
    /* Bob */
    wickr_buffer_destroy(&bob_last_rx);
    wickr_buffer_destroy(&bob_last_tx);
    bob_last_status = TRANSPORT_STATUS_NONE;
    bob_last_error = TRANSPORT_ERROR_NONE;
    wickr_identity_chain_destroy(&bob_last_identity);
}

DESCRIBE(wickr_transport_ctx, "Wickr Transport Context")
{
    wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();
    
    wickr_transport_callbacks_t alice_callbacks = {
        .tx = wickr_transport_alice_tx_func,
        .rx = wickr_transport_alice_rx_func,
        .on_state = wickr_transport_alice_state_change_func,
        .on_identity_verify = wickr_transport_alice_validate_identity_func
    };
    
    wickr_transport_callbacks_t bob_callbacks = {
        .tx = wickr_transport_bob_tx_func,
        .rx = wickr_transport_bob_rx_func,
        .on_state = wickr_transport_bob_state_change_func,
        .on_identity_verify = wickr_transport_bob_validate_identity_func
    };
    
    IT("can be created with a remote")
    {
        wickr_identity_chain_t *local_identity = createIdentityChain("local");
        wickr_identity_chain_t *remote_identity = createIdentityChain("remote");
        
        /* Missing Inputs */
        SHOULD_BE_NULL(wickr_transport_ctx_create(test_engine, NULL, remote_identity, 0, alice_callbacks, NULL));
        
        /* Proper Creation with remote */
        wickr_transport_ctx_t *test_transport_remote = wickr_transport_ctx_create(test_engine,
                                                                                  local_identity,
                                                                                  remote_identity, 42,
                                                                                  alice_callbacks, NULL);
        
        SHOULD_NOT_BE_NULL(test_transport_remote);
        SHOULD_EQUAL(wickr_transport_ctx_get_local_identity_ptr(test_transport_remote), local_identity);
        SHOULD_EQUAL(wickr_transport_ctx_get_remote_identity_ptr(test_transport_remote), remote_identity);
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_remote), TRANSPORT_STATUS_NONE);
        SHOULD_EQUAL(wickr_transport_ctx_get_last_error(test_transport_remote), TRANSPORT_ERROR_NONE);
        
        /* Verify private values */
        SHOULD_EQUAL(memcmp(&test_transport_remote->engine, &test_engine, sizeof(wickr_crypto_engine_t)), 0);
        SHOULD_EQUAL(memcmp(&test_transport_remote->callbacks, &alice_callbacks, sizeof(wickr_transport_callbacks_t)), 0);
        SHOULD_EQUAL(test_transport_remote->evo_count, 42);
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_remote);
    }
    END_IT
    
    IT("will fail creation if the evo count is out of range")
    {
        wickr_identity_chain_t *local_identity = createIdentityChain("local");
        wickr_identity_chain_t *remote_identity = createIdentityChain("remote");
        
        SHOULD_BE_NULL(wickr_transport_ctx_create(test_engine, local_identity, remote_identity, PACKET_PER_EVO_MAX + 1, alice_callbacks, NULL));
        
        wickr_identity_chain_destroy(&local_identity);
        wickr_identity_chain_destroy(&remote_identity);
    }
    END_IT
    
    IT("will set a default value for evo count if 0 is passed")
    {
        wickr_identity_chain_t *local_identity = createIdentityChain("local");
        wickr_identity_chain_t *remote_identity = createIdentityChain("remote");
        
        wickr_transport_ctx_t *ctx = wickr_transport_ctx_create(test_engine, local_identity, remote_identity, 0, alice_callbacks, NULL);
        SHOULD_EQUAL(ctx->evo_count, PACKET_PER_EVO_DEFAULT);
        
        wickr_transport_ctx_destroy(&ctx);
    }
    END_IT
    
    IT("can be created without a remote")
    {
        wickr_identity_chain_t *local_identity = createIdentityChain("local");
        
        /* Creation without remote */
        wickr_transport_ctx_t *test_transport_no_remote = wickr_transport_ctx_create(test_engine,
                                                                                  local_identity,
                                                                                  NULL, 42,
                                                                                  alice_callbacks, NULL);
        
        SHOULD_NOT_BE_NULL(test_transport_no_remote);
        SHOULD_EQUAL(wickr_transport_ctx_get_local_identity_ptr(test_transport_no_remote), local_identity);
        SHOULD_EQUAL(wickr_transport_ctx_get_remote_identity_ptr(test_transport_no_remote), NULL);
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_no_remote), TRANSPORT_STATUS_NONE);
        SHOULD_EQUAL(wickr_transport_ctx_get_last_error(test_transport_no_remote), TRANSPORT_ERROR_NONE);
        
        /* Verify private values */
        SHOULD_EQUAL(memcmp(&test_transport_no_remote->engine, &test_engine, sizeof(wickr_crypto_engine_t)), 0);
        SHOULD_EQUAL(memcmp(&test_transport_no_remote->callbacks, &alice_callbacks, sizeof(wickr_transport_callbacks_t)), 0);
        SHOULD_EQUAL(test_transport_no_remote->evo_count, 42);
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_no_remote);
    }
    END_IT
    
    IT("can be created with user data")
    {
        wickr_identity_chain_t *local_identity = createIdentityChain("local");
        wickr_buffer_t *user_data = test_engine.wickr_crypto_engine_crypto_random(32);
        
        wickr_transport_ctx_t *test_transport = wickr_transport_ctx_create(test_engine,
                                                                           local_identity,
                                                                           NULL, 42,
                                                                           alice_callbacks, user_data);
        
        SHOULD_EQUAL(wickr_transport_ctx_get_user_ctx(test_transport), user_data);
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport);
        wickr_buffer_destroy(&user_data);
    }
    END_IT
    
    IT("can be started with a handshake")
    {
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 createIdentityChain("alice"),
                                                                                 createIdentityChain("bob"), 0,
                                                                                 alice_callbacks,
                                                                                 NULL);
        
        wickr_transport_ctx_start(test_transport_alice);
        SHOULD_EQUAL(alice_last_status, TRANSPORT_STATUS_INITIAL_HANDSHAKE);
        
        SHOULD_NOT_BE_NULL(alice_last_tx);
        SHOULD_BE_NULL(alice_last_rx);
        SHOULD_BE_NULL(alice_last_identity);
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_alice), alice_last_status);
        
        wickr_transport_ctx_destroy(&test_transport_alice);
    }
    END_IT
    
    reset_callback_data();
    
    IT("will fail to kick off another handshake if one has already been started")
    {
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 createIdentityChain("alice"),
                                                                                 createIdentityChain("bob"), 0,
                                                                                 alice_callbacks,
                                                                                 NULL);
        
        /* Simulate a double start */
        wickr_transport_ctx_start(test_transport_alice);
        wickr_transport_ctx_start(test_transport_alice);
        
        SHOULD_EQUAL(alice_last_status, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(alice_last_error, TRANSPORT_ERROR_BAD_START_STATUS);
        
        wickr_transport_ctx_destroy(&test_transport_alice);
    }
    END_IT
    
    reset_callback_data();
    
    IT("will fail to process data packets if the initial handshake is in process")
    {
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 createIdentityChain("alice"),
                                                                                 createIdentityChain("bob"), 0,
                                                                                 alice_callbacks,
                                                                                 NULL);
        
        wickr_transport_ctx_start(test_transport_alice);
        
        /* Make a fake data packet */
        wickr_transport_packet_meta_t meta;
        wickr_transport_packet_meta_initialize_data(&meta, 42, TRANSPORT_MAC_TYPE_AUTH_CIPHER);
        wickr_buffer_t *packet_contents = test_engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_packet_t *packet = wickr_transport_packet_create(meta, packet_contents);
        wickr_buffer_t *packet_buffer = wickr_transport_packet_serialize(packet);
        wickr_transport_packet_destroy(&packet);
        
        /* Inject packet into the transport */
        wickr_transport_ctx_process_rx_buffer(test_transport_alice, packet_buffer);
        SHOULD_EQUAL(alice_last_status, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(alice_last_error, TRANSPORT_ERROR_BAD_RX_STATE);
        SHOULD_BE_NULL(alice_last_rx);
        
        /* Cleanup */
        wickr_buffer_destroy(&packet_buffer);
        wickr_transport_ctx_destroy(&test_transport_alice);
        reset_callback_data();
    }
    END_IT
    
    reset_callback_data();
    
    IT("can be initialized by an incoming handshake packet")
    {
        wickr_identity_chain_t *alice_identity = createIdentityChain("alice");
        wickr_identity_chain_t *bob_identity = createIdentityChain("bob");
        
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 alice_identity,
                                                                                 bob_identity, 42,
                                                                                 alice_callbacks, NULL);
        
        wickr_transport_ctx_t *test_transport_bob = wickr_transport_ctx_create(test_engine,
                                                                               wickr_identity_chain_copy(bob_identity),
                                                                               wickr_identity_chain_copy(alice_identity),
                                                                               43, bob_callbacks, NULL);
        
        /* Start the alice transport */
        wickr_transport_ctx_start(test_transport_alice);
        SHOULD_EQUAL(alice_last_status, TRANSPORT_STATUS_INITIAL_HANDSHAKE);
        
        /* Initialize bob transport with alice packet */
        wickr_transport_ctx_process_rx_buffer(test_transport_bob, alice_last_tx);
        
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_bob), TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(bob_last_status, TRANSPORT_STATUS_ACTIVE);
        SHOULD_NOT_BE_NULL(bob_last_tx);
        SHOULD_BE_NULL(bob_last_rx);
        SHOULD_NOT_BE_NULL(test_transport_bob->rx_stream);
        SHOULD_NOT_BE_NULL(test_transport_bob->tx_stream);
        
        /* Complete the handshake */
        
        wickr_transport_ctx_process_rx_buffer(test_transport_alice, bob_last_tx);
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_alice), TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(alice_last_status, TRANSPORT_STATUS_ACTIVE);
        SHOULD_BE_NULL(alice_last_rx);
        
        /* Verify private data */
        SHOULD_BE_TRUE(wickr_stream_key_is_equal(test_transport_alice->rx_stream->key, test_transport_bob->tx_stream->key));
        SHOULD_BE_TRUE(wickr_stream_key_is_equal(test_transport_alice->tx_stream->key, test_transport_bob->rx_stream->key));
        SHOULD_EQUAL(test_transport_bob->evo_count, test_transport_alice->tx_stream->key->packets_per_evolution);
        SHOULD_EQUAL(test_transport_bob->evo_count, test_transport_bob->rx_stream->key->packets_per_evolution);
        SHOULD_EQUAL(test_transport_bob->evo_count, test_transport_bob->tx_stream->key->packets_per_evolution);
        SHOULD_EQUAL(test_transport_bob->evo_count, test_transport_alice->rx_stream->key->packets_per_evolution);
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_alice);
        wickr_transport_ctx_destroy(&test_transport_bob);
    }
    END_IT
    
    reset_callback_data();
    
    /* For additional handshake testing see test_transport_handshake.c */
    
    IT("can be copied")
    {
        wickr_identity_chain_t *alice_identity = createIdentityChain("alice");
        wickr_identity_chain_t *bob_identity = createIdentityChain("bob");
        
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 alice_identity,
                                                                                 bob_identity, 42,
                                                                                 alice_callbacks, NULL);
        
        wickr_transport_ctx_t *test_transport_bob = wickr_transport_ctx_create(test_engine,
                                                                               wickr_identity_chain_copy(bob_identity),
                                                                               wickr_identity_chain_copy(alice_identity),
                                                                               43, bob_callbacks, NULL);
        
        /* Start the alice transport */
        wickr_transport_ctx_start(test_transport_alice);
        wickr_transport_ctx_process_rx_buffer(test_transport_bob, alice_last_tx);
        wickr_transport_ctx_process_rx_buffer(test_transport_alice, bob_last_tx);
        
        /* Make a copy */
        wickr_transport_ctx_t *copy = wickr_transport_ctx_copy(test_transport_alice);
        SHOULD_NOT_BE_NULL(copy);
        
        SHOULD_EQUAL(memcmp(&copy->callbacks, &test_transport_alice->callbacks, sizeof(wickr_transport_callbacks_t)), 0);
        SHOULD_EQUAL(memcmp(&copy->engine, &test_transport_alice->engine, sizeof(wickr_crypto_engine_t)), 0);
        SHOULD_EQUAL(copy->evo_count, test_transport_alice->evo_count);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->local_identity->node->identifier,
                                             test_transport_alice->local_identity->node->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->remote_identity->root->identifier,
                                             test_transport_alice->remote_identity->root->identifier, NULL));
        SHOULD_BE_TRUE(wickr_stream_key_is_equal(copy->rx_stream->key, test_transport_alice->rx_stream->key));
        SHOULD_BE_TRUE(wickr_stream_key_is_equal(copy->tx_stream->key, test_transport_alice->tx_stream->key));
        SHOULD_EQUAL(copy->evo_count, test_transport_alice->evo_count);
        SHOULD_EQUAL(copy->status, test_transport_alice->status);
        SHOULD_EQUAL(copy->user, test_transport_alice->user);
        
        wickr_transport_ctx_destroy(&copy);
    }
    END_IT
    
    reset_callback_data();
    
    IT("will shut down if needed and forward handshake errors")
    {
        wickr_identity_chain_t *alice_identity = createIdentityChain("alice");
        wickr_identity_chain_t *bob_identity = createIdentityChain("bob");
        
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 alice_identity,
                                                                                 bob_identity, 42,
                                                                                 alice_callbacks, NULL);
        
        wickr_transport_ctx_t *test_transport_bob = wickr_transport_ctx_create(test_engine,
                                                                               wickr_identity_chain_copy(bob_identity),
                                                                               wickr_identity_chain_copy(alice_identity),
                                                                               43, bob_callbacks, NULL);
        
        /* Start the handshake */
        wickr_transport_ctx_start(test_transport_alice);
        
        /* Decode and corrupt the handshake data */
        wickr_transport_packet_t *pkt = wickr_transport_packet_create_from_buffer(alice_last_tx);
        wickr_buffer_destroy(&pkt->mac);
        wickr_buffer_t *corrupt_packet = wickr_transport_packet_serialize(pkt);
        wickr_transport_packet_destroy(&pkt);
        
        wickr_transport_ctx_process_rx_buffer(test_transport_bob, corrupt_packet);
        wickr_buffer_destroy(&corrupt_packet);
        
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_bob), TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(bob_last_status, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(bob_last_error, TRANSPORT_ERROR_PROCESS_HANDSHAKE_FAILED);
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_alice);
        wickr_transport_ctx_destroy(&test_transport_bob);
    }
    END_IT
    
    reset_callback_data();
    
    IT("will call identity callbacks if required by the handshake")
    {
        wickr_identity_chain_t *alice_identity = createIdentityChain("alice");
        wickr_identity_chain_t *bob_identity = createIdentityChain("bob");
        
        /* Create transports that don't have remotes set to force identity callbacks */
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 alice_identity,
                                                                                 NULL, 42,
                                                                                 alice_callbacks, NULL);
        
        wickr_transport_ctx_t *test_transport_bob = wickr_transport_ctx_create(test_engine,
                                                                               wickr_identity_chain_copy(bob_identity),
                                                                               NULL,
                                                                               43, bob_callbacks, NULL);
        
        wickr_transport_ctx_start(test_transport_alice);
        wickr_transport_ctx_process_rx_buffer(test_transport_bob, alice_last_tx);
        
        /* Verify the identity callback for bob was fired */
        SHOULD_NOT_BE_NULL(bob_last_identity);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_last_identity->root->identifier,
                                             alice_identity->root->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_last_identity->root->sig_key->pub_data,
                                             alice_identity->root->sig_key->pub_data, NULL));
        
        wickr_transport_ctx_process_rx_buffer(test_transport_alice, bob_last_tx);
        
        /* Verify the identity callback for alice was fired */
        SHOULD_NOT_BE_NULL(alice_last_identity);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_last_identity->root->identifier,
                                             bob_identity->root->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_last_identity->root->sig_key->pub_data,
                                             bob_identity->root->sig_key->pub_data, NULL));
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_alice);
        wickr_transport_ctx_destroy(&test_transport_bob);
    }
    END_IT
    
    reset_callback_data();
    
    IT("will be marked as failed if the identity callback says the identity is invalid (bob)")
    {
        wickr_identity_chain_t *alice_identity = createIdentityChain("alice");
        wickr_identity_chain_t *bob_identity = createIdentityChain("bob");
        
        wickr_transport_callbacks_t identity_fail_callback = bob_callbacks;
        identity_fail_callback.on_identity_verify = wickr_transport_bob_validate_identity_fail_func;
        
        /* Create transports that don't have remotes set to force identity callbacks */
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 alice_identity,
                                                                                 NULL, 42,
                                                                                 alice_callbacks, NULL);
        
        wickr_transport_ctx_t *test_transport_bob = wickr_transport_ctx_create(test_engine,
                                                                               wickr_identity_chain_copy(bob_identity),
                                                                               NULL,
                                                                               43, identity_fail_callback, NULL);
        
        wickr_transport_ctx_start(test_transport_alice);
        wickr_transport_ctx_process_rx_buffer(test_transport_bob, alice_last_tx);
        
        /* Verity the failed callback has terminated bob's transport */
        SHOULD_EQUAL(bob_last_status, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_bob), TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(bob_last_error, TRANSPORT_ERROR_HANDSHAKE_FAILED);
        SHOULD_BE_NULL(bob_last_tx);
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_alice);
        wickr_transport_ctx_destroy(&test_transport_bob);
    }
    END_IT
    
    reset_callback_data();
    
    IT("will be marked as failed if the identity callback says the identity is invalid (alice)")
    {
        wickr_identity_chain_t *alice_identity = createIdentityChain("alice");
        wickr_identity_chain_t *bob_identity = createIdentityChain("bob");
        
        wickr_transport_callbacks_t identity_fail_callback = alice_callbacks;
        identity_fail_callback.on_identity_verify = wickr_transport_alice_validate_identity_fail_func;
        
        /* Create transports that don't have remotes set to force identity callbacks */
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 alice_identity,
                                                                                 NULL, 42,
                                                                                 identity_fail_callback, NULL);
        
        wickr_transport_ctx_t *test_transport_bob = wickr_transport_ctx_create(test_engine,
                                                                               wickr_identity_chain_copy(bob_identity),
                                                                               NULL,
                                                                               43, bob_callbacks, NULL);
        
        wickr_transport_ctx_start(test_transport_alice);
        wickr_transport_ctx_process_rx_buffer(test_transport_bob, alice_last_tx);
        wickr_transport_ctx_process_rx_buffer(test_transport_alice, bob_last_tx);
        
        /* Verity the failed callback has terminated alice's transport */
        SHOULD_EQUAL(alice_last_status, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_alice), TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(alice_last_error, TRANSPORT_ERROR_HANDSHAKE_FAILED);
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_alice);
        wickr_transport_ctx_destroy(&test_transport_bob);
    }
    END_IT
    
    reset_callback_data();
    
    IT("will not allow tx packets to process before the handshake")
    {
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 createIdentityChain("alice"),
                                                                                 createIdentityChain("bob"), 42,
                                                                                 alice_callbacks, NULL);
        
        wickr_buffer_t *random_buffer = test_engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(test_transport_alice, random_buffer);
        wickr_buffer_destroy(&random_buffer);
        
        SHOULD_EQUAL(alice_last_status, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_alice), TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(alice_last_error, TRANSPORT_ERROR_BAD_TX_STATE);
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_alice);
    }
    END_IT
    
    reset_callback_data();
    
    IT("will not allow tx packets to process during the handshake")
    {
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 createIdentityChain("alice"),
                                                                                 createIdentityChain("bob"), 42,
                                                                                 alice_callbacks, NULL);
        /* Start the transport */
        wickr_transport_ctx_start(test_transport_alice);
        
        wickr_buffer_t *random_buffer = test_engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(test_transport_alice, random_buffer);
        wickr_buffer_destroy(&random_buffer);
        
        SHOULD_EQUAL(alice_last_status, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_alice), TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(alice_last_error, TRANSPORT_ERROR_BAD_TX_STATE);
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_alice);
    }
    END_IT
    
    reset_callback_data();
    
    IT("will not allow another handshake packet once the channel is established")
    {
        wickr_identity_chain_t *alice_identity = createIdentityChain("alice");
        wickr_identity_chain_t *bob_identity = createIdentityChain("bob");
        
        /* Create transports */
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 alice_identity,
                                                                                 bob_identity, 42,
                                                                                 alice_callbacks, NULL);
        
        wickr_transport_ctx_t *test_transport_bob = wickr_transport_ctx_create(test_engine,
                                                                               wickr_identity_chain_copy(bob_identity),
                                                                               wickr_identity_chain_copy(alice_identity),
                                                                               43, bob_callbacks, NULL);
        
        wickr_transport_ctx_start(test_transport_alice);
        wickr_transport_ctx_process_rx_buffer(test_transport_bob, alice_last_tx);
        wickr_transport_ctx_process_rx_buffer(test_transport_alice, bob_last_tx);
        
        /* Create a handshake packet */
        wickr_transport_handshake_t *new_handshake = wickr_transport_handshake_create(test_engine,
                                                                                      wickr_identity_chain_copy(alice_identity),
                                                                                      wickr_identity_chain_copy(bob_identity), 1, 42, NULL);
        
        wickr_transport_packet_t *packet = wickr_transport_handshake_start(new_handshake);
        wickr_buffer_t *serialized_packet = wickr_transport_packet_serialize(packet);
        wickr_transport_packet_destroy(&packet);
        wickr_transport_handshake_destroy(&new_handshake);
        SHOULD_NOT_BE_NULL(serialized_packet);
        
        wickr_transport_ctx_process_rx_buffer(test_transport_bob, serialized_packet);
        wickr_buffer_destroy(&serialized_packet);
        
        SHOULD_EQUAL(bob_last_status, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_bob), bob_last_status);
        SHOULD_EQUAL(bob_last_error, TRANSPORT_ERROR_PACKET_DECODE_FAILED);
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_alice);
        wickr_transport_ctx_destroy(&test_transport_bob);
    }
    END_IT
    
    reset_callback_data();
    
    IT("can transfer data over the established channel and ratchet keys appropriatly")
    {
        wickr_identity_chain_t *alice_identity = createIdentityChain("alice");
        wickr_identity_chain_t *bob_identity = createIdentityChain("bob");
        
        /* Create transports */
        wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                                 alice_identity,
                                                                                 bob_identity, 16,
                                                                                 alice_callbacks, NULL);
        
        wickr_transport_ctx_t *test_transport_bob = wickr_transport_ctx_create(test_engine,
                                                                               wickr_identity_chain_copy(bob_identity),
                                                                               wickr_identity_chain_copy(alice_identity),
                                                                               16, bob_callbacks, NULL);
        
        /* Establish the connection */
        wickr_transport_ctx_start(test_transport_alice);
        wickr_transport_ctx_process_rx_buffer(test_transport_bob, alice_last_tx);
        wickr_transport_ctx_process_rx_buffer(test_transport_alice, bob_last_tx);
        
        reset_callback_data();
        
        wickr_stream_key_t *alice_first_rx = wickr_stream_key_copy(test_transport_alice->rx_stream->key);
        wickr_stream_key_t *alice_first_tx = wickr_stream_key_copy(test_transport_alice->tx_stream->key);
        
        wickr_stream_key_t *bob_first_rx = wickr_stream_key_copy(test_transport_bob->rx_stream->key);
        wickr_stream_key_t *bob_first_tx = wickr_stream_key_copy(test_transport_bob->tx_stream->key);
        
        /* Send enough packets to verify a ratchet */
        for (int i = 0; i < 17; i++) {
            
            /* Transmit a packet from alice to bob */
            wickr_buffer_t *alice_data = test_engine.wickr_crypto_engine_crypto_random(32);
            wickr_transport_ctx_process_tx_buffer(test_transport_alice, alice_data);

            /* Verify the data was encrypted and there are no errors */
            SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_alice), TRANSPORT_STATUS_ACTIVE);
            SHOULD_NOT_BE_NULL(alice_last_tx);
            SHOULD_BE_FALSE(wickr_buffer_is_equal(alice_data, alice_last_tx, NULL));
            SHOULD_BE_TRUE(alice_data->length < alice_last_tx->length);
            
            /* Verify the data can be decrypted properly and there are no errors */
            wickr_transport_ctx_process_rx_buffer(test_transport_bob, alice_last_tx);
            SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_bob), TRANSPORT_STATUS_ACTIVE);
            SHOULD_NOT_BE_NULL(bob_last_rx);
            SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_last_rx, alice_data, NULL));
            
            /* Transmit a packet from bob to alice */
            wickr_buffer_t *bob_data = test_engine.wickr_crypto_engine_crypto_random(32);
            wickr_transport_ctx_process_tx_buffer(test_transport_bob, bob_data);
            
            /* Verify the data was encrypted and there are no errors */
            SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_bob), TRANSPORT_STATUS_ACTIVE);
            SHOULD_NOT_BE_NULL(bob_last_tx);
            SHOULD_BE_FALSE(wickr_buffer_is_equal(alice_data, bob_last_tx, NULL));
            SHOULD_BE_TRUE(bob_data->length < bob_last_tx->length);
            
            /* Verify the data can be decrypted properly and there are no errors */
            wickr_transport_ctx_process_rx_buffer(test_transport_alice, bob_last_tx);
            SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_alice), TRANSPORT_STATUS_ACTIVE);
            SHOULD_NOT_BE_NULL(alice_last_rx);
            SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_last_rx, bob_data, NULL));
            
            if (i < 15) {
                /* Verify that the key hasn't ratcheted */
                SHOULD_BE_TRUE(wickr_stream_key_is_equal(alice_first_rx, test_transport_alice->rx_stream->key));
                SHOULD_BE_TRUE(wickr_stream_key_is_equal(alice_first_tx, test_transport_alice->tx_stream->key));
                SHOULD_BE_TRUE(wickr_stream_key_is_equal(bob_first_rx, test_transport_bob->rx_stream->key));
                SHOULD_BE_TRUE(wickr_stream_key_is_equal(bob_first_tx, test_transport_bob->tx_stream->key));
            } else {
                /* The key should have ratcheted */
                SHOULD_BE_FALSE(wickr_stream_key_is_equal(alice_first_rx, test_transport_alice->rx_stream->key));
                SHOULD_BE_FALSE(wickr_stream_key_is_equal(alice_first_tx, test_transport_alice->tx_stream->key));
                SHOULD_BE_FALSE(wickr_stream_key_is_equal(bob_first_rx, test_transport_bob->rx_stream->key));
                SHOULD_BE_FALSE(wickr_stream_key_is_equal(bob_first_tx, test_transport_bob->tx_stream->key));
                
                SHOULD_BE_TRUE(wickr_stream_key_is_equal(test_transport_alice->rx_stream->key,
                                                         test_transport_bob->tx_stream->key));
                SHOULD_BE_TRUE(wickr_stream_key_is_equal(test_transport_alice->tx_stream->key,
                                                         test_transport_bob->rx_stream->key));
            }
            
            wickr_buffer_destroy(&bob_data);
            wickr_buffer_destroy(&alice_data);
            reset_callback_data();
        }
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_alice);
        wickr_transport_ctx_destroy(&test_transport_bob);
        wickr_stream_key_destroy(&alice_first_rx);
        wickr_stream_key_destroy(&alice_first_tx);
        wickr_stream_key_destroy(&bob_first_rx);
        wickr_stream_key_destroy(&bob_first_tx);
    }
    END_IT
    
    reset_callback_data();
    
    /* These transports used for the next 2 tests */
    wickr_identity_chain_t *alice_identity = createIdentityChain("alice");
    wickr_identity_chain_t *bob_identity = createIdentityChain("bob");
    
    /* Create transports */
    wickr_transport_ctx_t *test_transport_alice = wickr_transport_ctx_create(test_engine,
                                                                             alice_identity,
                                                                             bob_identity, 16,
                                                                             alice_callbacks, NULL);
    
    wickr_transport_ctx_t *test_transport_bob = wickr_transport_ctx_create(test_engine,
                                                                           wickr_identity_chain_copy(bob_identity),
                                                                           wickr_identity_chain_copy(alice_identity),
                                                                           16, bob_callbacks, NULL);
    
    IT("can handle corrupt data by moving to the error state")
    {
        /* Establish the connection */
        wickr_transport_ctx_start(test_transport_alice);
        wickr_transport_ctx_process_rx_buffer(test_transport_bob, alice_last_tx);
        wickr_transport_ctx_process_rx_buffer(test_transport_alice, bob_last_tx);
        
        /* Create a bad packet */
        wickr_transport_packet_meta_t meta;
        wickr_transport_packet_meta_initialize_data(&meta, 1, TRANSPORT_MAC_TYPE_AUTH_CIPHER);
        wickr_buffer_t *plaintext_body = test_engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_packet_t *packet = wickr_transport_packet_create(meta, plaintext_body);
        wickr_buffer_t *packet_buffer = wickr_transport_packet_serialize(packet);
        wickr_transport_packet_destroy(&packet);
        
        /* Send the bad packet */
        wickr_transport_ctx_process_rx_buffer(test_transport_bob, packet_buffer);
        wickr_transport_packet_destroy(&packet);
        
        SHOULD_BE_NULL(bob_last_rx);
        SHOULD_EQUAL(wickr_transport_ctx_get_status(test_transport_bob), TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(bob_last_status, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(bob_last_error, TRANSPORT_ERROR_PACKET_DECODE_FAILED);
    }
    END_IT
    
    reset_callback_data();
    
    IT("will not allow further actions once it is in the error state")
    {
        wickr_buffer_t *random_buffer = test_engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(test_transport_bob, random_buffer);
        wickr_buffer_destroy(&random_buffer);
        
        SHOULD_BE_NULL(bob_last_tx);
        
        /* Cleanup */
        wickr_transport_ctx_destroy(&test_transport_alice);
        wickr_transport_ctx_destroy(&test_transport_bob);
    }
    END_IT
    
    reset_callback_data();
    
    IT("can be destroyed")
    {
        wickr_transport_ctx_t *test_transport = wickr_transport_ctx_create(test_engine,
                                                                           createIdentityChain("local"),
                                                                           NULL, 42,
                                                                           alice_callbacks, NULL);
        
        SHOULD_NOT_BE_NULL(test_transport);
        
        wickr_transport_ctx_destroy(&test_transport);
        SHOULD_BE_NULL(test_transport);
    }
    END_IT
}
END_DESCRIBE
