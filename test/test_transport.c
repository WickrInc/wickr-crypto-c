
#include "test_transport.h"
#include "transport_ctx.h"
#include "private/transport_priv.h"
#include "stream_ctx.h"
#include "externs.h"
#include <string.h>

/* Test Transports */
wickr_transport_ctx_t *alice_transport = NULL;
wickr_transport_ctx_t *bob_transport = NULL;

/* Static helper variables */

/* Alice */
const char *test_alice_user_data = "ALICE";
static wickr_buffer_t *last_tx_alice = NULL;
static wickr_buffer_t *last_rx_alice = NULL;
static wickr_transport_status last_status_alice = TRANSPORT_STATUS_NONE;
static wickr_identity_chain_t *verified_identity_alice = NULL;
static wickr_buffer_t *alice_psk = NULL;
static wickr_buffer_t *alice_user_data = NULL;
static wickr_stream_ctx_t *alice_existing_ctx = NULL;

/* Bob */
const char *test_bob_user_data = "BOB";
static wickr_buffer_t *last_tx_bob = NULL;
static wickr_buffer_t *last_rx_bob = NULL;
static wickr_transport_status last_status_bob = TRANSPORT_STATUS_NONE;
static wickr_identity_chain_t *verified_identity_bob = NULL;
static wickr_buffer_t *bob_user_data = NULL;
static wickr_stream_ctx_t *bob_existing_ctx = NULL;
static wickr_buffer_t *bob_psk = NULL;

/* Test Callbacks for Alice */
void wickr_test_transport_tx_alice(const wickr_transport_ctx_t *ctx,
                                   const wickr_buffer_t *data,
                                   wickr_transport_payload_type payload_type,
                                   void *user)
{
    wickr_buffer_destroy(&last_tx_alice);
    last_tx_alice = (wickr_buffer_t *)data;
    
    SHOULD_EQUAL(test_alice_user_data, (const char *)user);
    SHOULD_EQUAL(wickr_transport_ctx_get_user_ctx(ctx), user);
    
    wickr_buffer_t *decode = wickr_transport_ctx_process_rx_buffer(bob_transport, data);
    
    if (payload_type == TRANSPORT_PAYLOAD_TYPE_HANDSHAKE) {
        SHOULD_BE_NULL(decode);
    }
    else {
        SHOULD_EQUAL(decode, last_rx_bob);
    }

}

void wickr_test_transport_tx_alice_no_send(const wickr_transport_ctx_t *ctx,
                                           const wickr_buffer_t *data,
                                           wickr_transport_payload_type payload_type,
                                           void *user)
{
    wickr_buffer_destroy(&last_tx_alice);
    last_tx_alice = (wickr_buffer_t *)data;
    
    SHOULD_EQUAL(test_alice_user_data, (const char *)user);
    SHOULD_EQUAL(wickr_transport_ctx_get_user_ctx(ctx), user);
}

void wickr_test_transport_rx_alice(const wickr_transport_ctx_t *ctx, const wickr_buffer_t *data, void *user)
{
    wickr_buffer_destroy(&last_rx_alice);
    last_rx_alice = (wickr_buffer_t *)data;
    
    SHOULD_EQUAL(test_alice_user_data, (const char *)user);
    SHOULD_EQUAL(wickr_transport_ctx_get_user_ctx(ctx), user);
}

void wickr_test_transport_status_alice(const wickr_transport_ctx_t *ctx, wickr_transport_status status, void *user)
{
    last_status_alice = status;
    
    SHOULD_EQUAL(wickr_transport_ctx_get_status(ctx), status);
    SHOULD_EQUAL(test_alice_user_data, (const char *)user);
    SHOULD_EQUAL(wickr_transport_ctx_get_user_ctx(ctx), user);
}

bool wickr_test_transport_verify_remote_alice(const wickr_transport_ctx_t *ctx, wickr_identity_chain_t *identity, void *user)
{
    wickr_identity_chain_destroy(&verified_identity_alice);
    
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    if (wickr_identity_chain_validate(identity, &engine)) {
        verified_identity_alice = wickr_identity_chain_copy(identity);
        return true;
    }
    
    return false;
}

/* Test callbacks for Bob */
void wickr_test_transport_tx_bob(const wickr_transport_ctx_t *ctx,
                                 const wickr_buffer_t *data,
                                 wickr_transport_payload_type payload_type,
                                 void *user)
{
    wickr_buffer_destroy(&last_tx_bob);
    last_tx_bob = (wickr_buffer_t *)data;
    
    wickr_transport_ctx_process_rx_buffer(alice_transport, data);
    
    SHOULD_EQUAL(test_bob_user_data, (const char *)user);
    SHOULD_EQUAL(wickr_transport_ctx_get_user_ctx(ctx), user);
}

void wickr_test_transport_tx_bob_no_send(const wickr_transport_ctx_t *ctx,
                                         const wickr_buffer_t *data,
                                         wickr_transport_payload_type payload_type,
                                         void *user)
{
    wickr_buffer_destroy(&last_tx_bob);
    last_tx_bob = (wickr_buffer_t *)data;
    
    SHOULD_EQUAL(test_bob_user_data, (const char *)user);
    SHOULD_EQUAL(wickr_transport_ctx_get_user_ctx(ctx), user);
}

void wickr_test_transport_rx_bob(const wickr_transport_ctx_t *ctx, const wickr_buffer_t *data, void *user)
{
    wickr_buffer_destroy(&last_rx_bob);
    last_rx_bob = (wickr_buffer_t *)data;
    
    SHOULD_EQUAL(test_bob_user_data, (const char *)user);
    SHOULD_EQUAL(wickr_transport_ctx_get_user_ctx(ctx), user);
}

void wickr_test_transport_status_bob(const wickr_transport_ctx_t *ctx, wickr_transport_status status, void *user)
{
    last_status_bob = status;
    SHOULD_EQUAL(wickr_transport_ctx_get_status(ctx), status);
    SHOULD_EQUAL(test_bob_user_data, (const char *)user);
    SHOULD_EQUAL(wickr_transport_ctx_get_user_ctx(ctx), user);
}

bool wickr_test_transport_verify_remote_bob(const wickr_transport_ctx_t *ctx, wickr_identity_chain_t *identity, void *user)
{
    wickr_identity_chain_destroy(&verified_identity_bob);
    
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    if (wickr_identity_chain_validate(identity, &engine)) {
        verified_identity_bob = wickr_identity_chain_copy(identity);
        return true;
    }
    
    return false;
}

bool wickr_test_transport_verify_remote_failure(const wickr_transport_ctx_t *ctx, wickr_identity_chain_t *identity, void *users)
{
    return false;
}

wickr_buffer_t *wickr_test_transport_bob_psk(const wickr_transport_ctx_t *ctx, void *user)
{
    return bob_psk;
}

wickr_buffer_t *wickr_test_transport_alice_psk(const wickr_transport_ctx_t *ctx, void *user)
{
    return alice_psk;
}

wickr_stream_ctx_t *wickr_test_transport_alice_user_data_injection(const wickr_transport_ctx_t *ctx, wickr_stream_ctx_t *s_ctx, void *user)
{
    s_ctx->key->user_data = wickr_buffer_copy(alice_user_data);
    return s_ctx;
}

wickr_stream_ctx_t *wickr_test_transport_bob_user_data_injection(const wickr_transport_ctx_t *ctx, wickr_stream_ctx_t *s_ctx, void *user)
{
    s_ctx->key->user_data = wickr_buffer_copy(bob_user_data);
    return s_ctx;
}

wickr_stream_ctx_t *wickr_test_transport_bob_custom_tx_stream(const wickr_transport_ctx_t *ctx, wickr_stream_ctx_t *s_ctx, void *user)
{
    wickr_stream_key_t *key = wickr_stream_key_create_rand(ctx->engine, CIPHER_AES256_GCM, PACKET_PER_EVO_DEFAULT);
    bob_existing_ctx = wickr_stream_ctx_create(ctx->engine, key, STREAM_DIRECTION_ENCODE);
    return bob_existing_ctx;
}

wickr_stream_ctx_t *wickr_test_transport_alice_custom_tx_stream(const wickr_transport_ctx_t *ctx, wickr_stream_ctx_t *s_ctx, void *user)
{
    wickr_stream_key_t *key = wickr_stream_key_create_rand(ctx->engine, CIPHER_AES256_GCM, PACKET_PER_EVO_DEFAULT);
    alice_existing_ctx = wickr_stream_ctx_create(ctx->engine, key, STREAM_DIRECTION_ENCODE);
    return alice_existing_ctx;
}

static wickr_transport_callbacks_t test_callbacks_alice = { wickr_test_transport_tx_alice,
    wickr_test_transport_rx_alice,
    wickr_test_transport_status_alice,
    wickr_test_transport_verify_remote_alice,
    NULL,
    NULL
};


static wickr_transport_callbacks_t test_callbacks_bob = { wickr_test_transport_tx_bob,
    wickr_test_transport_rx_bob,
    wickr_test_transport_status_bob,
    wickr_test_transport_verify_remote_bob,
    NULL,
    NULL
};

void test_packet_send(wickr_transport_ctx_t *sender_ctx, wickr_buffer_t **last_packet, wickr_buffer_t **expected, int pkt_number)
{
    wickr_buffer_t *test_buffer = engine.wickr_crypto_engine_crypto_random(32);
    wickr_buffer_t *tx_result = wickr_transport_ctx_process_tx_buffer(sender_ctx, test_buffer);
    SHOULD_EQUAL(tx_result, *last_packet);
    
    /* The tx callback for alice will produce the encrypted packets */
    SHOULD_BE_FALSE(wickr_buffer_is_equal(test_buffer, *last_packet, NULL));
    SHOULD_BE_TRUE((*last_packet)->length > test_buffer->length);
    
    uint64_t *bytes = (uint64_t *)(*last_packet)->bytes;
    SHOULD_EQUAL(bytes[0], pkt_number);
    
    SHOULD_EQUAL(((*last_packet)->bytes[sizeof(uint64_t)] & 0xF0) >> 4, TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT);
    SHOULD_EQUAL(((*last_packet)->bytes[sizeof(uint64_t)] & 0xF), TRANSPORT_MAC_TYPE_AUTH_CIPHER);

    
    wickr_buffer_t temp_buffer;
    temp_buffer.bytes = (*last_packet)->bytes[sizeof(uint64_t) + 1];
    temp_buffer.length = (*last_packet)->length - sizeof(uint64_t) - 1;
    
    SHOULD_BE_FALSE(wickr_buffer_is_equal(test_buffer, &temp_buffer, NULL));
    
    /* The rx callback for bob will produce the original buffer after decryption */
    SHOULD_BE_TRUE(wickr_buffer_is_equal(test_buffer, *expected, NULL));
    SHOULD_NOT_EQUAL(test_buffer, *expected);
    
    wickr_buffer_destroy(&test_buffer);
}

void reset_alice_bob()
{
    const wickr_crypto_engine_t default_engine = wickr_crypto_engine_get_default();

    wickr_node_t *alice_node_1 = createUserNode("alice", hex_char_to_buffer("alice_device"));
    wickr_node_t *bob_node_1 = createUserNode("bob", hex_char_to_buffer("bob_device"));
    wickr_node_t *alice_node_2 = wickr_node_copy(alice_node_1);
    wickr_node_t *bob_node_2 = wickr_node_copy(bob_node_1);
    
    SHOULD_NOT_BE_NULL(alice_node_1);
    SHOULD_NOT_BE_NULL(bob_node_1);
    SHOULD_NOT_BE_NULL(alice_node_2);
    SHOULD_NOT_BE_NULL(bob_node_2);
    
    wickr_transport_ctx_destroy(&alice_transport);
    wickr_transport_ctx_destroy(&bob_transport);
    
    SHOULD_BE_TRUE(alice_transport = wickr_transport_ctx_create(default_engine, alice_node_1, bob_node_1, 0, test_callbacks_alice, (void *)test_alice_user_data));
    SHOULD_BE_TRUE(bob_transport = wickr_transport_ctx_create(default_engine, bob_node_2, alice_node_2, 0, test_callbacks_bob, (void *)test_bob_user_data));
    
    last_status_bob = TRANSPORT_STATUS_NONE;
    last_status_alice = TRANSPORT_STATUS_NONE;
    wickr_buffer_destroy_zero(&last_tx_alice);
    wickr_buffer_destroy_zero(&last_tx_bob);
    wickr_buffer_destroy_zero(&last_rx_alice);
    wickr_buffer_destroy_zero(&last_rx_bob);
    wickr_buffer_destroy(&bob_psk);
    wickr_buffer_destroy(&alice_psk);
    wickr_buffer_destroy(&bob_user_data);
    wickr_buffer_destroy(&alice_user_data);
    wickr_stream_ctx_destroy(&bob_existing_ctx);
    wickr_stream_ctx_destroy(&alice_existing_ctx);
}

void verify_established_connection()
{
    /* No packets are provided to the callback during the handshake as they are internal */
    SHOULD_BE_NULL(last_rx_bob);
    SHOULD_BE_NULL(last_rx_alice);
    
    /* Check that handshake packets were sent properly */
    SHOULD_NOT_BE_NULL(last_tx_alice);
    SHOULD_NOT_BE_NULL(last_tx_bob);
    
    SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
    SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ACTIVE);
    
    SHOULD_NOT_BE_NULL(alice_transport->rx_stream);
    SHOULD_NOT_BE_NULL(alice_transport->tx_stream);
    SHOULD_NOT_BE_NULL(bob_transport->rx_stream);
    SHOULD_NOT_BE_NULL(bob_transport->tx_stream);
    
    SHOULD_EQUAL(alice_transport->rx_stream->direction, STREAM_DIRECTION_DECODE);
    SHOULD_EQUAL(bob_transport->rx_stream->direction, STREAM_DIRECTION_DECODE);
    SHOULD_EQUAL(alice_transport->tx_stream->direction, STREAM_DIRECTION_ENCODE);
    SHOULD_EQUAL(bob_transport->tx_stream->direction, STREAM_DIRECTION_ENCODE);
    
    /* Determine that the rx stream key material for Alice matches the tx stream key material for Bob */
    SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_transport->rx_stream->key->cipher_key->key_data, bob_transport->tx_stream->key->cipher_key->key_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_transport->rx_stream->key->evolution_key, bob_transport->tx_stream->key->evolution_key, NULL));
    SHOULD_EQUAL(alice_transport->rx_stream->key->packets_per_evolution, bob_transport->tx_stream->key->packets_per_evolution);
    
    /* Determine that the rx stream key material for Alice is different than the rx stream key material for Bob */
    SHOULD_BE_FALSE(wickr_buffer_is_equal(alice_transport->rx_stream->key->cipher_key->key_data, bob_transport->rx_stream->key->cipher_key->key_data, NULL));
    SHOULD_BE_FALSE(wickr_buffer_is_equal(alice_transport->rx_stream->key->evolution_key, bob_transport->rx_stream->key->evolution_key, NULL));
    
    /* Determine that the rx stream for Bob matches the tx stream for Alice */
    SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_transport->tx_stream->key->cipher_key->key_data, bob_transport->rx_stream->key->cipher_key->key_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_transport->tx_stream->key->evolution_key, bob_transport->rx_stream->key->evolution_key, NULL));
    SHOULD_EQUAL(alice_transport->tx_stream->key->packets_per_evolution, bob_transport->rx_stream->key->packets_per_evolution);
    
    /* Determine that the tx stream key material for Alice is different than the tx stream key material for Bob */
    SHOULD_BE_FALSE(wickr_buffer_is_equal(alice_transport->tx_stream->key->cipher_key->key_data, bob_transport->tx_stream->key->cipher_key->key_data, NULL));
    SHOULD_BE_FALSE(wickr_buffer_is_equal(alice_transport->tx_stream->key->evolution_key, bob_transport->tx_stream->key->evolution_key, NULL));
}

DESCRIBE(wickr_transport_ctx, "wickr_transport_ctx")
{
    const wickr_crypto_engine_t default_engine = wickr_crypto_engine_get_default();
    
    wickr_node_t *alice_node_1 = createUserNode("alice", hex_char_to_buffer("alice_device"));
    wickr_node_t *bob_node_1 = createUserNode("bob", hex_char_to_buffer("bob_device"));
    wickr_node_t *alice_node_2 = wickr_node_copy(alice_node_1);
    wickr_node_t *bob_node_2 = wickr_node_copy(bob_node_1);
    
    SHOULD_NOT_BE_NULL(alice_node_1);
    SHOULD_NOT_BE_NULL(bob_node_1);
    SHOULD_NOT_BE_NULL(alice_node_2);
    SHOULD_NOT_BE_NULL(bob_node_2);
    
    IT("can be initialized for both parties")
    {
        
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, NULL, NULL,0, test_callbacks_alice, NULL));
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, NULL, alice_node_1, 0, test_callbacks_alice, NULL));
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, alice_node_1, bob_node_1, PACKET_PER_EVO_MIN - 1, test_callbacks_alice, NULL));
        SHOULD_BE_NULL(wickr_transport_ctx_create(default_engine, alice_node_1, bob_node_1, PACKET_PER_EVO_MAX + 1, test_callbacks_alice, NULL));

        SHOULD_BE_TRUE(alice_transport = wickr_transport_ctx_create(default_engine, alice_node_1, bob_node_1, 0, test_callbacks_alice, (void *)test_alice_user_data));
        SHOULD_BE_TRUE(bob_transport = wickr_transport_ctx_create(default_engine, bob_node_2, alice_node_2, 0, test_callbacks_bob, (void *)test_bob_user_data));
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_NONE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_NONE);
        SHOULD_BE_NULL(last_rx_alice);
        SHOULD_BE_NULL(last_rx_bob);
        SHOULD_BE_NULL(last_tx_alice);
        SHOULD_BE_NULL(last_tx_bob);
        
        SHOULD_BE_NULL(alice_transport->rx_stream);
        SHOULD_BE_NULL(alice_transport->tx_stream);
        
        SHOULD_BE_NULL(bob_transport->tx_stream);
        SHOULD_BE_NULL(bob_transport->rx_stream);
        
        SHOULD_EQUAL(alice_transport->evo_count, PACKET_PER_EVO_DEFAULT);
        SHOULD_EQUAL(bob_transport->evo_count, PACKET_PER_EVO_DEFAULT);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_transport->local_identity->id_chain->node->sig_key->pub_data, alice_node_1->id_chain->node->sig_key->pub_data, NULL));
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->local_identity->id_chain->node->sig_key->pub_data, bob_node_1->id_chain->node->sig_key->pub_data, NULL));

    }
    END_IT
    
    IT("should have getters and setters to certain properties")
    {
        SHOULD_BE_NULL(wickr_transport_ctx_get_rxstream_user_data(NULL));
        SHOULD_BE_NULL(wickr_transport_ctx_get_remote_node_ptr(NULL));
        SHOULD_BE_NULL(wickr_transport_ctx_get_local_node_ptr(NULL));
        SHOULD_BE_NULL(wickr_transport_ctx_get_user_ctx(NULL));
        
        SHOULD_BE_NULL(wickr_transport_ctx_get_rxstream_user_data(alice_transport));
        SHOULD_EQUAL(wickr_transport_ctx_get_local_node_ptr(alice_transport), alice_node_1);
        SHOULD_EQUAL(wickr_transport_ctx_get_remote_node_ptr(alice_transport), bob_node_1);
        
        SHOULD_EQUAL(memcmp(wickr_transport_ctx_get_user_ctx(alice_transport),
                            test_alice_user_data, strlen(test_alice_user_data)), 0);
        
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(32);
        
        wickr_transport_ctx_set_user_ctx(alice_transport, test_data);
        SHOULD_EQUAL(wickr_transport_ctx_get_user_ctx(alice_transport), test_data);
        
        wickr_transport_ctx_set_user_ctx(alice_transport, NULL);
        
        wickr_buffer_destroy(&test_data);
        
        SHOULD_BE_NULL(wickr_transport_ctx_get_user_ctx(alice_transport));
    }
    END_IT
    
    IT("should be able to get and set callbacks after creations")
    {
        SHOULD_BE_NULL(wickr_transport_ctx_get_callbacks(NULL));
        const wickr_transport_callbacks_t *callbacks = wickr_transport_ctx_get_callbacks(alice_transport);
        SHOULD_EQUAL(callbacks, &alice_transport->callbacks);
        
        wickr_transport_callbacks_t another_callbacks = {1,2,3,4,5,6};
        wickr_transport_ctx_set_callbacks(alice_transport, &another_callbacks);
        SHOULD_EQUAL((wickr_transport_tx_func)1, alice_transport->callbacks.tx);
        SHOULD_EQUAL((wickr_transport_rx_func)2, alice_transport->callbacks.rx);
        SHOULD_EQUAL((wickr_transport_state_change_func)3, alice_transport->callbacks.on_state);
        SHOULD_EQUAL((wickr_transport_validate_identity_func)4, alice_transport->callbacks.on_identity_verify);
        SHOULD_EQUAL((wickr_transport_psk_func)5, alice_transport->callbacks.on_psk_required);
        SHOULD_EQUAL((wickr_transport_tx_stream_func)6, alice_transport->callbacks.on_tx_stream_gen);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("should not allow you to transmit packets if no handshake has happened")
    {
        wickr_buffer_t *rand_buffer = engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(alice_transport, rand_buffer);
        SHOULD_EQUAL(TRANSPORT_STATUS_ERROR, last_status_alice);
        wickr_buffer_destroy(&rand_buffer);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("will have a failed handshake if the incorrect signature keys are used for either party")
    {
        /* Case: Alice presents an invalid signature for herself */
        wickr_ec_key_destroy(&alice_transport->local_identity->id_chain->node->sig_key);
        alice_transport->local_identity->id_chain->node->sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_BE_NULL(last_tx_bob);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        
        reset_alice_bob();

        /* Case: Bob presents an invalid signature for his response to alice */
        wickr_ec_key_destroy(&bob_transport->local_identity->id_chain->node->sig_key);
        bob_transport->local_identity->id_chain->node->sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_NOT_BE_NULL(last_tx_bob);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        
        reset_alice_bob();
        
        /* Case: Alice has the incorrect signature key for bob */
        wickr_ec_key_destroy(&alice_transport->remote_identity->id_chain->node->sig_key);
        alice_transport->remote_identity->id_chain->node->sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_NOT_BE_NULL(last_tx_bob);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        
        reset_alice_bob();
        
        /* Case: Bob has the incorrect signature key for alice */
        wickr_ec_key_destroy(&bob_transport->remote_identity->id_chain->node->sig_key);
        bob_transport->remote_identity->id_chain->node->sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_BE_NULL(last_tx_bob);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        
        reset_alice_bob();
        
        /* Case: Alice presents an improperly signed "Final" packet */
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Swap Alice key so that we produce a signature by the wrong key */
        wickr_ec_key_destroy(&alice_transport->local_identity->id_chain->node->sig_key);
        alice_transport->local_identity->id_chain->node->sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        /* Process the final packet from alice that was signed incorrectly */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);

    }
    END_IT
    
    reset_alice_bob();
    
    wickr_buffer_t *actual_handshake = NULL;
    
    IT("should handle corrupted packets at the initial seed packet of the handshake")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Swap the proper packet with a bad one */
        actual_handshake = last_tx_alice;
        last_tx_alice = engine.wickr_crypto_engine_crypto_random(1024);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    IT("should reject handshake info after the error occures (initial)")
    {
        wickr_transport_ctx_process_rx_buffer(bob_transport, actual_handshake);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_NULL(bob_transport->tx_stream);
        SHOULD_BE_NULL(bob_transport->rx_stream);
    }
    END_IT
    
    IT("should reject sending data in the error state (Initial)")
    {
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(bob_transport, test_data);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_NULL(last_tx_bob);
        SHOULD_BE_NULL(last_rx_alice);
        
        wickr_buffer_destroy(&test_data);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject in transit packet modification of handshake packets (initial)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Swap the first byte of the packet */
        last_tx_alice->bytes[0] = 0x5;
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_BE_NULL(last_tx_bob);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject non handshake packets when expecting handshake packets (initial)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Change the type of the packet */
        SHOULD_EQUAL((last_tx_alice->bytes[sizeof(uint64_t)] & 0xF0) >> 4, TRANSPORT_PAYLOAD_TYPE_HANDSHAKE);
        last_tx_alice->bytes[sizeof(uint64_t)] = (((uint8_t)TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT << 4) | TRANSPORT_MAC_TYPE_AUTH_CIPHER);
;
        
        /* Swap signature so the packet is valid */
        wickr_transport_packet_t *pkt = wickr_transport_packet_create_from_buffer(last_tx_alice);
        SHOULD_NOT_BE_NULL(pkt);
        
        wickr_buffer_destroy(&pkt->mac);
        SHOULD_BE_TRUE(wickr_transport_packet_sign(pkt, &engine, alice_transport->local_identity->id_chain->node));
        
        wickr_buffer_t *new_buffer = wickr_transport_packet_serialize(pkt);
        wickr_transport_packet_destroy(&pkt);
        
        SHOULD_NOT_BE_NULL(new_buffer);
        
        wickr_buffer_destroy(&last_tx_alice);
        last_tx_alice = new_buffer;
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_BE_NULL(last_tx_bob);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject non handshake content in the handshake (initial)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        wickr_buffer_t *data = engine.wickr_crypto_engine_crypto_random(128);
        
        wickr_transport_packet_t *pkt = wickr_transport_packet_create(0, TRANSPORT_PAYLOAD_TYPE_HANDSHAKE, data);
        /* Swap signature so the packet is valid */
        SHOULD_NOT_BE_NULL(pkt);
        
        SHOULD_BE_TRUE(wickr_transport_packet_sign(pkt, &engine, alice_transport->local_identity->id_chain->node));
        
        wickr_buffer_t *new_buffer = wickr_transport_packet_serialize(pkt);
        wickr_transport_packet_destroy(&pkt);
        
        SHOULD_NOT_BE_NULL(new_buffer);
        
        wickr_buffer_destroy(&last_tx_alice);
        last_tx_alice = new_buffer;
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_BE_NULL(last_tx_bob);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject handshake packets of the incorrect phase (initial)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        alice_transport->tx_stream = wickr_stream_ctx_create(engine,
                                                             wickr_stream_key_create_rand(engine, CIPHER_AES256_GCM, PACKET_PER_EVO_DEFAULT),
                                                             STREAM_DIRECTION_ENCODE);
        
        Wickr__Proto__Handshake__KeyExchange key_exchange_p = WICKR__PROTO__HANDSHAKE__KEY_EXCHANGE__INIT;
        key_exchange_p.has_sender_pub = false;
        key_exchange_p.has_exchange_data = false;
        
        Wickr__Proto__Handshake__Response response = WICKR__PROTO__HANDSHAKE__RESPONSE__INIT;
        response.key_exchange = &key_exchange_p;
        
        Wickr__Proto__Handshake return_handshake = WICKR__PROTO__HANDSHAKE__INIT;
        return_handshake.payload_case = WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE;
        return_handshake.response = &response;
        return_handshake.version = CURRENT_HANDSHAKE_VERSION;
        
        wickr_transport_packet_t *pkt = wickr_transport_packet_create_proto_handshake(alice_transport, &return_handshake);
        
        /* Swap signature so the packet is valid */
        SHOULD_NOT_BE_NULL(pkt);
        
        wickr_buffer_t *new_buffer = wickr_transport_packet_serialize(pkt);
        wickr_transport_packet_destroy(&pkt);
        
        SHOULD_NOT_BE_NULL(new_buffer);
        
        wickr_buffer_destroy(&last_tx_alice);
        last_tx_alice = new_buffer;
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        
        SHOULD_NOT_BE_NULL(last_tx_alice)
        SHOULD_BE_NULL(last_tx_bob);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should handle corrupted packets at the response packet of the handshake")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Swap the proper packet with a bad one */
        actual_handshake = last_tx_bob;
        last_tx_bob = engine.wickr_crypto_engine_crypto_random(1024);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    IT("should reject handshake after the error occures (return)")
    {
        wickr_transport_ctx_process_rx_buffer(alice_transport, actual_handshake);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_NULL(alice_transport->rx_stream);
    }
    END_IT
    
    IT("should reject sending data in the error state (return)")
    {
        wickr_buffer_destroy_zero(&last_rx_alice);
        
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(bob_transport, test_data);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_NOT_BE_NULL(last_tx_bob);
        SHOULD_BE_NULL(last_rx_alice);
        
        wickr_buffer_destroy_zero(&test_data);
    }
    END_IT
    
    IT("should reject sending data in the TX Init state")
    {
        wickr_buffer_destroy_zero(&last_rx_bob);
        wickr_buffer_destroy_zero(&last_tx_alice);
        
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(alice_transport, test_data);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);

        SHOULD_BE_NULL(last_tx_alice);
        SHOULD_BE_NULL(last_rx_bob);
        
        wickr_buffer_destroy_zero(&test_data);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject in transit packet modification of handshake packets (return)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Swap the first byte of the packet */
        last_tx_bob->bytes[0] = 0x5;
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject non handshake packets when expecting a handshake packet (return)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Swap the first byte of the packet */
        SHOULD_EQUAL((last_tx_bob->bytes[sizeof(uint64_t)] & 0xF0) >> 4, TRANSPORT_PAYLOAD_TYPE_HANDSHAKE);
        last_tx_bob->bytes[sizeof(uint64_t)] = (((uint8_t)TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT << 4) | TRANSPORT_MAC_TYPE_AUTH_CIPHER);
        
        /* Swap signature so the packet is valid */
        wickr_transport_packet_t *pkt = wickr_transport_packet_create_from_buffer(last_tx_alice);
        SHOULD_NOT_BE_NULL(pkt);
        
        wickr_buffer_destroy(&pkt->mac);
        SHOULD_BE_TRUE(wickr_transport_packet_sign(pkt, &engine, alice_transport->local_identity->id_chain->node));
        
        wickr_buffer_t *new_buffer = wickr_transport_packet_serialize(pkt);
        wickr_transport_packet_destroy(&pkt);
        
        SHOULD_NOT_BE_NULL(new_buffer);
        
        wickr_buffer_destroy(&last_tx_alice);
        last_tx_alice = new_buffer;
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject handshake data of the incorrect phase (response)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        Wickr__Proto__Handshake__Seed seed = WICKR__PROTO__HANDSHAKE__SEED__INIT;
        
        Wickr__Proto__Handshake handshake = WICKR__PROTO__HANDSHAKE__INIT;
        handshake.payload_case = WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED;
        handshake.seed = &seed;
        handshake.version = CURRENT_HANDSHAKE_VERSION;
        
        wickr_transport_packet_t *pkt = wickr_transport_packet_create_proto_handshake(bob_transport, &handshake);
        
        wickr_buffer_t *new_buffer = wickr_transport_packet_serialize(pkt);
        wickr_transport_packet_destroy(&pkt);
        
        SHOULD_NOT_BE_NULL(new_buffer);
        
        wickr_buffer_destroy(&last_tx_bob);
        last_tx_bob = new_buffer;
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject non handshake data in handshake packets (return)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        wickr_buffer_t *data = engine.wickr_crypto_engine_crypto_random(128);
        
        wickr_transport_packet_t *pkt = wickr_transport_packet_create(0, TRANSPORT_PAYLOAD_TYPE_HANDSHAKE, data);
        /* Swap signature so the packet is valid */
        SHOULD_NOT_BE_NULL(pkt);
        
        SHOULD_BE_TRUE(wickr_transport_packet_sign(pkt, &engine, bob_transport->local_identity->id_chain->node));
        
        wickr_buffer_t *new_buffer = wickr_transport_packet_serialize(pkt);
        wickr_transport_packet_destroy(&pkt);
        
        SHOULD_NOT_BE_NULL(new_buffer);
        
        wickr_buffer_destroy(&last_tx_bob);
        last_tx_bob = new_buffer;
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should handle corrupted packets at the final packet of the handshake")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        /* Swap the proper packet with a bad one */
        actual_handshake = last_tx_alice;
        last_tx_alice = engine.wickr_crypto_engine_crypto_random(1024);
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    
    IT("should reject handshake and content after the error occures (final)")
    {
        wickr_transport_ctx_process_rx_buffer(bob_transport, actual_handshake);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_NOT_BE_NULL(bob_transport->tx_stream);
        SHOULD_BE_NULL(bob_transport->rx_stream);
        
        wickr_buffer_t *test_content = engine.wickr_crypto_engine_crypto_random(32);
        
        wickr_transport_ctx_process_tx_buffer(alice_transport, test_content);
        SHOULD_NOT_BE_NULL(last_tx_alice);
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(last_rx_bob, test_content, NULL));
        
        wickr_buffer_destroy_zero(&test_content);
    }
    END_IT
    
    IT("should reject sending data in the error state (final)")
    {
        wickr_buffer_destroy_zero(&last_tx_bob);
        wickr_buffer_destroy_zero(&last_tx_alice);
        
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(bob_transport, test_data);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_NULL(last_tx_bob);
        SHOULD_BE_NULL(last_rx_alice);
        
        wickr_buffer_destroy(&test_data);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should handle corrupted packets at the final packet of the handshake")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        /* Swap the proper packet with a bad one */
        last_tx_alice->bytes[0] = 0x5;
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should not handle non handshake payloads when expecting handshake payloads (final)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        /* Change the type of the packet */
        SHOULD_EQUAL((last_tx_alice->bytes[sizeof(uint64_t)] & 0xF0) >> 4 , TRANSPORT_PAYLOAD_TYPE_HANDSHAKE);
        last_tx_alice->bytes[sizeof(uint64_t)] = (((uint8_t)TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT << 4) | TRANSPORT_MAC_TYPE_AUTH_CIPHER);
        
        /* Swap signature so the packet is valid */
        wickr_transport_packet_t *pkt = wickr_transport_packet_create_from_buffer(last_tx_alice);
        SHOULD_NOT_BE_NULL(pkt);
        
        wickr_buffer_destroy(&pkt->mac);
        SHOULD_BE_TRUE(wickr_transport_packet_sign(pkt, &engine, alice_transport->local_identity->id_chain->node));
        
        wickr_buffer_t *new_buffer = wickr_transport_packet_serialize(pkt);
        wickr_transport_packet_destroy(&pkt);
        
        SHOULD_NOT_BE_NULL(new_buffer);
        
        wickr_buffer_destroy(&last_tx_alice);
        last_tx_alice = new_buffer;
                
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject handshake packets of the incorrect phase (final)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        Wickr__Proto__Handshake__Seed seed = WICKR__PROTO__HANDSHAKE__SEED__INIT;
        
        Wickr__Proto__Handshake handshake = WICKR__PROTO__HANDSHAKE__INIT;
        handshake.payload_case = WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED;
        handshake.seed = &seed;
        handshake.version = CURRENT_HANDSHAKE_VERSION;
        
        wickr_transport_packet_t *pkt = wickr_transport_packet_create_proto_handshake(alice_transport, &handshake);
        
        wickr_buffer_t *new_buffer = wickr_transport_packet_serialize(pkt);
        wickr_transport_packet_destroy(&pkt);
        
        SHOULD_NOT_BE_NULL(new_buffer);
        
        wickr_buffer_destroy(&last_tx_alice);
        last_tx_alice = new_buffer;
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("should reject non handshake data in a handshake packet (final)")
    {
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        /* Generate the seed packet with proper signature */
        wickr_transport_ctx_start(alice_transport);
        
        /* Send the seed packet to bob */
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        /* Send the response packet with proper signature */
        wickr_transport_ctx_process_rx_buffer(alice_transport, last_tx_bob);
        
        wickr_buffer_t *data = engine.wickr_crypto_engine_crypto_random(128);
        
        wickr_transport_packet_t *pkt = wickr_transport_packet_create(0, TRANSPORT_PAYLOAD_TYPE_HANDSHAKE, data);
        /* Swap signature so the packet is valid */
        SHOULD_NOT_BE_NULL(pkt);
        
        SHOULD_BE_TRUE(wickr_transport_packet_sign(pkt, &engine, bob_transport->local_identity->id_chain->node));
        
        wickr_buffer_t *new_buffer = wickr_transport_packet_serialize(pkt);
        wickr_transport_packet_destroy(&pkt);
        
        SHOULD_NOT_BE_NULL(new_buffer);
        
        wickr_buffer_destroy(&last_tx_alice);
        last_tx_alice = new_buffer;
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    wickr_buffer_destroy_zero(&actual_handshake);
    reset_alice_bob();
    
    IT("will drop the connection if a presented, valid, identity is passed that does not match the pinned identity")
    {
        wickr_node_t *charlie = createUserNode("charlie", hex_char_to_buffer("charlie_device"));
        SHOULD_NOT_BE_NULL(charlie);
        
        wickr_node_destroy(&alice_transport->local_identity);
        alice_transport->local_identity = charlie;
        
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_NULL(bob_transport->tx_stream);
        SHOULD_BE_NULL(bob_transport->rx_stream);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("will fail a handshake if psk is used and does not match on either side")
    {
        alice_transport->callbacks.on_psk_required = wickr_test_transport_alice_psk;
        bob_transport->callbacks.on_psk_required = wickr_test_transport_bob_psk;
        
        bob_psk = engine.wickr_crypto_engine_crypto_random(32);
        alice_psk = engine.wickr_crypto_engine_crypto_random(32);
        SHOULD_NOT_BE_NULL(bob_psk);
        SHOULD_NOT_BE_NULL(alice_psk);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(bob_psk, alice_psk, NULL));
        
        wickr_transport_ctx_start(alice_transport);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("will fail a handshake if the initiator used a psk and the other party did not")
    {
        alice_psk = engine.wickr_crypto_engine_crypto_random(32);
        alice_transport->callbacks.on_psk_required = wickr_test_transport_alice_psk;
        
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("will fail a handshake if the initiator did not use a psk and the other party did")
    {
        bob_transport->callbacks.on_psk_required = wickr_test_transport_bob_psk;
        bob_psk = engine.wickr_crypto_engine_crypto_random(32);
        SHOULD_NOT_BE_NULL(bob_psk);
        
        wickr_transport_ctx_start(alice_transport);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("it can establish a connection via a secure handshake with a pinned remote")
    {
        wickr_transport_ctx_start(alice_transport);
        verify_established_connection();
        SHOULD_BE_NULL(verified_identity_alice);
        SHOULD_BE_NULL(verified_identity_bob);
    }
    END_IT
    
    IT("can transmit secure packets after the handshake is established (pinned remote)")
    {
        test_packet_send(alice_transport, &last_tx_alice, &last_rx_bob, 3);
        test_packet_send(bob_transport, &last_tx_bob, &last_rx_alice, 2);
    }
    END_IT
    
    IT("can transmit many secure packets (pinned remote)")
    {
        
        for (int i = 0; i < 10000; i++) {
            test_packet_send(alice_transport, &last_tx_alice, &last_rx_bob, i + 4);
        }
        
        for (int i = 0; i < 10000; i++) {
            test_packet_send(bob_transport, &last_tx_bob, &last_rx_alice, i + 3);
        }
        
    }
    END_IT
    
    reset_alice_bob();
    
    IT("can pass user data when establishing stream keys (initiator)")
    {
        alice_user_data = engine.wickr_crypto_engine_crypto_random(32);
        alice_transport->callbacks.on_tx_stream_gen = wickr_test_transport_alice_user_data_injection;
        
        wickr_transport_ctx_start(alice_transport);
        
        verify_established_connection();
        
        const wickr_buffer_t *test_bob_user_data = wickr_transport_ctx_get_rxstream_user_data(bob_transport);
        
        SHOULD_NOT_BE_NULL(test_bob_user_data);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(alice_user_data, test_bob_user_data, NULL));
    }
    END_IT
    
    reset_alice_bob();
    
    IT("can pass user data when establishing stream keys (receiver)")
    {
        bob_user_data = engine.wickr_crypto_engine_crypto_random(32);
        bob_transport->callbacks.on_tx_stream_gen = wickr_test_transport_bob_user_data_injection;
        
        wickr_transport_ctx_start(alice_transport);
        
        verify_established_connection();
        
        const wickr_buffer_t *test_alicerx_user_data = wickr_transport_ctx_get_rxstream_user_data(alice_transport);
        
        SHOULD_NOT_BE_NULL(test_alicerx_user_data);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_user_data, test_alicerx_user_data, NULL));
    }
    END_IT
    
    reset_alice_bob();
    
    IT("can use a psk as part of the handshake process")
    {
        bob_psk = engine.wickr_crypto_engine_crypto_random(32);
        alice_psk = wickr_buffer_copy(bob_psk);
        SHOULD_NOT_BE_NULL(bob_psk);
        SHOULD_NOT_BE_NULL(alice_psk);
        
        bob_transport->callbacks.on_psk_required = wickr_test_transport_bob_psk;
        alice_transport->callbacks.on_psk_required = wickr_test_transport_alice_psk;
        
        wickr_transport_ctx_start(alice_transport);
        verify_established_connection();
    }
    END_IT
    
    reset_alice_bob();
    
    IT("can user a user provided tx stream (initiator)") {
        
        alice_transport->callbacks.on_tx_stream_gen = wickr_test_transport_alice_custom_tx_stream;
        wickr_transport_ctx_start(alice_transport);
        verify_established_connection();
        
        SHOULD_EQUAL(alice_transport->tx_stream, alice_existing_ctx);
        
        test_packet_send(alice_transport, &last_tx_alice, &last_rx_bob, 3);
        test_packet_send(bob_transport, &last_tx_bob, &last_rx_alice, 2);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("can user a user provided tx stream (receiver)") {
        
        bob_transport->callbacks.on_tx_stream_gen = wickr_test_transport_bob_custom_tx_stream;
        wickr_transport_ctx_start(alice_transport);
        verify_established_connection();
        
        SHOULD_EQUAL(bob_transport->tx_stream, bob_existing_ctx);
        
        test_packet_send(alice_transport, &last_tx_alice, &last_rx_bob, 3);
        test_packet_send(bob_transport, &last_tx_bob, &last_rx_alice, 2);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("can user a user provided tx stream (both sides)") {
        
        bob_transport->callbacks.on_tx_stream_gen = wickr_test_transport_bob_custom_tx_stream;
        alice_transport->callbacks.on_tx_stream_gen = wickr_test_transport_alice_custom_tx_stream;
        
        wickr_transport_ctx_start(alice_transport);
        verify_established_connection();
        
        SHOULD_EQUAL(bob_transport->tx_stream, bob_existing_ctx);
        SHOULD_EQUAL(alice_transport->tx_stream, alice_existing_ctx);

        test_packet_send(alice_transport, &last_tx_alice, &last_rx_bob, 3);
        test_packet_send(bob_transport, &last_tx_bob, &last_rx_alice, 2);
    }
    END_IT
    
    reset_alice_bob();
    wickr_node_destroy(&bob_transport->remote_identity);
    bob_transport->callbacks.on_identity_verify = &wickr_test_transport_verify_remote_failure;
    
    IT("will fail connection establishment if the remote party rejects the incoming identity (non pinned remote)")
    {
        wickr_transport_ctx_start(alice_transport);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_SEEDED);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_NULL(bob_transport->tx_stream);
        SHOULD_BE_NULL(bob_transport->rx_stream);
    }
    END_IT
    
    reset_alice_bob();
    wickr_node_destroy(&bob_transport->remote_identity);
    wickr_node_destroy(&alice_transport->remote_identity);
    alice_transport->callbacks.on_identity_verify = &wickr_test_transport_verify_remote_failure;
    
    IT("will fail connection establishment if any party rejects the incoming identity (non pinned remote)")
    {
        wickr_transport_ctx_start(alice_transport);
        SHOULD_EQUAL(last_status_alice, TRANSPORT_STATUS_ERROR);
        SHOULD_EQUAL(last_status_bob, TRANSPORT_STATUS_TX_INIT);
        SHOULD_BE_NULL(alice_transport->rx_stream);
    }
    END_IT
    
    reset_alice_bob();
    wickr_node_destroy(&bob_transport->remote_identity);

    IT("can establish a secure connection without pinning a remote")
    {
        wickr_transport_ctx_start(alice_transport);
        verify_established_connection();
        SHOULD_NOT_BE_NULL(verified_identity_bob);
        SHOULD_NOT_BE_NULL(bob_transport->remote_identity);
        
        /* Verify equality between parties */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->dev_id, alice_transport->local_identity->dev_id, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->root->identifier, alice_transport->local_identity->id_chain->root->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->node->identifier, alice_transport->local_identity->id_chain->node->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->node->sig_key->pub_data, alice_transport->local_identity->id_chain->node->sig_key->pub_data, NULL));
        
        /* Verify equality between verified identity and used identity */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->root->identifier, verified_identity_bob->root->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->node->identifier,verified_identity_bob->node->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->node->sig_key->pub_data, verified_identity_bob->node->sig_key->pub_data, NULL));
    }
    END_IT
    
    IT("can transmit secure packets after the handshake is established (non pinned remote)")
    {
        test_packet_send(alice_transport, &last_tx_alice, &last_rx_bob, 3);
        test_packet_send(bob_transport, &last_tx_bob, &last_rx_alice, 2);
    }
    END_IT
    
    IT("can transmit many secure packets (non pinned remote)")
    {
        
        for (int i = 0; i < 10000; i++) {
            test_packet_send(alice_transport, &last_tx_alice, &last_rx_bob, i + 4);
        }
        
        for (int i = 0; i < 10000; i++) {
            test_packet_send(bob_transport, &last_tx_bob, &last_rx_alice, i + 3);
        }
         
    }
    END_IT
    
    wickr_buffer_destroy(&last_rx_alice);
    wickr_buffer_destroy(&last_tx_alice);
    wickr_buffer_destroy(&last_rx_bob);
    wickr_buffer_destroy(&last_tx_bob);
    
    IT("can support different data flow modes")
    {
        SHOULD_EQUAL(wickr_transport_ctx_get_data_flow_mode(alice_transport), TRANSPORT_DATA_FLOW_BIDIRECTIONAL);
        wickr_transport_ctx_set_data_flow_mode(alice_transport, TRANSPORT_DATA_FLOW_READ_ONLY);
        SHOULD_EQUAL(wickr_transport_ctx_get_data_flow_mode(alice_transport), TRANSPORT_DATA_FLOW_READ_ONLY);
        
        wickr_buffer_t *test_buffer = engine.wickr_crypto_engine_crypto_random(32);
        
        /* Data should not be sent in read only mode */
        wickr_transport_ctx_process_tx_buffer(alice_transport, test_buffer);
        SHOULD_BE_NULL(last_tx_alice);
        
        wickr_buffer_destroy(&last_rx_alice);
        wickr_buffer_destroy(&last_tx_alice);
        wickr_buffer_destroy(&last_rx_bob);
        wickr_buffer_destroy(&last_tx_bob);
        
        /* Data should not be read in write only mode */
        wickr_transport_ctx_set_data_flow_mode(alice_transport, TRANSPORT_DATA_FLOW_WRITE_ONLY);
        SHOULD_EQUAL(wickr_transport_ctx_get_data_flow_mode(alice_transport), TRANSPORT_DATA_FLOW_WRITE_ONLY);
        
        wickr_transport_ctx_process_tx_buffer(bob_transport, test_buffer);
        SHOULD_NOT_BE_NULL(last_tx_bob);
        SHOULD_BE_NULL(last_rx_alice);
        
        wickr_buffer_destroy(&test_buffer);
    }
    END_IT
    
    reset_alice_bob();
    wickr_node_destroy(&bob_transport->remote_identity);
    wickr_node_destroy(&alice_transport->remote_identity);
    
    IT("can establish a secure connection when neither side has a pinned remote")
    {
        wickr_transport_ctx_start(alice_transport);
        verify_established_connection();
        SHOULD_NOT_BE_NULL(verified_identity_bob);
        SHOULD_NOT_BE_NULL(verified_identity_alice);
        SHOULD_NOT_BE_NULL(bob_transport->remote_identity);
        
        /* Verify equality between parties */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->dev_id, alice_transport->local_identity->dev_id, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->root->identifier, alice_transport->local_identity->id_chain->root->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->node->identifier, alice_transport->local_identity->id_chain->node->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->node->sig_key->pub_data, alice_transport->local_identity->id_chain->node->sig_key->pub_data, NULL));
        
        /* Verify equality between verified identity and used identity */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->root->identifier, verified_identity_bob->root->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->node->identifier,verified_identity_bob->node->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bob_transport->remote_identity->id_chain->node->sig_key->pub_data, verified_identity_bob->node->sig_key->pub_data, NULL));
    }
    END_IT
    
    IT("can transmit secure packets after the handshake is established (no pinned remotes)")
    {
        test_packet_send(alice_transport, &last_tx_alice, &last_rx_bob, 3);
        test_packet_send(bob_transport, &last_tx_bob, &last_rx_alice, 2);
    }
    END_IT
    
    IT("can transmit many secure packets (non pinned remotes)")
    {
        
        for (int i = 0; i < 10000; i++) {
            test_packet_send(alice_transport, &last_tx_alice, &last_rx_bob, i + 4);
        }
        
        for (int i = 0; i < 10000; i++) {
            test_packet_send(bob_transport, &last_tx_bob, &last_rx_alice, i + 3);
        }
        
    }
    END_IT
    
    IT("can perform a key exchange at any time")
    {
        wickr_stream_ctx_t *old_alice_rx = wickr_stream_ctx_copy(alice_transport->rx_stream);
        wickr_stream_ctx_t *old_alice_tx = wickr_stream_ctx_copy(alice_transport->tx_stream);
        
        wickr_stream_ctx_t *old_bob_rx = wickr_stream_ctx_copy(bob_transport->rx_stream);
        wickr_stream_ctx_t *old_bob_tx = wickr_stream_ctx_copy(bob_transport->tx_stream);

        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_EQUAL(alice_transport->status, TRANSPORT_STATUS_ACTIVE);
        SHOULD_EQUAL(bob_transport->status, TRANSPORT_STATUS_ACTIVE);

        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(old_alice_rx->key->cipher_key->key_data, alice_transport->rx_stream->key->cipher_key->key_data, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(old_alice_tx->key->cipher_key->key_data, alice_transport->tx_stream->key->cipher_key->key_data, NULL));
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(old_bob_rx->key->cipher_key->key_data, bob_transport->rx_stream->key->cipher_key->key_data, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(old_bob_tx->key->cipher_key->key_data, bob_transport->tx_stream->key->cipher_key->key_data, NULL));
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(old_alice_rx->key->evolution_key, alice_transport->rx_stream->key->evolution_key, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(old_alice_tx->key->evolution_key, alice_transport->tx_stream->key->evolution_key, NULL));
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(old_bob_rx->key->evolution_key, bob_transport->rx_stream->key->evolution_key, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(old_bob_tx->key->evolution_key, bob_transport->tx_stream->key->evolution_key, NULL));
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(old_alice_tx->iv_factory->seed, alice_transport->tx_stream->iv_factory->seed, NULL));
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(old_bob_tx->iv_factory->seed, bob_transport->tx_stream->iv_factory->seed, NULL));
        
        SHOULD_EQUAL(alice_transport->rx_stream->last_seq, old_alice_rx->last_seq + 1);
        SHOULD_EQUAL(alice_transport->tx_stream->last_seq, old_alice_tx->last_seq + 2);
        SHOULD_EQUAL(bob_transport->rx_stream->last_seq, old_bob_rx->last_seq + 2);
        SHOULD_EQUAL(bob_transport->tx_stream->last_seq, old_bob_tx->last_seq + 1);

        wickr_stream_ctx_destroy(&old_bob_rx);
        wickr_stream_ctx_destroy(&old_bob_tx);
        wickr_stream_ctx_destroy(&old_alice_rx);
        wickr_stream_ctx_destroy(&old_alice_tx);
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_transport_ctx_set_data_flow_mode(alice_transport, TRANSPORT_DATA_FLOW_WRITE_ONLY);
        
        wickr_transport_ctx_t *copy = wickr_transport_ctx_copy(alice_transport);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->local_identity->dev_id, alice_transport->local_identity->dev_id, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->remote_identity->dev_id, alice_transport->remote_identity->dev_id, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->tx_stream->iv_factory->seed, alice_transport->tx_stream->iv_factory->seed, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->rx_stream->key->evolution_key, alice_transport->rx_stream->key->evolution_key, NULL));
        SHOULD_EQUAL(copy->status, alice_transport->status);
        SHOULD_EQUAL(copy->evo_count, alice_transport->evo_count);
        SHOULD_EQUAL(copy->data_flow, alice_transport->data_flow);
        
        wickr_transport_ctx_destroy(&copy);
        
    }
    END_IT
    
    reset_alice_bob();
    
    IT("should enter a failure state when a corrupted packet is entered into the stream")
    {
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, alice_transport->status);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, bob_transport->status);
        
        wickr_buffer_t *test_bad_packet = engine.wickr_crypto_engine_crypto_random(32);
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, test_bad_packet);
        
        SHOULD_EQUAL(TRANSPORT_STATUS_ERROR, bob_transport->status);
        
        wickr_buffer_destroy(&test_bad_packet);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("should enter a failure state if the packet is too small (1)")
    {
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, alice_transport->status);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, bob_transport->status);
        
        wickr_buffer_t *test_bad_packet = engine.wickr_crypto_engine_crypto_random(sizeof(uint64_t) / 2);
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, test_bad_packet);
        
        SHOULD_EQUAL(TRANSPORT_STATUS_ERROR, bob_transport->status);
        
        wickr_buffer_destroy(&test_bad_packet);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("should enter a failure state if the packet is too small (2)")
    {
        wickr_transport_ctx_start(alice_transport);
        
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, alice_transport->status);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, bob_transport->status);
        
        wickr_buffer_t *test_bad_packet = engine.wickr_crypto_engine_crypto_random(sizeof(uint64_t));
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, test_bad_packet);
        
        SHOULD_EQUAL(TRANSPORT_STATUS_ERROR, bob_transport->status);
        
        wickr_buffer_destroy(&test_bad_packet);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("should enter a failure state when the body of packet is modified in transit")
    {
        wickr_transport_ctx_start(alice_transport);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, alice_transport->status);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, bob_transport->status);
        
        wickr_buffer_t *test_bad_packet = engine.wickr_crypto_engine_crypto_random(32);

        wickr_transport_ctx_process_tx_buffer(alice_transport, test_bad_packet);
        
        if (last_tx_alice->bytes[last_tx_alice->length /2] != 0x0) {
            last_tx_alice->bytes[last_tx_alice->length / 2] = 0x0;
        }
        else {
            last_tx_alice->bytes[last_tx_alice->length / 2] = 0x1;
        }
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, test_bad_packet);
        
        SHOULD_EQUAL(TRANSPORT_STATUS_ERROR, bob_transport->status);
        
        wickr_buffer_destroy(&test_bad_packet);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("should enter a failure state if the sequence number of a packet is modified in transit")
    {
        wickr_transport_ctx_start(alice_transport);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, alice_transport->status);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, bob_transport->status);
        
        wickr_buffer_t *test_bad_packet = engine.wickr_crypto_engine_crypto_random(32);
        
        wickr_transport_ctx_process_tx_buffer(alice_transport, test_bad_packet);
        
        last_tx_alice->bytes[0] = 0x5;
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, test_bad_packet);
        
        SHOULD_EQUAL(TRANSPORT_STATUS_ERROR, bob_transport->status);
        
        wickr_buffer_destroy(&test_bad_packet);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("should enter a failure state if a sequence number goes backwards")
    {
        wickr_transport_ctx_start(alice_transport);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, alice_transport->status);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, bob_transport->status);
        
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        wickr_buffer_t *test_data_1 = engine.wickr_crypto_engine_crypto_random(32);
        wickr_buffer_t *test_data_2 = engine.wickr_crypto_engine_crypto_random(32);

        
        wickr_transport_ctx_process_tx_buffer(alice_transport, test_data_1);

        wickr_buffer_t *test_pkt_1 = wickr_buffer_copy(last_tx_alice);
        
        wickr_transport_ctx_process_tx_buffer(alice_transport, test_data_2);

        wickr_buffer_t *test_pkt_2 = wickr_buffer_copy(last_tx_alice);
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, test_pkt_1);
        
        SHOULD_EQUAL(bob_transport->status, TRANSPORT_STATUS_ACTIVE);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_data_1, last_rx_bob, NULL));
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, test_pkt_2);
        
        SHOULD_EQUAL(bob_transport->status, TRANSPORT_STATUS_ACTIVE);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_data_2, last_rx_bob, NULL));
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, test_pkt_1);
        
        SHOULD_EQUAL(bob_transport->status, TRANSPORT_STATUS_ERROR);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(test_data_1, last_rx_bob, NULL));
        
        wickr_buffer_destroy(&test_pkt_1);
        wickr_buffer_destroy(&test_pkt_2);
        wickr_buffer_destroy(&test_data_1);
        wickr_buffer_destroy(&test_data_2);

    }
    END_IT
    
    reset_alice_bob();
    
    IT("should enter a failure state if there is a replay")
    {
        wickr_transport_ctx_start(alice_transport);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, alice_transport->status);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, bob_transport->status);
        
        alice_transport->callbacks.tx = wickr_test_transport_tx_alice_no_send;
        bob_transport->callbacks.tx = wickr_test_transport_tx_bob_no_send;
        
        wickr_buffer_t *test_data_1 = engine.wickr_crypto_engine_crypto_random(32);
        
        
        wickr_transport_ctx_process_tx_buffer(alice_transport, test_data_1);
        
        wickr_buffer_t *test_pkt_1 = wickr_buffer_copy(last_tx_alice);
        
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, test_pkt_1);
        
        SHOULD_EQUAL(bob_transport->status, TRANSPORT_STATUS_ACTIVE);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(test_data_1, last_rx_bob, NULL));
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, test_pkt_1);
        
        SHOULD_EQUAL(bob_transport->status, TRANSPORT_STATUS_ERROR);
        
        wickr_buffer_destroy(&test_pkt_1);
        wickr_buffer_destroy(&test_data_1);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("should enter a failure state if the packet type is modified in transit")
    {
        wickr_transport_ctx_start(alice_transport);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, alice_transport->status);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, bob_transport->status);
        
        wickr_buffer_t *test_bad_packet = engine.wickr_crypto_engine_crypto_random(32);
        
        wickr_transport_ctx_process_tx_buffer(alice_transport, test_bad_packet);
        
        SHOULD_EQUAL((last_tx_alice->bytes[sizeof(uint64_t)] & 0xF0) >> 4, TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT);
        last_tx_alice->bytes[sizeof(uint64_t)] = (((uint8_t)TRANSPORT_PAYLOAD_TYPE_HANDSHAKE << 4) | TRANSPORT_MAC_TYPE_EC_P521);
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, test_bad_packet);
        
        SHOULD_EQUAL(TRANSPORT_STATUS_ERROR, bob_transport->status);
        
        wickr_buffer_destroy(&test_bad_packet);
    }
    END_IT
    
    reset_alice_bob();
    
    IT("should enter a failure state if the packet is not encrypted")
    {
        wickr_transport_ctx_start(alice_transport);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, alice_transport->status);
        SHOULD_EQUAL(TRANSPORT_STATUS_ACTIVE, bob_transport->status);
        
        wickr_buffer_t *test_bad_packet = engine.wickr_crypto_engine_crypto_random(32);
        
        wickr_transport_packet_t *pkt = wickr_transport_packet_create(alice_transport->tx_stream->last_seq + 1, TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT, test_bad_packet);
        SHOULD_NOT_BE_NULL(pkt);
        
        wickr_buffer_t *pkt_buffer = wickr_transport_packet_serialize(pkt);
        wickr_transport_packet_destroy(&pkt);
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, pkt_buffer);
        
        SHOULD_EQUAL(TRANSPORT_STATUS_ERROR, bob_transport->status);
        
        wickr_buffer_destroy(&pkt_buffer);

    }
    END_IT
    
    IT("should not allow you to send or receive packets in the error state")
    {
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(32);

        wickr_buffer_destroy(&last_tx_bob);
        wickr_buffer_destroy(&last_rx_bob);
        wickr_buffer_destroy(&last_tx_alice);
        
        wickr_transport_ctx_process_tx_buffer(alice_transport, test_data);
        SHOULD_NOT_BE_NULL(last_tx_alice);
        
        wickr_transport_ctx_process_tx_buffer(bob_transport, test_data);
        
        SHOULD_EQUAL(TRANSPORT_STATUS_ERROR, bob_transport->status);
        SHOULD_BE_NULL(last_tx_bob);
        
        wickr_transport_ctx_process_rx_buffer(bob_transport, last_tx_alice);
        SHOULD_BE_NULL(last_rx_bob);
        
        wickr_buffer_destroy(&test_data);
    }
    END_IT
    
    
    reset_alice_bob();
    
    IT("should allow you to bump the tx stream to the next key evolution")
    {
        wickr_transport_ctx_start(alice_transport);
        verify_established_connection();
        
        wickr_transport_ctx_t *backup = wickr_transport_ctx_copy(alice_transport);
        SHOULD_BE_TRUE(wickr_transport_ctx_force_tx_key_evo(alice_transport));
        
        SHOULD_NOT_EQUAL(backup->tx_stream->last_seq, alice_transport->tx_stream->last_seq);
        
        // Until another packet is generated the key does not evolove
        SHOULD_BE_TRUE(wickr_buffer_is_equal(backup->tx_stream->key->cipher_key->key_data, alice_transport->tx_stream->key->cipher_key->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(backup->tx_stream->key->evolution_key, alice_transport->tx_stream->key->evolution_key, NULL));
        
        wickr_buffer_t *random = engine.wickr_crypto_engine_crypto_random(32);
        wickr_transport_ctx_process_tx_buffer(alice_transport, random);
        
        // A packet was generated so the evolution should be complete
        SHOULD_BE_FALSE(wickr_buffer_is_equal(backup->tx_stream->key->cipher_key->key_data, alice_transport->tx_stream->key->cipher_key->key_data, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(backup->tx_stream->key->evolution_key, alice_transport->tx_stream->key->evolution_key, NULL));
        
        // Reset backup and evolove again to confirm incrementing
        wickr_transport_ctx_destroy(&backup);
        backup = wickr_transport_ctx_copy(alice_transport);
        SHOULD_BE_TRUE(wickr_transport_ctx_force_tx_key_evo(alice_transport));

        wickr_transport_ctx_process_tx_buffer(alice_transport, random);
        wickr_buffer_destroy(&random);
        
        SHOULD_NOT_EQUAL(backup->tx_stream->last_seq, alice_transport->tx_stream->last_seq);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(backup->tx_stream->key->cipher_key->key_data, alice_transport->tx_stream->key->cipher_key->key_data, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(backup->tx_stream->key->evolution_key, alice_transport->tx_stream->key->evolution_key, NULL));
        
        // Verify edge cases
        SHOULD_BE_FALSE(wickr_transport_ctx_force_tx_key_evo(NULL));
        alice_transport->status = TRANSPORT_STATUS_NONE;
        SHOULD_BE_FALSE(wickr_transport_ctx_force_tx_key_evo(alice_transport));
        
        wickr_transport_ctx_destroy(&backup);
    }
    END_IT
    
    reset_alice_bob();
    
    wickr_transport_ctx_destroy(&alice_transport);
    wickr_transport_ctx_destroy(&bob_transport);
    
    SHOULD_BE_NULL(alice_transport);
    SHOULD_BE_NULL(bob_transport);
}
END_DESCRIBE
