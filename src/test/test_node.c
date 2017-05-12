
#include "test_node.h"
#include "buffer.h"
#include "crypto_engine.h"
#include "identity.h"
#include "node.h"

DESCRIBE(node_tests, "node.c")
{
    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();

    wickr_buffer_t *test_dev_id = engine.wickr_crypto_engine_crypto_random(32);
    
    wickr_buffer_t *test_root_id = engine.wickr_crypto_engine_crypto_random(32);
    wickr_ec_key_t *test_root_sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    
    wickr_identity_t *root_id = wickr_identity_create(IDENTITY_TYPE_ROOT, test_root_id, test_root_sig_key, NULL);
    wickr_identity_t *node_id = wickr_node_identity_gen(&engine, root_id);
    
    wickr_identity_chain_t *test_id_chain = wickr_identity_chain_create(root_id, node_id);
    
    wickr_ephemeral_keypair_t *test_keypair = wickr_ephemeral_keypair_generate_identity(&engine, 1, node_id);
    
    IT("should fail generation unless all fields are provided")
    {
        SHOULD_BE_NULL(wickr_node_create(NULL, NULL, NULL));
        SHOULD_BE_NULL(wickr_node_create(test_dev_id, NULL, NULL));
        SHOULD_BE_NULL(wickr_node_create(NULL, test_id_chain, NULL));
        SHOULD_BE_NULL(wickr_node_create(NULL, NULL, test_keypair));
        SHOULD_BE_NULL(wickr_node_create(NULL, test_id_chain, test_keypair));
        SHOULD_BE_NULL(wickr_node_create(test_dev_id, NULL, test_keypair));
    }
    END_IT
    
    wickr_node_t *node = NULL;
    
    IT("should generate if all fields are provided")
    {
        node = wickr_node_create(test_dev_id, test_id_chain, test_keypair);
        SHOULD_NOT_BE_NULL(node);
        SHOULD_EQUAL(node->dev_id, test_dev_id);
        SHOULD_EQUAL(node->ephemeral_keypair, test_keypair);
        SHOULD_EQUAL(node->id_chain, test_id_chain);
        
        wickr_node_t *copy_node = wickr_node_copy(node);
        SHOULD_NOT_BE_NULL(copy_node);
        SHOULD_NOT_BE_NULL(copy_node->dev_id);
        SHOULD_NOT_BE_NULL(copy_node->ephemeral_keypair);
        SHOULD_NOT_BE_NULL(copy_node->id_chain);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_node->dev_id, node->dev_id, NULL));
        
        SHOULD_NOT_EQUAL(copy_node->dev_id, test_dev_id);
        SHOULD_NOT_EQUAL(copy_node->ephemeral_keypair, test_keypair);
        SHOULD_NOT_EQUAL(copy_node->id_chain, test_id_chain);
        
        wickr_node_destroy(&copy_node);
    }
    END_IT
    
    
    IT("should be able to validate it's signing chain")
    {
        SHOULD_BE_TRUE(wickr_node_verify_signature_chain(node, &engine));
    }
    END_IT
    
    node->id_chain->status = IDENTITY_CHAIN_STATUS_UNKNOWN;
    
    IT("should fail validation if it's current status is failed")
    {
        wickr_node_t *copy_node = wickr_node_copy(node);
        copy_node->id_chain->status = IDENTITY_CHAIN_STATUS_INVALID;
        
        SHOULD_BE_FALSE(wickr_node_verify_signature_chain(copy_node, &engine));
        wickr_node_destroy(&copy_node);
    }
    END_IT
    
    IT("should fail validation if it doesn't have a keypair")
    {
        wickr_node_t *copy_node = wickr_node_copy(node);
        wickr_ephemeral_keypair_destroy(&copy_node->ephemeral_keypair);
        SHOULD_BE_FALSE(wickr_node_verify_signature_chain(copy_node, &engine));
        wickr_node_destroy(&copy_node);
    }
    END_IT
    
    node->id_chain->status = IDENTITY_CHAIN_STATUS_UNKNOWN;
    
    IT("should fail validation if it's identity->node signature is incorrect")
    {
        wickr_node_t *copy_node = wickr_node_copy(node);
        wickr_buffer_t *random_data = engine.wickr_crypto_engine_crypto_random(64);
        
        wickr_ecdsa_result_destroy(&copy_node->id_chain->node->signature);
        
        copy_node->id_chain->node->signature = wickr_identity_sign(copy_node->id_chain->root, &engine, random_data);
        wickr_buffer_destroy(&random_data);
        
        SHOULD_BE_FALSE(wickr_node_verify_signature_chain(copy_node, &engine))
        
        wickr_node_destroy(&copy_node);
    }
    END_IT
    
    node->id_chain->status = IDENTITY_CHAIN_STATUS_UNKNOWN;
    
    IT("should fail validation if it's ephemeral keypair signature is incorrect")
    {
        wickr_node_t *copy_node = wickr_node_copy(node);
        wickr_buffer_t *random_data = engine.wickr_crypto_engine_crypto_random(64);
        
        wickr_ecdsa_result_destroy(&copy_node->ephemeral_keypair->signature);
        
        copy_node->ephemeral_keypair->signature = wickr_identity_sign(copy_node->id_chain->node, &engine, random_data);
        wickr_buffer_destroy(&random_data);
        
        SHOULD_BE_FALSE(wickr_node_verify_signature_chain(copy_node, &engine))
        
        /* Check that this should fail, EVEN if someone explicitly manipulates the identity chain status to be "valid" */
        copy_node->id_chain->status = IDENTITY_CHAIN_STATUS_VALID;
        
        SHOULD_BE_FALSE(wickr_node_verify_signature_chain(copy_node, &engine));
        
        wickr_node_destroy(&copy_node);

    }
    END_IT
    
    node->id_chain->status = IDENTITY_CHAIN_STATUS_UNKNOWN;
    
    IT("should allow you to rotate the key pair it holds")
    {
        wickr_ephemeral_keypair_t *another_keypair = wickr_ephemeral_keypair_generate_identity(&engine, 2, node_id);
        
        SHOULD_BE_TRUE(wickr_node_rotate_keypair(node, another_keypair, false));
        
        SHOULD_EQUAL(node->ephemeral_keypair, another_keypair);
        
        wickr_ephemeral_keypair_t *copy_keypair = wickr_ephemeral_keypair_copy(another_keypair);
        
        SHOULD_BE_TRUE(wickr_node_rotate_keypair(node, copy_keypair, true));
        
        SHOULD_NOT_EQUAL(node->ephemeral_keypair, copy_keypair);
        
        wickr_ephemeral_keypair_destroy(&copy_keypair);

        SHOULD_EQUAL(node->ephemeral_keypair->identifier, 2);
    }
    END_IT
    
    IT("can be put into a node array")
    {
        wickr_node_array_t *node_array = wickr_node_array_new(1);
        SHOULD_NOT_BE_NULL(node_array);
        
        SHOULD_BE_TRUE(wickr_node_array_set_item(node_array, 0, node));
        SHOULD_EQUAL(wickr_node_array_fetch_item(node_array, 0), node);
        
        wickr_node_array_t *copy_array = wickr_node_array_copy(node_array);
        SHOULD_NOT_BE_NULL(node_array);
        SHOULD_NOT_EQUAL(wickr_node_array_fetch_item(copy_array, 0), wickr_node_array_fetch_item(node_array, 0));
        
        wickr_array_destroy(&copy_array, true);
        
        wickr_node_array_destroy(&node_array);
    }
    END_IT
    
    wickr_node_destroy(&node);
    
}
END_DESCRIBE
