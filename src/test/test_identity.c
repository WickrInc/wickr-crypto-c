
#include "test_identity.h"
#include "identity.h"
#include "externs.h"

DESCRIBE(identity, "identity tests")
{
    wickr_identity_t *test_identity = NULL;
    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    
    IT("can be created with the required fields")
    {
        SHOULD_BE_NULL(wickr_identity_create(IDENTITY_TYPE_NODE, NULL, NULL, NULL));
        SHOULD_BE_NULL(wickr_identity_create(IDENTITY_TYPE_ROOT, NULL, NULL, NULL));
        
        wickr_buffer_t *identifier = engine.wickr_crypto_engine_crypto_random(IDENTIFIER_LEN);
        
        SHOULD_BE_NULL(wickr_identity_create(IDENTITY_TYPE_NODE, identifier, NULL, NULL));
        SHOULD_BE_NULL(wickr_identity_create(IDENTITY_TYPE_ROOT, identifier, NULL, NULL));

        wickr_ec_key_t *sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        SHOULD_BE_NULL(wickr_identity_create(IDENTITY_TYPE_NODE, NULL, sig_key, NULL));
        SHOULD_BE_NULL(wickr_identity_create(IDENTITY_TYPE_ROOT, NULL, sig_key, NULL));
        
        /* Sign identifier since this test doesn't need the proper setup and we already have that value */
        wickr_ecdsa_result_t *result = engine.wickr_crypto_engine_ec_sign(sig_key, identifier, DIGEST_SHA_512);
        
        SHOULD_BE_NULL(wickr_identity_create(IDENTITY_TYPE_NODE, NULL, NULL, result));
        SHOULD_BE_NULL(wickr_identity_create(IDENTITY_TYPE_ROOT, NULL, NULL, result));
        SHOULD_BE_NULL(wickr_identity_create(IDENTITY_TYPE_NODE, identifier, NULL, result));
        SHOULD_BE_NULL(wickr_identity_create(IDENTITY_TYPE_ROOT, identifier, NULL, result));
        
        wickr_identity_t *node_id = wickr_identity_create(IDENTITY_TYPE_NODE, wickr_buffer_copy(identifier), wickr_ec_key_copy(sig_key), NULL);
        SHOULD_NOT_BE_NULL(node_id);
        wickr_identity_destroy(&node_id);
        
        test_identity = wickr_identity_create(IDENTITY_TYPE_ROOT, identifier, sig_key, result);
        SHOULD_NOT_BE_NULL(test_identity);
    }
    END_IT
    
    IT("can generate a node identity as a root identity")
    {
        wickr_identity_t *node_id = wickr_node_identity_gen(&engine, test_identity);
        SHOULD_NOT_BE_NULL(node_id);
        SHOULD_EQUAL(node_id->type, IDENTITY_TYPE_NODE);
        SHOULD_NOT_BE_NULL(node_id->signature);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(node_id->identifier, test_identity->identifier, NULL));
        SHOULD_BE_FALSE(wickr_buffer_is_equal(node_id->sig_key->pub_data, test_identity->sig_key->pub_data, NULL));
        wickr_identity_destroy(&node_id);
    }
    END_IT
    
    IT("can sign content")
    {
        wickr_buffer_t *test_data = engine.wickr_crypto_engine_crypto_random(32);
        wickr_ecdsa_result_t *signature = wickr_identity_sign(test_identity, &engine, test_data);
        SHOULD_NOT_BE_NULL(signature);
        
        SHOULD_BE_TRUE(engine.wickr_crypto_engine_ec_verify(signature, test_identity->sig_key, test_data));
        
        wickr_buffer_destroy(&test_data);
        wickr_ecdsa_result_destroy(&signature);
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_identity_t *copy = wickr_identity_copy(test_identity);
        SHOULD_NOT_BE_NULL(copy);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->identifier, test_identity->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->sig_key->pub_data, test_identity->sig_key->pub_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->signature->sig_data, test_identity->signature->sig_data, NULL));
        SHOULD_EQUAL(copy->type, test_identity->type);
        
        wickr_identity_destroy(&copy);
    }
    END_IT
    
    IT("can be serialized / deserialized")
    {
        wickr_buffer_t *serialized = wickr_identity_serialize(test_identity);
        SHOULD_NOT_BE_NULL(serialized);
        
        wickr_identity_t *identity = wickr_identity_create_from_buffer(serialized, &engine);
        SHOULD_NOT_BE_NULL(identity);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(identity->identifier, test_identity->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(identity->sig_key->pub_data, test_identity->sig_key->pub_data, NULL));
        SHOULD_EQUAL(identity->type, test_identity->type);
        
        wickr_buffer_destroy(&serialized);
        wickr_identity_destroy(&identity);
    }
    END_IT
    
    wickr_identity_destroy(&test_identity);
    SHOULD_BE_NULL(test_identity);
}
END_DESCRIBE

DESCRIBE(identity_chain, "identity chain tests")
{
    wickr_identity_chain_t *test_chain = NULL;
    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    
    IT("can be created with the proper fields")
    {
        wickr_buffer_t *identifier = engine.wickr_crypto_engine_crypto_random(IDENTIFIER_LEN);
        wickr_ec_key_t *sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);

        wickr_identity_t *test_root = wickr_identity_create(IDENTITY_TYPE_ROOT, identifier, sig_key, NULL);
        wickr_identity_t *test_node = wickr_node_identity_gen(&engine, test_root);
        
        SHOULD_BE_NULL(wickr_identity_chain_create(NULL, NULL));
        SHOULD_BE_NULL(wickr_identity_chain_create(test_root, NULL));
        SHOULD_BE_NULL(wickr_identity_chain_create(NULL, test_node));
        
        test_chain = wickr_identity_chain_create(test_root, test_node);
        SHOULD_NOT_BE_NULL(test_chain);
        
        SHOULD_EQUAL(test_chain->node, test_node);
        SHOULD_EQUAL(test_chain->root, test_root);
        SHOULD_EQUAL(test_chain->status, IDENTITY_CHAIN_STATUS_UNKNOWN);
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_identity_chain_t *copy = wickr_identity_chain_copy(test_chain);
        SHOULD_NOT_BE_NULL(copy);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->root->identifier, test_chain->root->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->root->sig_key->pub_data, test_chain->root->sig_key->pub_data, NULL));
        SHOULD_EQUAL(copy->root->type, test_chain->root->type);

        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->node->identifier, test_chain->node->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->node->sig_key->pub_data, test_chain->node->sig_key->pub_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->node->signature->sig_data, test_chain->node->signature->sig_data, NULL));
        SHOULD_EQUAL(copy->node->type, test_chain->node->type);
        
        wickr_identity_chain_destroy(&copy);
    }
    END_IT
    
    IT("can be serialized / deserialized")
    {
        wickr_buffer_t *serialized = wickr_identity_chain_serialize(test_chain);
        SHOULD_NOT_BE_NULL(serialized);
        
        wickr_identity_chain_t *deserialized = wickr_identity_chain_create_from_buffer(serialized, &engine);
        SHOULD_NOT_BE_NULL(deserialized);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->root->identifier, test_chain->root->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->root->sig_key->pub_data, test_chain->root->sig_key->pub_data, NULL));
        SHOULD_EQUAL(deserialized->root->type, test_chain->root->type);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->node->identifier, test_chain->node->identifier, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->node->sig_key->pub_data, test_chain->node->sig_key->pub_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->node->signature->sig_data, test_chain->node->signature->sig_data, NULL));
        SHOULD_EQUAL(deserialized->node->type, test_chain->node->type);
        
        wickr_buffer_destroy(&serialized);
        wickr_identity_chain_destroy(&deserialized);
    }
    END_IT
    
    IT("can be validated")
    {
        SHOULD_BE_TRUE(wickr_identity_chain_validate(test_chain, &engine));
        SHOULD_EQUAL(test_chain->status, IDENTITY_CHAIN_STATUS_UNKNOWN);
        
        wickr_buffer_t *identifier = engine.wickr_crypto_engine_crypto_random(IDENTIFIER_LEN);
        wickr_ec_key_t *sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        wickr_ecdsa_result_t *signature = engine.wickr_crypto_engine_ec_sign(sig_key, identifier, DIGEST_SHA_512);
        
        wickr_identity_t *bad_node = wickr_identity_create(IDENTITY_TYPE_NODE, identifier, sig_key, signature);
        SHOULD_NOT_BE_NULL(bad_node);
        
        wickr_identity_destroy(&test_chain->node);
        test_chain->node = bad_node;
        
        SHOULD_BE_FALSE(wickr_identity_chain_validate(test_chain, &engine));
        SHOULD_EQUAL(test_chain->status, IDENTITY_CHAIN_STATUS_UNKNOWN);
    }
    END_IT
    
    wickr_identity_chain_destroy(&test_chain);
    SHOULD_BE_NULL(test_chain);
}
END_DESCRIBE
