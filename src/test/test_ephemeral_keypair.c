
#include "test_ephemeral_keypair.h"
#include "ephemeral_keypair.h"
#include "externs.h"

DESCRIBE(ephemeral_keypair, "ephemeral keypair")
{
    wickr_ephemeral_keypair_t *ephemeral_keypair = NULL;
    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    uint64_t test_id = 42;
    
    IT("should be created when the required fields are passed in")
    {
        wickr_ecdsa_result_t result;
        
        SHOULD_BE_NULL(wickr_ephemeral_keypair_create(0, NULL, NULL));
        SHOULD_BE_NULL(wickr_ephemeral_keypair_create(0, NULL, &result));
        
        ephemeral_keypair = wickr_ephemeral_keypair_create(test_id, engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521), NULL);
        SHOULD_NOT_BE_NULL(ephemeral_keypair);
    }
    END_IT
    
    wickr_identity_chain_t *test_chain = createIdentityChain("alice");
    SHOULD_NOT_BE_NULL(test_chain);
    wickr_ephemeral_keypair_t *id_keypair = NULL;

    IT("should be able to be generated using an identity for signing")
    {
        id_keypair = wickr_ephemeral_keypair_generate_identity(&engine, test_id, test_chain->node);
        SHOULD_NOT_BE_NULL(id_keypair);
        SHOULD_NOT_BE_NULL(id_keypair->ec_key);
        SHOULD_EQUAL(id_keypair->identifier, test_id);
        
        SHOULD_BE_TRUE(engine.wickr_crypto_engine_ec_verify(id_keypair->signature, test_chain->node->sig_key, id_keypair->ec_key->pub_data));
    }
    END_IT
    
    IT("can have it's ownership validated")
    {
        wickr_identity_chain_t *test_invalid = createIdentityChain("bob");
        SHOULD_BE_TRUE(wickr_ephemeral_keypair_verify_owner(id_keypair, &engine, test_chain->node));
        SHOULD_BE_FALSE(wickr_ephemeral_keypair_verify_owner(id_keypair, &engine, test_invalid->node));
        wickr_identity_chain_destroy(&test_invalid);
    }
    END_IT
    
    wickr_identity_chain_destroy(&test_chain);
    wickr_ephemeral_keypair_destroy(&id_keypair);
    
    IT("can can be purged of the private ec_key that it holds")
    {
        wickr_ephemeral_keypair_make_public(ephemeral_keypair);
        SHOULD_BE_NULL(ephemeral_keypair->ec_key->pri_data);
    }
    END_IT
    
    IT("can be serialized / deserialized")
    {
        wickr_buffer_t *serialized = wickr_ephemeral_keypair_serialize(ephemeral_keypair);
        SHOULD_NOT_BE_NULL(serialized);
        
        const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
        wickr_ephemeral_keypair_t *deserialized = wickr_ephemeral_keypair_create_from_buffer(serialized, &engine);
        SHOULD_NOT_BE_NULL(deserialized);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(ephemeral_keypair->ec_key->pub_data, deserialized->ec_key->pub_data, NULL));
        SHOULD_EQUAL(ephemeral_keypair->identifier, deserialized->identifier);
        
        wickr_buffer_destroy(&serialized);
        wickr_ephemeral_keypair_destroy(&deserialized);
    }
    END_IT
    
    IT("can be copied")
    {
        wickr_ephemeral_keypair_t *copied = wickr_ephemeral_keypair_copy(ephemeral_keypair);
        SHOULD_NOT_BE_NULL(copied);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(ephemeral_keypair->ec_key->pub_data, copied->ec_key->pub_data, NULL));
        SHOULD_EQUAL(ephemeral_keypair->identifier, copied->identifier);
        wickr_ephemeral_keypair_destroy(&copied);

    }
    END_IT
    
    wickr_ephemeral_keypair_destroy(&ephemeral_keypair);
    SHOULD_BE_NULL(ephemeral_keypair);
}
END_DESCRIBE
