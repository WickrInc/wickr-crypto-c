#include "cspec.h"
#include "externs.h"
#include "test_buffer.h"
#include "crypto_engine.h"
#include "wickr_ctx.h"
#include "ephemeral_keypair.h"
#include "util.h"

#include <string.h>

wickr_crypto_engine_t engine;
wickr_buffer_t *devSalt = NULL;

static uint64_t curIdentifier = 1;


void
initTest()
{
    engine = wickr_crypto_engine_get_default();
    
    // Setup SALT for user names
    if (devSalt == NULL) {
        devSalt = engine.wickr_crypto_engine_crypto_random(SCRYPT_SALT_SIZE);
    }
}

wickr_buffer_t *
hex_char_to_buffer(const char *hex)
{
    wickr_buffer_t hex_buf = { strlen(hex), (uint8_t *)hex };
    return getDataFromHexString(&hex_buf);
}

wickr_dev_info_t *
createDevInfo(wickr_buffer_t *systemID)
{
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    wickr_dev_info_t *devInfo = wickr_dev_info_create_new(&engine, systemID);
    
    return devInfo;
}

wickr_ctx_t *
createContext(wickr_node_t *userNode)
{
    wickr_dev_info_t *devInfo = createDevInfo(userNode->dev_id);
    
    wickr_cipher_key_t *localKey = engine.wickr_crypto_engine_cipher_key_random(engine.default_cipher);
    wickr_cipher_key_t *remoteKey = engine.wickr_crypto_engine_cipher_key_random(engine.default_cipher);
    wickr_storage_keys_t *storageKeys = wickr_storage_keys_create(localKey, remoteKey);
    
    wickr_ctx_t *ctx;
    SHOULD_NOT_BE_NULL(ctx = wickr_ctx_create(engine, devInfo, wickr_identity_chain_copy(userNode->id_chain), storageKeys))
    
    return ctx;
}


wickr_buffer_t *
createDeviceIdentity(uint8_t *devStr, size_t devLen)
{
    wickr_buffer_t *devIDBuffer = wickr_buffer_create(devStr, devLen);
    return devIDBuffer;
}

wickr_ephemeral_keypair_t *
generateKeypair(wickr_identity_t *identity)
{
    engine = wickr_crypto_engine_get_default();
    
    wickr_ec_key_t *key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    wickr_ecdsa_result_t *signature = wickr_identity_sign(identity, &engine, key->pub_data);
    wickr_ephemeral_keypair_t *keypair = wickr_ephemeral_keypair_create(curIdentifier++, key, signature);
    
    return keypair;
}

wickr_identity_chain_t *
createIdentityChain(char *userName)
{
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    
    wickr_buffer_t *userNameBuffer = wickr_buffer_create((uint8_t*)userName, strlen(userName));
    
    // Generate Hash of the user name
    wickr_buffer_t *userDigest = engine.wickr_crypto_engine_digest(userNameBuffer, devSalt, DIGEST_SHA_256);
    wickr_buffer_destroy(&userNameBuffer);
    
    wickr_ec_key_t *key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    
    wickr_identity_t *rootIdentity = wickr_identity_create(IDENTITY_TYPE_ROOT, userDigest, key, NULL);
    
    wickr_identity_t *nodeIdentity = wickr_node_identity_gen(&engine, rootIdentity);
    
    return wickr_identity_chain_create(rootIdentity, nodeIdentity);
}

wickr_node_t *
createUserNode(char *userName, wickr_buffer_t *devID)
{
    wickr_identity_chain_t *id_chain = createIdentityChain(userName);
    wickr_ephemeral_keypair_t *keypair = generateKeypair(id_chain->node);
    wickr_node_t *userNode = wickr_node_create(devID, id_chain, keypair);
    
    return userNode;
}

