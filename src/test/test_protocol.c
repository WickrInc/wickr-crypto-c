#include "cspec.h"

#include "crypto_engine.h"
#include "protocol.h"
#include "cipher.h"
#include "externs.h"
#include "util.h"

#include <limits.h>
#include <string.h>
#include <stdio.h>

// Packet Meta Testing
DESCRIBE(wickr_packet_meta, "protocol: wickr_packet_meta")
{
    wickr_ephemeral_info_t ephemeral = { 3600, 3600 };
    char *channelTag = "THIS IS A CHANNEL TAG";
    wickr_buffer_t *channelTagBfr = wickr_buffer_create((uint8_t*)channelTag, strlen(channelTag));
    wickr_packet_meta_t *packetMeta = wickr_packet_meta_create(ephemeral, channelTagBfr, 6001);

    IT( "Packet Meta should not be NULL" )
    {
        SHOULD_NOT_BE_NULL(packetMeta)
    }
    END_IT
    
    if (packetMeta != NULL) {
        IT( "Copy Packet Meta should compare to be equal")
        {
            wickr_packet_meta_t *copiedPacketMeta = wickr_packet_meta_copy(packetMeta);
            SHOULD_NOT_BE_NULL(copiedPacketMeta)
            if (copiedPacketMeta != NULL) {
                SHOULD_EQUAL(packetMeta->content_type, copiedPacketMeta->content_type)
                SHOULD_EQUAL(packetMeta->channel_tag->length, copiedPacketMeta->channel_tag->length)
                if (packetMeta->channel_tag->length == copiedPacketMeta->channel_tag->length) {
                    SHOULD_EQUAL(memcmp(packetMeta->channel_tag->bytes, copiedPacketMeta->channel_tag->bytes, packetMeta->channel_tag->length), 0)
                }
                wickr_packet_meta_destroy(&copiedPacketMeta);
                SHOULD_BE_NULL(copiedPacketMeta)
            }
            wickr_packet_meta_destroy(&packetMeta);
            SHOULD_BE_NULL(packetMeta)
        }
        END_IT
    }
}
END_DESCRIBE

static void testKeyExchange(wickr_key_exchange_t **keyExchange)
{
    IT( "Copy Key Exchange should compare to be equal")
    {
        wickr_key_exchange_t *copiedKeyExchange = wickr_key_exchange_copy(*keyExchange);
        SHOULD_NOT_BE_NULL(copiedKeyExchange)
        if (copiedKeyExchange != NULL) {
            SHOULD_EQUAL((*keyExchange)->ephemeral_key_id, copiedKeyExchange->ephemeral_key_id)
            SHOULD_EQUAL((*keyExchange)->node_id->length, copiedKeyExchange->node_id->length)
            if ((*keyExchange)->node_id->length == copiedKeyExchange->node_id->length) {
                SHOULD_EQUAL(memcmp((*keyExchange)->node_id->bytes,
                                    copiedKeyExchange->node_id->bytes,
                                    (*keyExchange)->node_id->length), 0)
            }
            SHOULD_EQUAL((*keyExchange)->exchange_data->length, copiedKeyExchange->exchange_data->length)
            if ((*keyExchange)->exchange_data->length == copiedKeyExchange->exchange_data->length) {
                SHOULD_EQUAL(memcmp((*keyExchange)->exchange_data->bytes,
                                    copiedKeyExchange->exchange_data->bytes,
                                    (*keyExchange)->exchange_data->length), 0)
            }
            wickr_key_exchange_destroy(&copiedKeyExchange);
            SHOULD_BE_NULL(copiedKeyExchange)
        }
        
    }
    END_IT
}

// Key Exchange Testing
DESCRIBE(wickr_key_exchange, "protocol: wickr_key_exchange")
{
    initTest();

    uint64_t ephemeralKeyId = 1234567890;
    
    wickr_buffer_t *nodeIDBfr = engine.wickr_crypto_engine_crypto_random(32);
    wickr_buffer_t *exchangeDataBfr = engine.wickr_crypto_engine_crypto_random(128);
    wickr_key_exchange_t *keyExchange = wickr_key_exchange_create(nodeIDBfr, ephemeralKeyId, exchangeDataBfr);
    
    IT( "wickr_key_exchange_create should not return NULL" )
    {
        SHOULD_NOT_BE_NULL(keyExchange)
    }
    END_IT
    
    if (keyExchange != NULL) {
        testKeyExchange(&keyExchange);
        wickr_key_exchange_destroy(&keyExchange);
    }
    
    wickr_cipher_key_t *pktKey = engine.wickr_crypto_engine_cipher_key_random(CIPHER_AES256_CTR);
    wickr_identity_chain_t *sender_identity = createIdentityChain("Alice");
    wickr_ec_key_t *exchange_key = engine.wickr_crypto_engine_ec_rand_key(engine.default_curve);
    wickr_node_t *receiver = createUserNode("Bob", engine.wickr_crypto_engine_crypto_random(32));
    
    keyExchange = wickr_key_exchange_create_with_packet_key(&engine, sender_identity, receiver, exchange_key, pktKey, CURRENT_PACKET_VERSION);
    
    
    IT( "Create Key Exchange From Components should not return NULL")
    {
        SHOULD_NOT_BE_NULL(keyExchange)
    }
    END_IT
    
    if (keyExchange != NULL) {
        testKeyExchange(&keyExchange);
        wickr_key_exchange_destroy(&keyExchange);
    }
    
    IT("should work with valid older version exchanges")
    {
        for (uint8_t i = OLDEST_PACKET_VERSION; i <= CURRENT_PACKET_VERSION; i++) {
            wickr_key_exchange_t *exchange =  wickr_key_exchange_create_with_packet_key(&engine, sender_identity, receiver, exchange_key, pktKey, i);
            
            wickr_cipher_key_t *cipher_key = wickr_key_exchange_derive_packet_key(&engine, sender_identity, receiver, exchange_key, exchange, i);
            
            SHOULD_BE_TRUE(wickr_buffer_is_equal(cipher_key->key_data, pktKey->key_data, NULL));
            SHOULD_EQUAL(cipher_key->cipher.cipher_id, pktKey->cipher.cipher_id);
            SHOULD_EQUAL(cipher_key->cipher.is_authenticated, pktKey->cipher.is_authenticated);
            SHOULD_EQUAL(cipher_key->cipher.auth_tag_len, pktKey->cipher.auth_tag_len);
            SHOULD_EQUAL(cipher_key->cipher.key_len, pktKey->cipher.key_len);
            SHOULD_EQUAL(cipher_key->cipher.iv_len, pktKey->cipher.iv_len);
            wickr_cipher_key_destroy(&cipher_key);
            
            wickr_key_exchange_destroy(&exchange);
        }
        
    }
    END_IT
    
    IT("should be able to derive a packet key from an existing exchange")
    {
        keyExchange =  wickr_key_exchange_create_with_packet_key(&engine, sender_identity, receiver, exchange_key, pktKey, CURRENT_PACKET_VERSION);

        wickr_cipher_key_t *cipher_key = wickr_key_exchange_derive_packet_key(&engine, sender_identity, receiver, exchange_key, keyExchange, CURRENT_PACKET_VERSION);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(cipher_key->key_data, pktKey->key_data, NULL));
        SHOULD_EQUAL(cipher_key->cipher.cipher_id, pktKey->cipher.cipher_id);
        SHOULD_EQUAL(cipher_key->cipher.is_authenticated, pktKey->cipher.is_authenticated);
        SHOULD_EQUAL(cipher_key->cipher.auth_tag_len, pktKey->cipher.auth_tag_len);
        SHOULD_EQUAL(cipher_key->cipher.key_len, pktKey->cipher.key_len);
        SHOULD_EQUAL(cipher_key->cipher.iv_len, pktKey->cipher.iv_len);
        wickr_cipher_key_destroy(&cipher_key);
    }
    END_IT
    
    IT("should fail to derive a packet key given an incorrect dev id")
    {
        wickr_buffer_t *incorrect_dev_id = engine.wickr_crypto_engine_crypto_random(32);
        
        wickr_node_t *receiver_copy = wickr_node_copy(receiver);
        wickr_buffer_destroy_zero(&receiver_copy->dev_id);
        receiver_copy->dev_id = incorrect_dev_id;
        
        wickr_cipher_key_t *cipher_key = wickr_key_exchange_derive_packet_key(&engine, sender_identity, receiver_copy, exchange_key, keyExchange, CURRENT_PACKET_VERSION);
        
        wickr_node_destroy(&receiver_copy);
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(cipher_key ? cipher_key->key_data : NULL, pktKey->key_data, NULL));
    }
    END_IT
    
    IT("should fail to derive a packet key given an incorrect local key")
    {
        wickr_ec_key_t *incorrect_local_key = engine.wickr_crypto_engine_ec_rand_key(engine.default_curve);
        
        wickr_node_t *receiver_copy = wickr_node_copy(receiver);
        wickr_ec_key_destroy(&receiver_copy->ephemeral_keypair->ec_key);
        receiver_copy->ephemeral_keypair->ec_key = incorrect_local_key;
        
        wickr_cipher_key_t *cipher_key = wickr_key_exchange_derive_packet_key(&engine, sender_identity, receiver_copy, exchange_key, keyExchange, CURRENT_PACKET_VERSION);

        wickr_node_destroy(&receiver_copy);
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(cipher_key ? cipher_key->key_data : NULL, pktKey->key_data, NULL));
        
    }
    END_IT
    
    IT("should fail to derive a packet key given an incorrect remote key")
    {
        wickr_ec_key_t *incorrect_remote_key = engine.wickr_crypto_engine_ec_rand_key(engine.default_curve);
        wickr_buffer_destroy_zero(&incorrect_remote_key->pri_data);
        wickr_cipher_key_t *cipher_key = wickr_key_exchange_derive_packet_key(&engine, sender_identity, receiver, incorrect_remote_key, keyExchange, CURRENT_PACKET_VERSION);
        wickr_ec_key_destroy(&incorrect_remote_key);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(cipher_key ? cipher_key->key_data : NULL, pktKey->key_data, NULL));
    }
    END_IT
    
    IT("should fail to derive a packet key given an incorrect local root signing key")
    {
        wickr_ec_key_t *incorrect_local_key = engine.wickr_crypto_engine_ec_rand_key(engine.default_curve);
        
        wickr_node_t *receiver_copy = wickr_node_copy(receiver);
        wickr_ec_key_destroy(&receiver_copy->id_chain->root->sig_key);
        receiver_copy->id_chain->root->sig_key = incorrect_local_key;
        
        wickr_cipher_key_t *cipher_key = wickr_key_exchange_derive_packet_key(&engine, sender_identity, receiver_copy, exchange_key, keyExchange, CURRENT_PACKET_VERSION);
        
        wickr_node_destroy(&receiver_copy);
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(cipher_key ? cipher_key->key_data : NULL, pktKey->key_data, NULL));
        
    }
    END_IT
    
    IT("should fail to derive a packet key given an incorrect remote root signing key")
    {
        wickr_ec_key_t *incorrect_remote_key = engine.wickr_crypto_engine_ec_rand_key(engine.default_curve);
        wickr_buffer_destroy_zero(&incorrect_remote_key->pri_data);
        
        wickr_identity_chain_t *sender_copy = wickr_identity_chain_copy(sender_identity);
        wickr_ec_key_destroy(&sender_copy->root->sig_key);
        sender_copy->root->sig_key = incorrect_remote_key;
        
        wickr_cipher_key_t *cipher_key = wickr_key_exchange_derive_packet_key(&engine, sender_copy, receiver, exchange_key, keyExchange, CURRENT_PACKET_VERSION);
        wickr_identity_chain_destroy(&sender_copy);
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(cipher_key ? cipher_key->key_data : NULL, pktKey->key_data, NULL));
        wickr_cipher_key_destroy(&cipher_key);
    }
    END_IT
    
    IT("should fail if the version is not compatible with the input")
    {
        for (uint8_t i = OLDEST_PACKET_VERSION; i < CURRENT_PACKET_VERSION; i++) {
            wickr_cipher_key_t *cipher_key = wickr_key_exchange_derive_packet_key(&engine, sender_identity, receiver, exchange_key, keyExchange, i);
            SHOULD_BE_FALSE(wickr_buffer_is_equal(cipher_key ? cipher_key->key_data : NULL, pktKey->key_data, NULL));
        }
    }
    END_IT
    
    
    wickr_cipher_key_destroy(&pktKey);
    wickr_key_exchange_destroy(&keyExchange);
    SHOULD_BE_NULL(keyExchange)
    
    wickr_identity_chain_destroy(&sender_identity);
    wickr_ec_key_destroy(&exchange_key);
    wickr_node_destroy(&receiver);
    
}
END_DESCRIBE

wickr_buffer_t *
createNodeID(char *baseString, int count)
{
    char nodeID[200];
    sprintf(nodeID, "%s %d", baseString, count);
    return wickr_buffer_create((uint8_t*)nodeID, strlen(nodeID));
}

wickr_exchange_array_t *
createRandomExchangeArray(uint32_t count, char *nodeBaseStr)
{
    wickr_exchange_array_t *exchArray;
    bool wickr_array_set_item_succeded = true;
    
    IT( "wickr_exchange_arraynew should return array" ) {
        SHOULD_NOT_BE_NULL(exchArray = wickr_exchange_array_new(count))
    } END_IT
    
    if (exchArray != NULL) {
        for (int i=0; i<count; i++) {
            uint64_t ephemeralKeyId = 1000000 + i;
            wickr_buffer_t *nodeIDBfr = createNodeID(nodeBaseStr, i);
            wickr_buffer_t *exchangeDataBfr = engine.wickr_crypto_engine_crypto_random(128);
            
            // Create the key exchange
            wickr_key_exchange_t *keyExchange = wickr_key_exchange_create(nodeIDBfr, ephemeralKeyId, exchangeDataBfr);
            if (!wickr_array_set_item(exchArray, i, keyExchange, false)) {
                wickr_array_set_item_succeded = false;
            }
        }
        
        IT( "wickr_exchange_array set item should return true!") {
            SHOULD_BE_TRUE(wickr_array_set_item_succeded)
        } END_IT
    }
    
    return exchArray;
}

// Exchange Array Testing
DESCRIBE(wickr_exchange_array, "protocol: wickr_exchange_array")
{
    wickr_exchange_array_t *exchanges;
    
    int count = 8;
    for (int i=0; i<8; i++) {
        exchanges = createRandomExchangeArray(count, "NODEID: exchange_array:");
        if (exchanges != NULL) {
            wickr_exchange_array_destroy(&exchanges);
            IT("wickr_exchange_array_destroy should clear local pointer") {
                SHOULD_BE_NULL(exchanges)
            } END_IT
        }
        count >>= 1;
    }
}
END_DESCRIBE

wickr_packet_header_t *
createPacketHeader(int exchCount, char *nodeIDBaseString)
{
    wickr_exchange_array_t *exchanges = createRandomExchangeArray(exchCount, nodeIDBaseString);
    wickr_ec_key_t *senderPub = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
    
    wickr_packet_header_t *pktHdr = wickr_packet_header_create(senderPub, exchanges);
    return pktHdr;
}

// Packet Header Testing
DESCRIBE(wickr_packet_header, "protocol: wickr_packet_header")
{
    initTest();
    
    int exchCount = 30;
    char *nodeIDString = "NODEID: packet_header: CreateTest:";
    wickr_packet_header_t *pktHdr = createPacketHeader(exchCount, nodeIDString);
    
    IT( "wickr_packet_header_create should not return NULL" )
    {
        SHOULD_NOT_BE_NULL(pktHdr)
    }
    END_IT
    
    // Test wickr_packet_header_find
    bool wickr_packet_header_find_succeeded = true;
    for (int i=0; i<exchCount; i++) {
        wickr_buffer_t *nodeIDBfr = createNodeID(nodeIDString, i);
        
        wickr_key_exchange_t *foundKeyExchange = wickr_packet_header_find(pktHdr, nodeIDBfr);
        wickr_buffer_destroy(&nodeIDBfr);
        
        if (! foundKeyExchange) {
            wickr_packet_header_find_succeeded = false;
        }
        wickr_key_exchange_destroy(&foundKeyExchange);
    }
    IT("wickr_packet_header_find() should return valid Key Exchange") {
        SHOULD_BE_TRUE(wickr_packet_header_find_succeeded)
    } END_IT
    
    // Test wickr_packet_header_copy
    if (pktHdr != NULL) {
        wickr_packet_header_t *pktHdrCopy = wickr_packet_header_copy(pktHdr);
        
        IT("wickr_packet_header_copy() should return valid Packet Header") {
            SHOULD_NOT_BE_NULL(pktHdrCopy)
            if (pktHdrCopy != NULL) {
                SHOULD_NOT_EQUAL(pktHdr, pktHdrCopy)
                SHOULD_NOT_EQUAL(pktHdr->exchanges, pktHdrCopy->exchanges)
                SHOULD_NOT_EQUAL(pktHdr->sender_pub, pktHdrCopy->sender_pub)
                
                //Compare the contents of the sender_pub
                if (pktHdr->sender_pub != NULL) {
                    SHOULD_EQUAL(memcmp(&pktHdr->sender_pub->curve,
                                        &pktHdrCopy->sender_pub->curve,
                                        sizeof(pktHdr->sender_pub->curve)), 0)
                    //Compare the contents of the public data
                    
                    SHOULD_BE_TRUE(wickr_buffer_is_equal(pktHdr->sender_pub->pub_data, pktHdrCopy->sender_pub->pub_data, NULL));
                    
                }
            }
        } END_IT
        
        // Test the destroy of the pkt header
        if (pktHdrCopy != NULL) {
            IT("wickr_packet_header_destroy() should clean up memory") {
                wickr_packet_header_destroy(&pktHdrCopy);
                
                SHOULD_BE_NULL(pktHdrCopy)
            } END_IT
        }
        
    }
    
    // Test wickr_packet_header_serialize
    if (pktHdr != NULL) {
        IT("wickr_packet_header_encrypt() should not return NULL") {
            wickr_cipher_key_t *hdrKey = engine.wickr_crypto_engine_cipher_key_random(CIPHER_AES256_GCM);
            wickr_cipher_result_t *result;
            
            SHOULD_NOT_BE_NULL(result = wickr_packet_header_encrypt(pktHdr, &engine, hdrKey))
            wickr_cipher_result_destroy(&result);
            wickr_cipher_key_destroy(&hdrKey);
            
        } END_IT
    }
    
    wickr_packet_header_destroy(&pktHdr);
    SHOULD_BE_NULL(pktHdr);

}
END_DESCRIBE

static wickr_cipher_key_t *__gen_test_header_key(const wickr_crypto_engine_t engine, wickr_cipher_t cipher, const wickr_identity_chain_t *id_chain)
{
    return wickr_cipher_key_create(cipher, wickr_buffer_create_empty_zero(cipher.key_len));
}

static wickr_cipher_key_t *__gen_test_rand_header_key(const wickr_crypto_engine_t engine, wickr_cipher_t cipher, const wickr_identity_chain_t *id_chain)
{
    return engine.wickr_crypto_engine_cipher_key_random(cipher);
}

DESCRIBE(wickr_packet_create_from_components, "protocol: wickr_packet_create_from_components")
{
    initTest();
    
    wickr_cipher_key_t *headerKey = __gen_test_header_key(engine, engine.default_cipher, NULL);
    wickr_cipher_key_t *payloadKey = engine.wickr_crypto_engine_cipher_key_random(engine.default_cipher);
    wickr_ec_key_t *exchangeKey = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);

    wickr_ephemeral_info_t ephemeralData = { 64000, 3600 };
    wickr_buffer_t *channelTag = engine.wickr_crypto_engine_crypto_random(32);
    uint16_t contentType = 3000;
    wickr_packet_meta_t *metaData = wickr_packet_meta_create(ephemeralData, channelTag, contentType);

    char *body = "THIS IS THE BODY OF THE MESSAGE";
    wickr_buffer_t *bodyData = wickr_buffer_create((uint8_t*)body, strlen(body));
    wickr_payload_t *payload = wickr_payload_create(metaData, bodyData);

    // Create the recipients
    wickr_node_array_t *recipients = wickr_node_array_new(1);

    // Create user 1
    char *dev1Str = "ALICEDEVICE";
    wickr_buffer_t *devID1 = createDeviceIdentity((uint8_t*)dev1Str, strlen(dev1Str));
    wickr_node_t *user1Node = createUserNode("alice@wickr.com", devID1);

    wickr_node_array_set_item(recipients, 0, user1Node);

    // Create user 2
    char *dev2Str = "BOBDEVICE";
    wickr_buffer_t *devID2 = createDeviceIdentity((uint8_t*)dev2Str, strlen(dev2Str));
    wickr_node_t *user2Node = createUserNode("bob@wickr.com", devID2);

    wickr_packet_t *pkt = NULL;
    

    IT( "Packet should not be NULL" )
    {
        pkt = wickr_packet_create_from_components(&engine,
                                            headerKey,
                                            payloadKey,
                                            exchangeKey,
                                            payload,
                                            recipients,
                                            user2Node->id_chain,
                                            CURRENT_PACKET_VERSION);
        
        
        
        SHOULD_NOT_BE_NULL(pkt)
        
        wickr_packet_t *pkt_copy = wickr_packet_copy(pkt);
        
        SHOULD_NOT_BE_NULL(pkt_copy);
        SHOULD_NOT_EQUAL(pkt, pkt_copy);
        SHOULD_NOT_EQUAL(pkt->content, pkt_copy->content);
        SHOULD_NOT_EQUAL(pkt->signature, pkt_copy->signature);
        SHOULD_EQUAL(pkt->version, pkt_copy->version);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(pkt_copy->content, pkt->content, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(pkt_copy->signature->sig_data, pkt->signature->sig_data, NULL));

        wickr_packet_destroy(&pkt_copy);
    }
    END_IT
    
    IT ("should fail to create a packet using a failed identity status")
    {
        wickr_node_t *first_recipient = wickr_node_array_fetch_item(recipients, 0);
        first_recipient->id_chain->status = IDENTITY_CHAIN_STATUS_INVALID;
        
        wickr_packet_t *bad_packet = wickr_packet_create_from_components(&engine, headerKey, payloadKey, exchangeKey, payload, recipients, user2Node->id_chain, CURRENT_PACKET_VERSION);
        SHOULD_BE_NULL(bad_packet);
    }
    END_IT
    
    IT("should fail to create a packet using an invalid recipient ephemeral keypair")
    {
        wickr_node_array_t *recipients_copy = wickr_node_array_copy(recipients);
        wickr_node_t *first_recipient = wickr_node_array_fetch_item(recipients_copy, 0);
        
        wickr_buffer_t *random_data = engine.wickr_crypto_engine_crypto_random(64);
        
        wickr_ecdsa_result_destroy(&first_recipient->ephemeral_keypair->signature);
        
        first_recipient->ephemeral_keypair->signature = wickr_identity_sign(first_recipient->id_chain->node, &engine, random_data);
        wickr_buffer_destroy(&random_data);

        wickr_packet_t *bad_packet = wickr_packet_create_from_components(&engine, headerKey, payloadKey, exchangeKey, payload, recipients_copy, user2Node->id_chain, CURRENT_PACKET_VERSION);
        SHOULD_BE_NULL(bad_packet);
        
        /* Force a valid identity chain state, make sure it still fails */
        first_recipient->id_chain->status = IDENTITY_CHAIN_STATUS_VALID;
        
        bad_packet = wickr_packet_create_from_components(&engine, headerKey, payloadKey, exchangeKey, payload, recipients_copy, user2Node->id_chain, CURRENT_PACKET_VERSION);
        SHOULD_BE_NULL(bad_packet);
        
        wickr_array_destroy(&recipients_copy, true);
    }
    END_IT
    
    IT("should fail to create a packet using an invalid recipient signature")
    {
        wickr_node_array_t *recipients_copy = wickr_node_array_copy(recipients);
        wickr_node_t *first_recipient = wickr_node_array_fetch_item(recipients_copy, 0);
        
        wickr_buffer_t *random_data = engine.wickr_crypto_engine_crypto_random(64);
        
        wickr_ecdsa_result_destroy(&first_recipient->id_chain->node->signature);
        
        first_recipient->id_chain->node->signature = wickr_identity_sign(first_recipient->id_chain->node, &engine, random_data);
        wickr_buffer_destroy(&random_data);
        
        wickr_packet_t *bad_packet = wickr_packet_create_from_components(&engine, headerKey, payloadKey, exchangeKey, payload, recipients_copy, user2Node->id_chain, CURRENT_PACKET_VERSION);
        SHOULD_BE_NULL(bad_packet);
        
        wickr_array_destroy(&recipients_copy, true);
    }
    END_IT
    
    wickr_ec_key_destroy(&exchangeKey);
    wickr_cipher_key_destroy(&headerKey);
    wickr_cipher_key_destroy(&payloadKey);
    wickr_node_array_destroy(&recipients);
    
    IT( "should be able to be serialized")
    {
        SHOULD_BE_NULL(wickr_packet_serialize(NULL));
        wickr_buffer_t *pkt_buffer = wickr_packet_serialize(pkt);
        SHOULD_NOT_BE_NULL(pkt_buffer);
        
        wickr_packet_t *pkt_restored = wickr_packet_create_from_buffer(pkt_buffer);
        SHOULD_NOT_BE_NULL(pkt_restored);
        SHOULD_EQUAL(pkt_restored->version, pkt->version);
        SHOULD_EQUAL(pkt_restored->version, CURRENT_PACKET_VERSION);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(pkt_restored->content, pkt->content, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(pkt_restored->signature->sig_data, pkt->signature->sig_data, NULL));
        SHOULD_EQUAL(pkt_restored->signature->curve.identifier, pkt->signature->curve.identifier);
        SHOULD_EQUAL(pkt_restored->signature->digest_mode.digest_id, pkt->signature->digest_mode.digest_id);
        wickr_packet_destroy(&pkt_restored);
        wickr_buffer_destroy(&pkt_buffer);
    }
    END_IT
    
    IT( "should fail parsing if the wrong node id is presented" )
    {
        wickr_parse_result_t *parse_result = wickr_parse_result_from_packet(&engine, pkt, user2Node->id_chain->node->identifier, __gen_test_header_key, user2Node->id_chain);
        SHOULD_NOT_BE_NULL(parse_result);
        SHOULD_EQUAL(parse_result->err, ERROR_NODE_NOT_FOUND);
        SHOULD_EQUAL(parse_result->signature_status, PACKET_SIGNATURE_VALID);
        SHOULD_BE_NULL(parse_result->enc_payload);
        SHOULD_BE_NULL(parse_result->header);
        SHOULD_BE_NULL(parse_result->key_exchange);
        
        wickr_parse_result_t *copy_result = wickr_parse_result_copy(parse_result);
        SHOULD_NOT_BE_NULL(copy_result);
        SHOULD_EQUAL(copy_result->err, parse_result->err);
        SHOULD_EQUAL(copy_result->signature_status, parse_result->signature_status);
        wickr_parse_result_destroy(&copy_result);
        
        wickr_parse_result_destroy(&parse_result);
    }
    END_IT
    
    IT( "should fail parsing if the wrong sender signing identity is presented" )
    {
        wickr_parse_result_t *parse_result = wickr_parse_result_from_packet(&engine, pkt, user1Node->id_chain->node->identifier, __gen_test_header_key, user1Node->id_chain);
        SHOULD_NOT_BE_NULL(parse_result);
        SHOULD_EQUAL(parse_result->err, ERROR_MAC_INVALID);
        SHOULD_EQUAL(parse_result->signature_status, PACKET_SIGNATURE_INVALID);
        SHOULD_BE_NULL(parse_result->enc_payload);
        SHOULD_BE_NULL(parse_result->header);
        SHOULD_BE_NULL(parse_result->key_exchange);
        wickr_parse_result_destroy(&parse_result);
    }
    END_IT
    
    IT ("should fail parsing if the wrong header key is presented")
    {
        wickr_cipher_key_t *rand_key = engine.wickr_crypto_engine_cipher_key_random(engine.default_cipher);
        wickr_parse_result_t *parse_result = wickr_parse_result_from_packet(&engine, pkt, user1Node->id_chain->node->identifier, __gen_test_rand_header_key, user2Node->id_chain);
        SHOULD_NOT_BE_NULL(parse_result);
        SHOULD_EQUAL(parse_result->err, ERROR_CORRUPT_PACKET);
        SHOULD_EQUAL(parse_result->signature_status, PACKET_SIGNATURE_VALID);
        SHOULD_BE_NULL(parse_result->enc_payload);
        SHOULD_BE_NULL(parse_result->header);
        SHOULD_BE_NULL(parse_result->key_exchange);
        wickr_cipher_key_destroy(&rand_key);
        wickr_parse_result_destroy(&parse_result);
    }
    END_IT
    
    wickr_parse_result_t *parse_result = NULL;

    IT( "should be able to be parsed")
    {
        parse_result = wickr_parse_result_from_packet(&engine, pkt, user1Node->id_chain->node->identifier, __gen_test_header_key, user2Node->id_chain);
        SHOULD_NOT_BE_NULL(parse_result);
        SHOULD_EQUAL(parse_result->err, E_SUCCESS);
        SHOULD_EQUAL(parse_result->signature_status, PACKET_SIGNATURE_VALID);
        SHOULD_NOT_BE_NULL(parse_result->enc_payload);
        SHOULD_NOT_BE_NULL(parse_result->header);
        SHOULD_NOT_BE_NULL(parse_result->key_exchange);
        
        wickr_parse_result_t *copy_result = wickr_parse_result_copy(parse_result);
        SHOULD_NOT_BE_NULL(copy_result);
        SHOULD_EQUAL(copy_result->err, parse_result->err);
        wickr_parse_result_destroy(&copy_result);
    }
    END_IT
    
    IT( "should fail decryption if the wrong key is presented" )
    {
        wickr_ec_key_t *rand_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        wickr_decode_result_t *decode_result = wickr_decode_result_from_parse_result(pkt, &engine, parse_result, user1Node->dev_id, rand_key, user1Node->id_chain, user2Node->id_chain);
        wickr_ec_key_destroy(&rand_key);
        SHOULD_NOT_BE_NULL(decode_result);
        SHOULD_EQUAL(decode_result->err, ERROR_KEY_EXCHANGE_FAILED);
        SHOULD_BE_NULL(decode_result->decrypted_payload);
        SHOULD_BE_NULL(decode_result->payload_key);
        
        wickr_decode_result_t *copy_result = wickr_decode_result_copy(decode_result);
        SHOULD_EQUAL(copy_result->err, decode_result->err);
        SHOULD_BE_NULL(copy_result->decrypted_payload);
        SHOULD_BE_NULL(copy_result->payload_key);
        wickr_decode_result_destroy(&copy_result);
        wickr_decode_result_destroy(&decode_result);
    }
    END_IT
    
    IT( "should ecrypt if the proper key is presented" )
    {
        wickr_decode_result_t *decode_result = wickr_decode_result_from_parse_result(pkt, &engine, parse_result, user1Node->dev_id, user1Node->ephemeral_keypair->ec_key, user1Node->id_chain, user2Node->id_chain);
        SHOULD_NOT_BE_NULL(decode_result);
        SHOULD_NOT_BE_NULL(decode_result->decrypted_payload);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(decode_result->decrypted_payload->body, bodyData, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(decode_result->decrypted_payload->meta->channel_tag, channelTag, NULL));
        SHOULD_BE_TRUE(decode_result->decrypted_payload->meta->content_type == contentType);
        SHOULD_BE_TRUE(decode_result->decrypted_payload->meta->ephemerality_settings.bor == ephemeralData.bor);
        SHOULD_BE_TRUE(decode_result->decrypted_payload->meta->ephemerality_settings.ttl == ephemeralData.ttl);

        wickr_decode_result_t *copy_result = wickr_decode_result_copy(decode_result);
        SHOULD_EQUAL(copy_result->err, decode_result->err);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy_result->decrypted_payload->body, decode_result->decrypted_payload->body, NULL));
        
        wickr_decode_result_destroy(&copy_result);
        wickr_decode_result_destroy(&decode_result);
    }
    END_IT
    
    wickr_payload_destroy(&payload);
    wickr_parse_result_destroy(&parse_result);
    wickr_node_destroy(&user1Node);
    wickr_node_destroy(&user2Node);
    wickr_packet_destroy(&pkt);
    
}
END_DESCRIBE
