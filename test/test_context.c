#include "cspec.h"
#include "test_buffer.h"
#include "externs.h"
#include "crypto_engine.h"
#include "wickr_ctx.h"
#include "encoder_result.h"

#include <string.h>

/*
 * Test the different functions that create the wickr_ctx_gen_result_t, including the following:
 *   - wickr_ctx_gen_new
 *   - wickr_ctx_gen_with_passphrase
 *   - wickr_ctx_gen_with_recovery
 *   - wickr_ctx_gen_with_root_keys
 */
DESCRIBE(wickr_ctx_generate, "wickr_ctx: test generation")
{
    initTest();

    wickr_ctx_gen_result_t *result;
    
    char *systemName = "SYSTEM_NAME_FOR_CONTEXT_TEST";
    wickr_buffer_t *devBuf = wickr_buffer_create((uint8_t *)systemName, strlen(systemName));
    wickr_dev_info_t *devInfo = createDevInfo(devBuf);
    
    wickr_buffer_t *rand_id = engine.wickr_crypto_engine_crypto_random(IDENTIFIER_LEN);
    
    IT("can be generated with devInfo and an id")
    {
        SHOULD_NOT_BE_NULL(result = wickr_ctx_gen_new(engine, devInfo, rand_id))
    }
    END_IT

    IT("should be able to make a copy of itself")
    {
        wickr_ctx_gen_result_t *copyResult;
        
        SHOULD_NOT_BE_NULL(copyResult = wickr_ctx_gen_result_copy(result))
        if (copyResult != NULL) {
            wickr_ctx_gen_result_destroy(&copyResult);
            SHOULD_BE_NULL(copyResult)
        }
    }
    END_IT
    
    IT("can be generated with devInfo and specified root keys")
    {
        wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
        wickr_root_keys_t *keys = wickr_root_keys_generate(&engine);
        
        SHOULD_NOT_BE_NULL(keys);
        
        wickr_ctx_gen_result_t *root_key_result = wickr_ctx_gen_with_root_keys(engine, devInfo, keys, rand_id);
        
        SHOULD_NOT_BE_NULL(root_key_result);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(root_key_result->root_keys->node_storage_root->key_data, keys->node_storage_root->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(root_key_result->root_keys->remote_storage_root->key_data, keys->remote_storage_root->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(root_key_result->root_keys->node_signature_root->pri_data, keys->node_signature_root->pri_data, NULL));

        wickr_ctx_gen_result_destroy(&root_key_result);
        wickr_root_keys_destroy(&keys);
        
        SHOULD_BE_NULL(root_key_result);
    }
    END_IT
    
    IT("can be generated with a specified signing key")
    {
        wickr_ec_key_t *sig_key = engine.wickr_crypto_engine_ec_rand_key(engine.default_curve);
        SHOULD_NOT_BE_NULL(sig_key);
        
        wickr_ctx_gen_result_t *sig_key_result = wickr_ctx_gen_new_with_sig_key(engine, devInfo, sig_key, rand_id);
        
        SHOULD_NOT_BE_NULL(sig_key_result);
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(sig_key_result->root_keys->node_signature_root->pri_data, sig_key->pri_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(sig_key_result->root_keys->node_signature_root->pub_data, sig_key->pub_data, NULL));

        wickr_ctx_gen_result_destroy(&sig_key_result);
        wickr_ec_key_destroy(&sig_key);
    }
    END_IT
    
    char *passPhrase = "password";
    wickr_buffer_t *passPhraseBfr = wickr_buffer_create((uint8_t*)passPhrase, strlen(passPhrase));
    wickr_buffer_t *recovery = NULL;
    
    
    IT("can export an recovery for you")
    {
        recovery = wickr_ctx_gen_result_make_recovery(result);
        SHOULD_NOT_BE_NULL(recovery);
    }
    END_IT
    
    IT("it can be generated with an recovery + recovery key")
    {
        wickr_ctx_gen_result_t *with_recovery_result = NULL;
        
        SHOULD_NOT_BE_NULL(with_recovery_result = wickr_ctx_gen_with_recovery(engine, devInfo, recovery, result->recovery_key, rand_id))
        
        /* Verify that the new context has all the same values as the old one */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_recovery_result->root_keys->node_storage_root->key_data,
                                             result->root_keys->node_storage_root->key_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_recovery_result->root_keys->remote_storage_root->key_data,
                                             result->root_keys->remote_storage_root->key_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_recovery_result->root_keys->node_signature_root->pri_data,
                                             result->root_keys->node_signature_root->pri_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_recovery_result->recovery_key->key_data,
                                             result->recovery_key->key_data, NULL));
        
        if (result != NULL) {
            wickr_ctx_gen_result_t *copyResult;
            
            SHOULD_NOT_BE_NULL(copyResult = wickr_ctx_gen_result_copy(result))
            if (copyResult != NULL) {
                wickr_ctx_gen_result_destroy(&copyResult);
                SHOULD_BE_NULL(copyResult)
            }
        }
        
        if (result != NULL) {
            wickr_ctx_gen_result_t *copyResult;
            
            SHOULD_NOT_BE_NULL(copyResult = wickr_ctx_gen_result_copy(result))
            
            if (copyResult != NULL) {
                wickr_ctx_gen_result_destroy(&copyResult);
                SHOULD_BE_NULL(copyResult)
            }
            wickr_ctx_gen_result_destroy(&with_recovery_result);
            SHOULD_BE_NULL(with_recovery_result)
        }
    }
    END_IT
    
    wickr_buffer_t *exportedEscrowKey = NULL;
    
    IT("can export your recovery key")
    {
        exportedEscrowKey = wickr_ctx_gen_export_recovery_key_passphrase(result, passPhraseBfr);
        SHOULD_NOT_BE_NULL(exportedEscrowKey);
        
        wickr_cipher_key_t *imported = wickr_ctx_gen_import_recovery_key_passphrase(result->ctx->engine, exportedEscrowKey, passPhraseBfr);
        
        SHOULD_NOT_BE_NULL(imported);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(imported->key_data, result->recovery_key->key_data, NULL));
        wickr_cipher_key_destroy(&imported);
    }
    END_IT
    
    IT("can be generated with a passphrase, recovery")
    {
        
        wickr_ctx_gen_result_t *with_passphrase_result = NULL;
        
        SHOULD_NOT_BE_NULL(with_passphrase_result = wickr_ctx_gen_with_passphrase(engine, devInfo, exportedEscrowKey, passPhraseBfr, recovery, rand_id))
        
        /* Verify that the new context has all the same values as the old one */
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_passphrase_result->root_keys->node_storage_root->key_data,
                                             result->root_keys->node_storage_root->key_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_passphrase_result->root_keys->remote_storage_root->key_data,
                                             result->root_keys->remote_storage_root->key_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_passphrase_result->root_keys->node_signature_root->pri_data,
                                             result->root_keys->node_signature_root->pri_data,
                                             NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(with_passphrase_result->recovery_key->key_data,
                                             result->recovery_key->key_data, NULL));
        
        if (result != NULL) {
            wickr_ctx_gen_result_t *copyResult;
            
            SHOULD_NOT_BE_NULL(copyResult = wickr_ctx_gen_result_copy(result))
            if (copyResult != NULL) {
                wickr_ctx_gen_result_destroy(&copyResult);
                SHOULD_BE_NULL(copyResult)
            }
            
            wickr_ctx_gen_result_destroy(&with_passphrase_result);
            SHOULD_BE_NULL(with_passphrase_result)
        }
    }
    END_IT
    
    wickr_buffer_destroy(&exportedEscrowKey);
    wickr_buffer_destroy(&passPhraseBfr);
    wickr_buffer_destroy(&rand_id);
    wickr_dev_info_destroy(&devInfo);
    wickr_buffer_destroy(&devBuf);
    wickr_buffer_destroy(&recovery);
    wickr_ctx_gen_result_destroy(&result);

}
END_DESCRIBE

static void __test_cipher_method(wickr_ctx_t *ctx, int size, int iterations, wickr_cipher_result_t *(*enc_op)(const wickr_ctx_t *ctx, const wickr_buffer_t *buffer), wickr_buffer_t *(*dec_op)(const wickr_ctx_t *ctx, const wickr_cipher_result_t *result))
{
    wickr_buffer_t *rand_data = engine.wickr_crypto_engine_crypto_random(size);
    
    wickr_cipher_result_t *enc_data = enc_op(ctx, rand_data);
    
    SHOULD_NOT_BE_NULL(enc_data);
    SHOULD_BE_FALSE(wickr_buffer_is_equal(enc_data->cipher_text, rand_data, NULL));
    
    for (int i = 0; i < 1000; i++) {
        wickr_cipher_result_t *one_encrypt = enc_op(ctx, rand_data);
        SHOULD_BE_FALSE(wickr_buffer_is_equal(one_encrypt->cipher_text, enc_data->cipher_text, NULL));
        wickr_cipher_result_destroy(&one_encrypt);
    }
    
    wickr_buffer_t *dec_data = dec_op(ctx, enc_data);
    
    SHOULD_NOT_BE_NULL(dec_data);
    SHOULD_BE_TRUE(wickr_buffer_is_equal(dec_data, rand_data, NULL));
    
    wickr_cipher_result_destroy(&enc_data);
    wickr_buffer_destroy(&dec_data);
    wickr_buffer_destroy(&rand_data);

}

void wickr_ctx_verify_equal(wickr_ctx_t *ctx, wickr_ctx_t *deserialized)
{
    SHOULD_NOT_BE_NULL(deserialized);
    
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->id_chain->node->identifier,
                                         ctx->id_chain->node->identifier, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->id_chain->root->sig_key->pri_data,
                                         ctx->id_chain->root->sig_key->pri_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->id_chain->root->identifier,
                                         ctx->id_chain->root->identifier, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->packet_header_key->key_data,
                                         ctx->packet_header_key->key_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->storage_keys->local->key_data,
                                         ctx->storage_keys->local->key_data, NULL));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(deserialized->storage_keys->remote->key_data,
                                         ctx->storage_keys->remote->key_data, NULL));
    SHOULD_EQUAL(deserialized->pkt_enc_version, ctx->pkt_enc_version);
}

DESCRIBE(wickr_ctx_functions, "wickr_ctx: general functions")
{
    initTest();
    
    char *systemName = "SYSTEM_NAME_FOR_CONTEXT_TEST";
    wickr_buffer_t *devBuf = wickr_buffer_create((uint8_t *)systemName, strlen(systemName));
    wickr_dev_info_t *devInfo = createDevInfo(devBuf);
    
    wickr_buffer_t *rand_id = engine.wickr_crypto_engine_crypto_random(IDENTIFIER_LEN);
    
    wickr_ctx_gen_result_t *ctx_res = NULL;
    SHOULD_NOT_BE_NULL(ctx_res = wickr_ctx_gen_new(engine, devInfo, rand_id))

    wickr_ctx_t *ctx = ctx_res->ctx;
    
    IT("can be serialized and deserialized")
    {
        wickr_buffer_t *serialized = wickr_ctx_serialize(ctx);
        SHOULD_NOT_BE_NULL(serialized);
        
        wickr_ctx_t *deserialized = wickr_ctx_create_from_buffer(engine,
                                                                 wickr_dev_info_copy(devInfo),
                                                                 serialized);
        wickr_ctx_verify_equal(ctx, deserialized);
        
        wickr_buffer_destroy(&serialized);
        wickr_ctx_destroy(&deserialized);
    }
    END_IT
    
    IT("can be exported and imported")
    {
        wickr_buffer_t *test_passphrase = engine.wickr_crypto_engine_crypto_random(32);
        wickr_buffer_t *serialized = wickr_ctx_export(ctx, test_passphrase);
        SHOULD_NOT_BE_NULL(serialized);
        
        wickr_ctx_t *deserialized = wickr_ctx_import(engine,
                                                     wickr_dev_info_copy(devInfo),
                                                     serialized,
                                                     test_passphrase);
        
        wickr_ctx_verify_equal(ctx, deserialized);
        
        wickr_buffer_destroy(&serialized);
        wickr_ctx_destroy(&deserialized);
        wickr_buffer_destroy(&test_passphrase);
    }
    END_IT
    
    IT("should be able to export storage keys with a passphrase")
    {
        wickr_buffer_t *rand_pass = engine.wickr_crypto_engine_crypto_random(IDENTIFIER_LEN);
        
        wickr_buffer_t *exported = wickr_ctx_export_storage_keys(ctx, rand_pass);
        
        SHOULD_NOT_BE_NULL(exported);
        
        wickr_storage_keys_t *imported =  wickr_ctx_import_storage_keys(engine, exported, rand_pass);
        
        SHOULD_NOT_BE_NULL(imported);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(imported->local->key_data, ctx->storage_keys->local->key_data, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(imported->remote->key_data, ctx->storage_keys->remote->key_data, NULL));
        
        
        wickr_buffer_destroy(&rand_pass);
        wickr_buffer_destroy(&exported);
        wickr_storage_keys_destroy(&imported);
    }
    END_IT
    
    IT("should be able to encrypt local data with random IVs")
    {
        __test_cipher_method(ctx, 10000, 1000, wickr_ctx_cipher_local, wickr_ctx_decipher_local);
    }
    END_IT
    
    IT("should be able to encrypt remote data with random IVs")
    {
        __test_cipher_method(ctx, 10000, 1000, wickr_ctx_cipher_remote, wickr_ctx_decipher_remote);
    }
    END_IT
    
    IT("should encrypt remote data differently than local data")
    {
        wickr_buffer_t *rand_data = engine.wickr_crypto_engine_crypto_random(10000);
        
        wickr_cipher_result_t *cipher_result = wickr_ctx_cipher_local(ctx, rand_data);
        SHOULD_NOT_BE_NULL(cipher_result);
        SHOULD_BE_NULL(wickr_ctx_decipher_remote(ctx, cipher_result));
        
        wickr_cipher_result_destroy(&cipher_result);
        
        cipher_result = wickr_ctx_cipher_remote(ctx, rand_data);
        
        SHOULD_NOT_BE_NULL(cipher_result);
        SHOULD_BE_NULL(wickr_ctx_decipher_local(ctx, cipher_result));
        
        wickr_cipher_result_destroy(&cipher_result);
        wickr_buffer_destroy(&rand_data);
    }
    END_IT
    
    IT("should be able to generate ephemeral keypairs")
    {
        wickr_ephemeral_keypair_t *keypair = wickr_ctx_ephemeral_keypair_gen(ctx, 100);
        SHOULD_NOT_BE_NULL(keypair);
        SHOULD_EQUAL(100, keypair->identifier);
        
        SHOULD_BE_TRUE(engine.wickr_crypto_engine_ec_verify(keypair->signature, ctx->id_chain->node->sig_key, keypair->ec_key->pub_data));
        
        SHOULD_BE_TRUE(wickr_ephemeral_keypair_verify_owner(keypair, &engine, ctx->id_chain->node));
        SHOULD_BE_FALSE(wickr_ephemeral_keypair_verify_owner(keypair, &engine, ctx->id_chain->root));
        
        wickr_ephemeral_keypair_destroy(&keypair);
    }
    END_IT
    
    wickr_buffer_destroy(&rand_id);
    wickr_dev_info_destroy(&devInfo);
    wickr_buffer_destroy(&devBuf);
    
    wickr_ctx_gen_result_destroy(&ctx_res);
}
END_DESCRIBE

void __test_packet_decode(wickr_ctx_t *ctxUser1,
                          wickr_ctx_t *ctxUser2,
                          wickr_node_t *nodeUser2,
                          wickr_encoder_result_t *encodePkt,
                          wickr_buffer_t *bodyData,
                          wickr_buffer_t *channelTag,
                          uint64_t contentType,
                          wickr_ephemeral_info_t ephemeralData)
{
    wickr_ctx_packet_t *inPacket = NULL;
    
    wickr_buffer_t *packet_buffer = wickr_packet_serialize(encodePkt->packet);
    
    SHOULD_NOT_BE_NULL(inPacket = wickr_ctx_parse_packet(ctxUser2, packet_buffer, ctxUser1->id_chain))
    
    if (inPacket != NULL) {
        
        SHOULD_NOT_BE_NULL(inPacket->parse_result->key_exchange);
        SHOULD_EQUAL(inPacket->parse_result->err, E_SUCCESS);
        SHOULD_NOT_BE_NULL(inPacket->packet);
        SHOULD_NOT_BE_NULL(inPacket->packet->content);
        SHOULD_NOT_BE_NULL(inPacket->packet->signature);
        SHOULD_EQUAL(inPacket->packet->version, ctxUser1->pkt_enc_version);
        SHOULD_NOT_BE_NULL(inPacket->parse_result->enc_payload);
        SHOULD_NOT_BE_NULL(inPacket->parse_result->key_exchange_set);
        SHOULD_EQUAL(inPacket->parse_result->signature_status, PACKET_SIGNATURE_VALID);
        
        wickr_decode_result_t *decodeResult;
        SHOULD_NOT_BE_NULL(decodeResult = wickr_ctx_decode_packet(ctxUser2, inPacket, nodeUser2->ephemeral_keypair->ec_key))
        
        SHOULD_BE_FALSE(wickr_buffer_is_equal(decodeResult->decrypted_payload->body, inPacket->packet->content, NULL))
        SHOULD_BE_FALSE(wickr_buffer_is_equal(bodyData, inPacket->packet->content, NULL));
        
        SHOULD_BE_TRUE(wickr_buffer_is_equal(bodyData, decodeResult->decrypted_payload->body, NULL));
        SHOULD_BE_TRUE(wickr_buffer_is_equal(channelTag, decodeResult->decrypted_payload->meta->channel_tag, NULL));
        SHOULD_EQUAL(ephemeralData.bor, decodeResult->decrypted_payload->meta->ephemerality_settings.bor);
        SHOULD_EQUAL(ephemeralData.ttl, decodeResult->decrypted_payload->meta->ephemerality_settings.ttl);
        SHOULD_EQUAL(contentType, decodeResult->decrypted_payload->meta->content_type);
        
        wickr_decode_result_destroy(&decodeResult);
        wickr_ctx_packet_destroy(&inPacket);
    }
    
     wickr_buffer_destroy(&packet_buffer);
}

DESCRIBE(wickr_ctx_send_pkt, "wickr_ctx: test sending packet")
{
    initTest();
    
    // Create user 1
    char *nameUser1 = "alice@wickr.com";
    char *nameDev1User1 = "alice:DEVICE1";
    wickr_buffer_t *devBufUser1 = wickr_buffer_create((uint8_t *)nameDev1User1, strlen(nameDev1User1));

    wickr_node_t *nodeUser1 = createUserNode(nameUser1, devBufUser1);
    wickr_ctx_t *ctxUser1 = createContext(nodeUser1);
    
    nodeUser1->dev_id = wickr_buffer_copy(ctxUser1->dev_info->msg_proto_id);
    wickr_buffer_destroy(&devBufUser1);
    
    // Create user 2
    char *nameUser2 = "bob@wickr.com";
    char *nameDev1User2 = "bpb:DEVICE1";
    wickr_buffer_t *devBufUser2 = wickr_buffer_create((uint8_t *)nameDev1User2, strlen(nameDev1User2));
    
    wickr_node_t *nodeUser2 = createUserNode(nameUser2, devBufUser2);
    wickr_ctx_t *ctxUser2 = createContext(nodeUser2);
    nodeUser2->dev_id = wickr_buffer_copy(ctxUser2->dev_info->msg_proto_id);
    wickr_buffer_destroy(&devBufUser2);
    
    wickr_node_array_t *recipients = wickr_node_array_new(2);
    
    wickr_node_array_set_item(recipients, 0, nodeUser2);
    wickr_node_array_set_item(recipients, 1, nodeUser1);
        
    wickr_ephemeral_info_t ephemeralData = { 64000, 3600 };
    wickr_buffer_t *channelTag = engine.wickr_crypto_engine_crypto_random(64);
    uint16_t contentType = 3000;
    wickr_packet_meta_t *metaData = wickr_packet_meta_create(ephemeralData, channelTag, contentType);
    
    char *body = "Hello World!";
    wickr_buffer_t *bodyData = wickr_buffer_create((uint8_t*)body, strlen(body));
    wickr_payload_t *payload = wickr_payload_create(metaData, bodyData);

    wickr_encoder_result_t *encodePkt = NULL;
    
    IT("should encode packets")
    {
        SHOULD_NOT_BE_NULL(encodePkt = wickr_ctx_encode_packet(ctxUser1, payload, recipients))
        
    }
    END_IT
    
    IT ("should fail to create a packet using a failed identity status")
    {
        wickr_node_t *first_recipient = wickr_node_array_fetch_item(recipients, 0);
        wickr_ec_key_t *correct_key = first_recipient->id_chain->node->sig_key;
        first_recipient->id_chain->node->sig_key = engine.wickr_crypto_engine_ec_rand_key(EC_CURVE_NIST_P521);
        
        wickr_encoder_result_t *bad_packet = wickr_ctx_encode_packet(ctxUser1, payload, recipients);
        SHOULD_BE_NULL(bad_packet);
        wickr_ec_key_destroy(&first_recipient->id_chain->node->sig_key);
        first_recipient->id_chain->node->sig_key = correct_key;
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
        
        wickr_encoder_result_t *bad_packet = wickr_ctx_encode_packet(ctxUser1, payload, recipients_copy);
        SHOULD_BE_NULL(bad_packet);
        
        /* Force a valid identity chain state, make sure it still fails */
        first_recipient->id_chain->status = IDENTITY_CHAIN_STATUS_VALID;
        
        bad_packet = wickr_ctx_encode_packet(ctxUser1, payload, recipients_copy);
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
        
        wickr_encoder_result_t *bad_packet = wickr_ctx_encode_packet(ctxUser1, payload, recipients_copy);
        SHOULD_BE_NULL(bad_packet);
        
        wickr_array_destroy(&recipients_copy, true);
    }
    END_IT
    
    IT("should parse packets for non decoding purposes")
    {
        wickr_ctx_packet_t *inPacket = NULL;
        
        wickr_buffer_t *packet_buffer = wickr_packet_serialize(encodePkt->packet);
        
        if (encodePkt != NULL) {
            
            SHOULD_NOT_BE_NULL(inPacket = wickr_ctx_parse_packet_no_decode(ctxUser2, packet_buffer, ctxUser1->id_chain));
            SHOULD_BE_NULL(inPacket->parse_result->key_exchange);
            SHOULD_EQUAL(inPacket->parse_result->err, E_SUCCESS);
            SHOULD_NOT_BE_NULL(inPacket->packet);
            SHOULD_NOT_BE_NULL(inPacket->packet->content);
            SHOULD_NOT_BE_NULL(inPacket->packet->signature);
            SHOULD_EQUAL(inPacket->packet->version, DEFAULT_PKT_ENC_VERSION);
            SHOULD_NOT_BE_NULL(inPacket->parse_result->enc_payload);
            SHOULD_NOT_BE_NULL(inPacket->parse_result->key_exchange_set);
            SHOULD_EQUAL(inPacket->parse_result->signature_status, PACKET_SIGNATURE_VALID);
            
            wickr_decode_result_t *decode_result = wickr_ctx_decode_packet(ctxUser2, inPacket, nodeUser2->ephemeral_keypair->ec_key);
            SHOULD_NOT_BE_NULL(decode_result);
            SHOULD_BE_NULL(decode_result->decrypted_payload);
            SHOULD_BE_NULL(decode_result->payload_key);
            SHOULD_EQUAL(decode_result->err, ERROR_KEY_EXCHANGE_FAILED);
            wickr_decode_result_destroy(&decode_result);
        }
        
        wickr_ctx_packet_destroy(&inPacket);
        wickr_buffer_destroy(&packet_buffer);
    }
    END_IT

    IT("should parse packets for decoding")
    {
        __test_packet_decode(ctxUser1, ctxUser2, nodeUser2, encodePkt, bodyData, channelTag, contentType, ephemeralData);
        wickr_encoder_result_destroy(&encodePkt);
    }
    END_IT
    
    IT("should support encoding and decoding older verisons of packets for stagged rollout scenarios")
    {
        for (uint8_t i = OLDEST_PACKET_VERSION; i <= CURRENT_PACKET_VERSION; i++) {
            ctxUser1->pkt_enc_version = i;
            SHOULD_NOT_BE_NULL(encodePkt = wickr_ctx_encode_packet(ctxUser1, payload, recipients))
            __test_packet_decode(ctxUser1, ctxUser2, nodeUser2, encodePkt, bodyData, channelTag, contentType, ephemeralData);
            wickr_encoder_result_destroy(&encodePkt);
        }
    }
    END_IT
    
    wickr_node_array_destroy(&recipients);
    wickr_node_destroy(&nodeUser1);
    wickr_node_destroy(&nodeUser2);
    wickr_payload_destroy(&payload);
    wickr_ctx_destroy(&ctxUser1);
    wickr_ctx_destroy(&ctxUser2);

}
END_DESCRIBE
