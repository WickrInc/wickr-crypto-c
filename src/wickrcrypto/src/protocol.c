
#include "protocol.h"
#include "memory.h"
#include "message.pb-c.h"
#include "ecdh_cipher_ctx.h"

#include <string.h>

#define PACKET_META_SIZE 2

static wickr_buffer_t *__wickr_key_exchange_get_kdf_info(const wickr_identity_chain_t *sender,
                                                         const wickr_node_t *receiver,
                                                         uint8_t version)
{
    if (!sender || !receiver) {
        return NULL;
    }
    
    switch (version) {
        case 2:
            return wickr_buffer_copy(receiver->dev_id);
        case 3:
        case 4:
        {
            wickr_buffer_t *info_buffers[] = { sender->root->sig_key->pub_data, receiver->id_chain->root->sig_key->pub_data, receiver->dev_id };
            return wickr_buffer_concat_multi(info_buffers, BUFFER_ARRAY_LEN(info_buffers));
        }
            break;
        default:
            return NULL;
    }
}

static wickr_kdf_meta_t *__wickr_key_exchange_get_kdf_meta(const wickr_identity_chain_t *sender,
                                                           const wickr_node_t *receiver,
                                                           wickr_cipher_t exchange_cipher,
                                                           const wickr_buffer_t *psk,
                                                           uint8_t version)
{
    if (!sender || !receiver || !receiver->ephemeral_keypair) {
        return NULL;
    }
    
    /* Fetch the proper algorithm for key exchange kdf based on protocol version */
    wickr_kdf_algo_t algo;
    
    switch (version) {
        case 2:
        case 3:
            algo = KDF_HKDF_SHA256;
            break;
        case 4:
            algo = KDF_HKDF_SHA512;
            break;
        default:
            return NULL;
    }
    
    /* Set the info field based on protocol version so that it can be used as application context data in HKDF */
    wickr_buffer_t *info = __wickr_key_exchange_get_kdf_info(sender, receiver, version);
    
    if (!info) {
        return NULL;
    }
    
    wickr_buffer_t *psk_copy = wickr_buffer_copy(psk);
    
    if (!psk_copy && psk) {
        wickr_buffer_destroy(&info);
        return NULL;
    }
    
    wickr_kdf_meta_t *meta = wickr_kdf_meta_create(algo, psk_copy, info);
    
    if (!meta) {
        wickr_buffer_destroy(&psk_copy);
        wickr_buffer_destroy(&info);
    }
    
    return meta;
}

wickr_key_exchange_t *wickr_key_exchange_create_with_data(const wickr_crypto_engine_t *engine,
                                                          const wickr_identity_chain_t *sender,
                                                          const wickr_node_t *receiver,
                                                          wickr_ec_key_t *packet_exchange_key,
                                                          const wickr_buffer_t *data_to_wrap,
                                                          wickr_cipher_t exchange_cipher,
                                                          const wickr_buffer_t *psk,
                                                          uint8_t version)
{
    if (!engine || !sender || !receiver || !receiver->ephemeral_keypair || !packet_exchange_key) {
        return NULL;
    }
    
    wickr_ec_key_t *copy_exchange_key = wickr_ec_key_copy(packet_exchange_key);
    
    if (!copy_exchange_key) {
        return NULL;
    }
    
    wickr_ecdh_cipher_ctx_t *ecdh_ctx = wickr_ecdh_cipher_ctx_create_key(*engine, copy_exchange_key, exchange_cipher);
    
    if (!ecdh_ctx) {
        wickr_ec_key_destroy(&copy_exchange_key);
        return NULL;
    }
    
    wickr_kdf_meta_t *kdf_params = __wickr_key_exchange_get_kdf_meta(sender, receiver, exchange_cipher, psk, version);
    
    if (!kdf_params) {
        wickr_ecdh_cipher_ctx_destroy(&ecdh_ctx);
        return NULL;
    }
    
    wickr_ecdh_cipher_result_t *cipher_result = wickr_ecdh_cipher_ctx_cipher(ecdh_ctx, data_to_wrap, receiver->ephemeral_keypair->ec_key, kdf_params);
    wickr_kdf_meta_destroy(&kdf_params);
    wickr_ecdh_cipher_ctx_destroy(&ecdh_ctx);
    
    if (!cipher_result) {
        return NULL;
    }
    
    wickr_buffer_t *node_id_copy = wickr_buffer_copy(receiver->id_chain->node->identifier);
    
    if (!node_id_copy) {
        wickr_ecdh_cipher_result_destroy(&cipher_result);
        return NULL;
    }
    
    wickr_key_exchange_t *exchange = wickr_key_exchange_create(node_id_copy, receiver->ephemeral_keypair->identifier, cipher_result);
    
    if (!exchange) {
        wickr_ecdh_cipher_result_destroy(&cipher_result);
        wickr_buffer_destroy(&node_id_copy);
    }
    
    return exchange;
}

wickr_key_exchange_t *wickr_key_exchange_create_with_packet_key(const wickr_crypto_engine_t *engine,
                                                                const wickr_identity_chain_t *sender,
                                                                const wickr_node_t *receiver,
                                                                wickr_ec_key_t *packet_exchange_key,
                                                                const wickr_cipher_key_t *packet_key,
                                                                const wickr_buffer_t *psk,
                                                                uint8_t version)
{
    if (!engine || !sender || !receiver || !packet_key || !packet_exchange_key) {
        return NULL;
    }
    
    wickr_buffer_t *serialized_packet_key = wickr_cipher_key_serialize(packet_key);
    
    if (!serialized_packet_key) {
        return NULL;
    }
    
    wickr_cipher_t cipher = wickr_exchange_cipher_matching_cipher(packet_key->cipher);
    
    wickr_key_exchange_t *key_exchange = wickr_key_exchange_create_with_data(engine, sender, receiver, packet_exchange_key, serialized_packet_key, cipher, psk, version);
    
    wickr_buffer_destroy_zero(&serialized_packet_key);
    
    return key_exchange;
}

/* Low level decrypting of key exchanges, safer to call from wickr_ctx instead! */
wickr_cipher_key_t *wickr_key_exchange_derive_packet_key(const wickr_crypto_engine_t *engine,
                                                         const wickr_identity_chain_t *sender,
                                                         const wickr_node_t *receiver,
                                                         wickr_ec_key_t *packet_exchange_key,
                                                         const wickr_key_exchange_t *exchange,
                                                         const wickr_buffer_t *psk,
                                                         uint8_t version)
{
    if (!exchange || !engine || !sender || !receiver) {
        return NULL;
    }
    
    wickr_buffer_t *packet_key_buffer = wickr_key_exchange_derive_data(engine, sender, receiver, packet_exchange_key, exchange, psk, version);
    
    wickr_cipher_key_t *packet_key = wickr_cipher_key_from_buffer(packet_key_buffer);
    wickr_buffer_destroy_zero(&packet_key_buffer);
    
    if (!packet_key) {
        return NULL;
    }
    
    return packet_key;
}

wickr_buffer_t *wickr_key_exchange_derive_data(const wickr_crypto_engine_t *engine,
                                               const wickr_identity_chain_t *sender,
                                               const wickr_node_t *receiver,
                                               wickr_ec_key_t *packet_exchange_key,
                                               const wickr_key_exchange_t *exchange,
                                               const wickr_buffer_t *psk,
                                               uint8_t version)
{
    if (!exchange || !engine || !sender || !receiver || !receiver->ephemeral_keypair) {
        return NULL;
    }
    
    wickr_ec_key_t *copy_local_key = wickr_ec_key_copy(receiver->ephemeral_keypair->ec_key);
    
    if (!copy_local_key) {
        return NULL;
    }
    
    wickr_ecdh_cipher_ctx_t *ecdh_ctx = wickr_ecdh_cipher_ctx_create_key(*engine, copy_local_key,
                                                                         exchange->exchange_ciphertext->cipher_result->cipher);
    
    if (!ecdh_ctx) {
        wickr_ec_key_destroy(&copy_local_key);
        return NULL;
    }
    
    wickr_kdf_meta_t *kdf_params = __wickr_key_exchange_get_kdf_meta(sender,
                                                                     receiver,
                                                                     exchange->exchange_ciphertext->cipher_result->cipher,
                                                                     psk,
                                                                     version);
    
    if (!kdf_params) {
        wickr_ecdh_cipher_ctx_destroy(&ecdh_ctx);
        return NULL;
    }
    
    wickr_buffer_t *decoded_data = wickr_ecdh_cipher_ctx_decipher(ecdh_ctx, exchange->exchange_ciphertext,
                                                                  packet_exchange_key, kdf_params);
    
    wickr_ecdh_cipher_ctx_destroy(&ecdh_ctx);
    wickr_kdf_meta_destroy(&kdf_params);
    
    return decoded_data;
}

wickr_packet_t *wickr_packet_create(uint8_t version, wickr_buffer_t *content, wickr_ecdsa_result_t *signature_data)
{
    if (!content || !signature_data) {
        return NULL;
    }
    
    wickr_packet_t *new_packet = wickr_alloc_zero(sizeof(wickr_packet_t));
    
    if (!new_packet) {
        return NULL;
    }
    
    new_packet->version = version;
    new_packet->content = content;
    new_packet->signature = signature_data;
    
    return new_packet;
}

wickr_packet_t *wickr_packet_create_with_components(const wickr_crypto_engine_t *engine, const wickr_cipher_result_t *enc_header, const wickr_cipher_result_t *enc_payload, const wickr_ec_key_t *signing_key, uint8_t version)
{
    if (!engine || !enc_payload || !signing_key) {
        return NULL;
    }
    
    Wickr__Proto__Packet proto_packet = WICKR__PROTO__PACKET__INIT;
    
    wickr_buffer_t *enc_header_bytes = wickr_cipher_result_serialize(enc_header);
    
    if (!enc_header_bytes) {
        return NULL;
    }
    
    wickr_buffer_t *enc_payload_bytes = wickr_cipher_result_serialize(enc_payload);
    
    proto_packet.enc_header.data = enc_header_bytes->bytes;
    proto_packet.enc_header.len = enc_header_bytes->length;
    proto_packet.enc_payload.data = enc_payload_bytes->bytes;
    proto_packet.enc_payload.len = enc_payload_bytes->length;
    
    size_t packet_size = wickr__proto__packet__get_packed_size(&proto_packet);
    
    wickr_buffer_t *result_buffer = wickr_buffer_create_empty(packet_size);
    
    if (!result_buffer) {
        wickr_buffer_destroy(&enc_header_bytes);
        wickr_buffer_destroy(&enc_payload_bytes);
        return NULL;
    }
    
    wickr__proto__packet__pack(&proto_packet, result_buffer->bytes);
    wickr_buffer_destroy(&enc_header_bytes);
    wickr_buffer_destroy(&enc_payload_bytes);
    
    wickr_digest_t digest_type = wickr_digest_matching_curve(signing_key->curve);
    wickr_ecdsa_result_t *signature = engine->wickr_crypto_engine_ec_sign(signing_key, result_buffer, digest_type);
    
    if (!signature) {
        wickr_buffer_destroy(&result_buffer);
        return NULL;
    }
    
    wickr_packet_t *new_packet = wickr_packet_create(version, result_buffer, signature);
    
    if (!new_packet) {
        wickr_buffer_destroy(&result_buffer);
        wickr_ecdsa_result_destroy(&signature);
        return NULL;
    }
    
    return new_packet;
}

wickr_packet_t *wickr_packet_create_from_buffer(const wickr_buffer_t *buffer)
{
    if (!buffer || buffer->length <= PACKET_META_SIZE) {
        return NULL;
    }
    
    uint8_t version = buffer->bytes[0];
    
    if (version > CURRENT_PACKET_VERSION || version < OLDEST_PACKET_VERSION) {
        return NULL;
    }
    
    uint8_t sig_type;
    
    switch (version) {
        case 2:
            sig_type = (buffer->bytes[1] & 0xF);
            break;
        case 3:
        case 4:
            sig_type = (buffer->bytes[1]);
            break;
        default:
            return NULL;
    }
    
    const wickr_ec_curve_t *curve = wickr_ec_curve_find(sig_type);
    
    if (!curve) {
        return NULL;
    }
    
    if (buffer->length <= PACKET_META_SIZE + curve->signature_size) {
        return NULL;
    }
    
    size_t signature_start = buffer->length - curve->signature_size;
    
    wickr_buffer_t sig_buffer;
    sig_buffer.length = curve->signature_size;
    sig_buffer.bytes = buffer->bytes + signature_start;
    
    wickr_digest_t digest = wickr_digest_matching_curve(*curve);
    
    wickr_ecdsa_result_t *signature = wickr_ecdsa_result_create_from_buffer(&sig_buffer);
    
    if (!signature ||
        signature->digest_mode.digest_id != digest.digest_id ||
        signature->curve.identifier != curve->identifier) {
        return NULL;
    }
    
    wickr_buffer_t *content_buffer = wickr_buffer_copy_section(buffer, PACKET_META_SIZE, buffer->length - curve->signature_size - PACKET_META_SIZE);
    
    if (!content_buffer) {
        wickr_ecdsa_result_destroy(&signature);
        return NULL;
    }
    
    wickr_packet_t *packet = wickr_packet_create(version, content_buffer, signature);
    
    if (!packet) {
        wickr_ecdsa_result_destroy(&signature);
        wickr_buffer_destroy(&content_buffer);
        return NULL;
    }
    
    return packet;
}

wickr_buffer_t *wickr_packet_serialize(const wickr_packet_t *packet)
{
    if (!packet) {
        return NULL;
    }
    
    if ((int)packet->signature->curve.identifier > UINT8_MAX) {
        return NULL;
    }
    
    uint8_t version = packet->version;
    uint8_t meta_data = (uint8_t)packet->signature->curve.identifier;
    
    wickr_buffer_t *sig_data = wickr_ecdsa_result_serialize(packet->signature);
    
    if (!sig_data || sig_data->length != packet->signature->curve.signature_size) {
        return NULL;
    }
    
    wickr_buffer_t version_buffer = { sizeof(uint8_t), &version };
    wickr_buffer_t meta_buffer = { sizeof(uint8_t), &meta_data };
    
    wickr_buffer_t *components[] = { &version_buffer, &meta_buffer, packet->content, sig_data };
    
    wickr_buffer_t *serialized_packet = wickr_buffer_concat_multi(components, BUFFER_ARRAY_LEN(components));
    wickr_buffer_destroy(&sig_data);
    
    return serialized_packet;
}

wickr_packet_t *wickr_packet_copy(const wickr_packet_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_buffer_t *content_copy = wickr_buffer_copy(source->content);
    
    if (!content_copy) {
        return NULL;
    }
    
    wickr_ecdsa_result_t *sig_copy = wickr_ecdsa_result_copy(source->signature);
    
    if (!sig_copy) {
        wickr_buffer_destroy(&content_copy);
        return NULL;
    }
    
    wickr_packet_t *packet = wickr_packet_create(source->version, content_copy, sig_copy);
    
    if (!packet) {
        wickr_buffer_destroy(&content_copy);
        wickr_ecdsa_result_destroy(&sig_copy);
    }
    
    return packet;
}

void wickr_packet_destroy(wickr_packet_t **packet)
{
    if (!packet || !*packet) {
        return;
    }
    
    wickr_buffer_destroy(&(*packet)->content);
    wickr_ecdsa_result_destroy(&(*packet)->signature);
    wickr_free(*packet);
    *packet = NULL;
}

static wickr_parse_result_t *__wickr_parse_result_create(wickr_key_exchange_set_t *key_exchange_set,
                                                         wickr_key_exchange_t *key_exchange,
                                                         wickr_cipher_result_t *enc_payload,
                                                         wickr_packet_signature_status sig_status,
                                                         wickr_decode_error error)
{
    wickr_parse_result_t *new_result = wickr_alloc_zero(sizeof(wickr_parse_result_t));
    
    if (!new_result) {
        return NULL;
    }
    
    new_result->err = error;
    new_result->signature_status = sig_status;
    new_result->key_exchange_set = key_exchange_set;
    new_result->enc_payload = enc_payload;
    new_result->key_exchange = key_exchange;
    
    return new_result;
}

wickr_parse_result_t *wickr_parse_result_create_failure(wickr_packet_signature_status signature_status, wickr_decode_error error)
{
    return __wickr_parse_result_create(NULL, NULL, NULL, signature_status, error);
}

wickr_parse_result_t *wickr_parse_result_create_success(wickr_key_exchange_set_t *header, wickr_key_exchange_t *key_exchange, wickr_cipher_result_t *enc_payload)
{
    return __wickr_parse_result_create(header, key_exchange, enc_payload, PACKET_SIGNATURE_VALID, E_SUCCESS);
}

wickr_parse_result_t *wickr_parse_result_copy(const wickr_parse_result_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_key_exchange_set_t *header_copy = wickr_key_exchange_set_copy(source->key_exchange_set);
    wickr_cipher_result_t *enc_payload_copy = wickr_cipher_result_copy(source->enc_payload);
    wickr_key_exchange_t *key_exchange_copy = wickr_key_exchange_copy(source->key_exchange);
    
    wickr_parse_result_t *copy = __wickr_parse_result_create(header_copy, key_exchange_copy, enc_payload_copy, source->signature_status, source->err);
    
    if (!copy) {
        wickr_key_exchange_set_destroy(&header_copy);
        wickr_cipher_result_destroy(&enc_payload_copy);
        wickr_key_exchange_destroy(&key_exchange_copy);
    }
    
    return copy;
}

void wickr_parse_result_destroy(wickr_parse_result_t **result)
{
    if (!result || !*result) {
        return;
    }
    
    wickr_key_exchange_set_destroy(&(*result)->key_exchange_set);
    wickr_cipher_result_destroy(&(*result)->enc_payload);
    wickr_key_exchange_destroy(&(*result)->key_exchange);
    wickr_free(*result);
    *result = NULL;
}

static wickr_decode_result_t *__wickr_decode_result_create(wickr_decode_error decode_error, wickr_payload_t *decrypted_payload, wickr_cipher_key_t *payload_key)
{
    
    wickr_decode_result_t *result = wickr_alloc_zero(sizeof(wickr_decode_result_t));
    
    if (!result) {
        return NULL;
    }
    
    result->decrypted_payload = decrypted_payload;
    result->err = decode_error;
    result->payload_key = payload_key;
    return result;
}


wickr_decode_result_t *wickr_decode_result_create_failure(wickr_decode_error decode_error)
{
    return __wickr_decode_result_create(decode_error, NULL, NULL);
}

wickr_decode_result_t *wickr_decode_result_create_success(wickr_payload_t *decrypted_payload, wickr_cipher_key_t *payload_key)
{
    return __wickr_decode_result_create(E_SUCCESS, decrypted_payload, payload_key);
}

wickr_decode_result_t *wickr_decode_result_copy(const wickr_decode_result_t *result)
{
    if (!result) {
        return NULL;
    }
    
    wickr_payload_t *payload_copy = wickr_payload_copy(result->decrypted_payload);
    wickr_cipher_key_t *cipher_key_copy = wickr_cipher_key_copy(result->payload_key);
    
    wickr_decode_result_t *copy = __wickr_decode_result_create(result->err, payload_copy, cipher_key_copy);
    
    if (!copy) {
        wickr_payload_destroy(&payload_copy);
    }
    
    return copy;
}

void wickr_decode_result_destroy(wickr_decode_result_t **result)
{
    if (!result || !*result) {
        return;
    }
    wickr_cipher_key_destroy(&(*result)->payload_key);
    wickr_payload_destroy(&(*result)->decrypted_payload);
    wickr_free(*result);
    *result = NULL;
}

static bool __wickr_recipients_validate(const wickr_node_array_t *recipients, const wickr_crypto_engine_t *engine)
{
    uint32_t recipient_count = wickr_array_get_item_count(recipients);
    
    for (int i = 0; i < recipient_count; i++) {
        
        wickr_node_t *one_node = wickr_node_array_fetch_item(recipients, i);
        
        if (!wickr_node_verify_signature_chain(one_node, engine)) {
            return false;
        }
        
    }
    
    return true;
}

/* Low level packet assembly, much safer if used by calling wickr_ctx instead! */
wickr_packet_t *wickr_packet_create_from_components(const wickr_crypto_engine_t *engine,
                                                    const wickr_cipher_key_t *header_key,
                                                    const wickr_cipher_key_t *payload_key,
                                                    wickr_ec_key_t *exchange_key,
                                                    const wickr_payload_t *payload,
                                                    const wickr_node_array_t *recipients,
                                                    const wickr_identity_chain_t *sender_signing_identity,
                                                    uint8_t version)
{
    if (!engine || !payload_key || !header_key || !payload || !recipients || !sender_signing_identity) {
        return NULL;
    }
    
    uint32_t recipient_count = wickr_array_get_item_count(recipients);
    
    if (recipient_count == 0) {
        return NULL;
    }
    
    if (!__wickr_recipients_validate(recipients, engine)) {
        return NULL;
    }
    
    wickr_exchange_array_t *exchange_array = wickr_exchange_array_new(recipient_count);
    
    for (int i = 0; i < recipient_count; i++) {
        
        wickr_node_t *one_node = wickr_node_array_fetch_item(recipients, i);
        
        wickr_key_exchange_t *one_exchange = wickr_key_exchange_create_with_packet_key(engine, sender_signing_identity, one_node, exchange_key, payload_key, NULL, version);
        
        if (!one_exchange) {
            wickr_exchange_array_destroy(&exchange_array);
            return NULL;
        }
        
        if (!wickr_exchange_array_set_item(exchange_array, i, one_exchange)) {
            wickr_key_exchange_destroy(&one_exchange);
            wickr_exchange_array_destroy(&exchange_array);
            return NULL;
        }
        
    }
    
    wickr_key_exchange_set_t packet_header;
    packet_header.exchanges = exchange_array;
    packet_header.sender_pub = exchange_key;
    
    wickr_cipher_result_t *enc_header = wickr_key_exchange_set_encrypt(&packet_header, engine, header_key);
    wickr_exchange_array_destroy(&exchange_array);
    
    if (!enc_header) {
        return NULL;
    }
    
    wickr_cipher_result_t *enc_payload = wickr_payload_encrypt(payload, engine, payload_key);
    
    if (!enc_payload) {
        wickr_cipher_result_destroy(&enc_header);
        return NULL;
    }
    
    wickr_packet_t *packet = wickr_packet_create_with_components(engine, enc_header, enc_payload, sender_signing_identity->node->sig_key, version);
    wickr_cipher_result_destroy(&enc_header);
    wickr_cipher_result_destroy(&enc_payload);
    
    return packet;
}

/* Low level packet dissasembly, much safer if used by calling wickr_ctx instead! */
wickr_parse_result_t *wickr_parse_result_from_packet(const wickr_crypto_engine_t *engine,
                                                     const wickr_packet_t *packet,
                                                     const wickr_buffer_t *receiver_node_id,
                                                     wickr_header_keygen_func header_keygen_func,
                                                     const wickr_identity_chain_t *sender_signing_identity)
{
    if (!engine || !packet || !sender_signing_identity || !header_keygen_func) {
        return wickr_parse_result_create_failure(PACKET_SIGNATURE_UNKNOWN, ERROR_INVALID_INPUT);
    }
    
    if (sender_signing_identity->node->sig_key->curve.identifier != packet->signature->curve.identifier) {
        return wickr_parse_result_create_failure(PACKET_SIGNATURE_INVALID, ERROR_INVALID_INPUT);
    }
    
    bool is_valid_packet = engine->wickr_crypto_engine_ec_verify(packet->signature, sender_signing_identity->node->sig_key, packet->content);
    
    if (!is_valid_packet) {
        return wickr_parse_result_create_failure(PACKET_SIGNATURE_INVALID, ERROR_MAC_INVALID);
    }
    
    Wickr__Proto__Packet *proto_packet = wickr__proto__packet__unpack(NULL, packet->content->length,
                                                                      packet->content->bytes);
    
    if (!proto_packet) {
        return wickr_parse_result_create_failure(PACKET_SIGNATURE_VALID, ERROR_CORRUPT_PACKET);
    }
    
    wickr_buffer_t temp_buffer;
    temp_buffer.bytes = proto_packet->enc_header.data;
    temp_buffer.length = proto_packet->enc_header.len;
    
    wickr_cipher_result_t *header_cipher_result = wickr_cipher_result_from_buffer(&temp_buffer);
    
    if (!header_cipher_result) {
        wickr__proto__packet__free_unpacked(proto_packet, NULL);
        return wickr_parse_result_create_failure(PACKET_SIGNATURE_VALID, ERROR_CORRUPT_PACKET);
    }
    
    wickr_cipher_key_t *header_key = header_keygen_func(*engine, header_cipher_result->cipher, sender_signing_identity);
    
    wickr_key_exchange_set_t *header = wickr_key_exchange_set_create_from_cipher(engine, header_cipher_result, header_key);
    
    wickr_cipher_key_destroy(&header_key);
    wickr_cipher_result_destroy(&header_cipher_result);
    
    if (!header) {
        wickr__proto__packet__free_unpacked(proto_packet, NULL);
        return wickr_parse_result_create_failure(PACKET_SIGNATURE_VALID, ERROR_CORRUPT_PACKET);
    }
    
    /* If we don't pass a receiver node id, we are just interested in parsing properties and can ignore the search */
    
    wickr_key_exchange_t *key_exchange = NULL;
    
    if (receiver_node_id) {
        key_exchange = wickr_key_exchange_set_find(header, receiver_node_id);
        
        if (!key_exchange) {
            wickr_key_exchange_set_destroy(&header);
            wickr__proto__packet__free_unpacked(proto_packet, NULL);
            return wickr_parse_result_create_failure(PACKET_SIGNATURE_VALID, ERROR_NODE_NOT_FOUND);
        }
    }
    
    temp_buffer.bytes = proto_packet->enc_payload.data;
    temp_buffer.length = proto_packet->enc_payload.len;
    
    wickr_cipher_result_t *payload_result = wickr_cipher_result_from_buffer(&temp_buffer);
    wickr__proto__packet__free_unpacked(proto_packet, NULL);
    
    if (!payload_result) {
        wickr_key_exchange_destroy(&key_exchange);
        wickr_key_exchange_set_destroy(&header);
        return wickr_parse_result_create_failure(PACKET_SIGNATURE_VALID, ERROR_CORRUPT_PACKET);
    }
    
    wickr_parse_result_t *final_result = wickr_parse_result_create_success(header, key_exchange, payload_result);
    
    if (!final_result) {
        wickr_key_exchange_destroy(&key_exchange);
        wickr_key_exchange_set_destroy(&header);
        wickr_cipher_result_destroy(&payload_result);
    }
    
    return final_result;
}

/* Low level packet decoding, much safer if used by calling wickr_ctx instead! */
wickr_decode_result_t *wickr_decode_result_from_parse_result(const wickr_packet_t *packet,
                                                             const wickr_crypto_engine_t *engine,
                                                             const wickr_parse_result_t *parse_result,
                                                             wickr_buffer_t *receiver_dev_id,
                                                             wickr_ec_key_t *receiver_decode_key,
                                                             wickr_identity_chain_t *receiver_signing_identity,
                                                             const wickr_identity_chain_t *sender_signing_identity)
{
    if (!parse_result || parse_result->err != E_SUCCESS ||
        parse_result->signature_status != PACKET_SIGNATURE_VALID || !receiver_decode_key) {
        return NULL;
    }
    
    wickr_node_t receiver_node;
    receiver_node.dev_id = receiver_dev_id;
    
    wickr_ephemeral_keypair_t receiver_key = { 0, receiver_decode_key, NULL };
    receiver_node.ephemeral_keypair = &receiver_key;
    receiver_node.id_chain = receiver_signing_identity;
    
    wickr_cipher_key_t *cipher_key = wickr_key_exchange_derive_packet_key(engine,
                                                                          sender_signing_identity,
                                                                          &receiver_node,
                                                                          parse_result->key_exchange_set->sender_pub,
                                                                          parse_result->key_exchange,
                                                                          NULL,
                                                                          packet->version);
    
    if (!cipher_key) {
        return wickr_decode_result_create_failure(ERROR_KEY_EXCHANGE_FAILED);
    }
    
    wickr_payload_t *payload = wickr_payload_create_from_cipher(engine,
                                                                parse_result->enc_payload,
                                                                cipher_key);
    
    
    if (!payload) {
        wickr_cipher_key_destroy(&cipher_key);
        return wickr_decode_result_create_failure(ERROR_KEY_EXCHANGE_FAILED);
    }
    
    wickr_decode_result_t *final_result = wickr_decode_result_create_success(payload, cipher_key);
    
    if (!final_result) {
        wickr_cipher_key_destroy(&cipher_key);
        wickr_payload_destroy(&payload);
    }
    
    return final_result;
}
