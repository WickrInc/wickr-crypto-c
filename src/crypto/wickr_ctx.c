
#include "wickr_ctx.h"
#include "memory.h"

static wickr_ctx_gen_result_t *__wickr_ctx_gen_result_create(wickr_ctx_t *ctx, wickr_cipher_key_t *recovery_key, wickr_root_keys_t *root_keys)
{
    if (!ctx || !recovery_key || !root_keys) {
        return NULL;
    }
    
    wickr_ctx_gen_result_t *new_result = wickr_alloc_zero(sizeof(wickr_ctx_gen_result_t));
    
    if (!new_result) {
        return NULL;
    }
    
    new_result->ctx = ctx;
    new_result->recovery_key = recovery_key;
    new_result->root_keys = root_keys;
    
    return new_result;
}

static wickr_cipher_key_t *__wickr_ctx_gen_header_key(const wickr_crypto_engine_t engine, wickr_cipher_t cipher, const wickr_identity_chain_t *id_chain)
{
    if (!id_chain) {
        return NULL;
    }
    
    wickr_digest_t digest = wickr_digest_matching_cipher(cipher);
    
    wickr_buffer_t *root_identifier = id_chain->root->identifier;
    wickr_buffer_t *node_identifier = id_chain->node->identifier;
    
    /* Generate a header key by generating a hash of your root_id followed by your node_id
     This is designed to hide the list of recipients for this message if you don't know who the sender is
     The Wickr server can calculate this key, in order to fan out the payload as needed to recipients
     All information in the a Wickr packet header is public key exchange information */
    
    wickr_buffer_t *digest_result = engine.wickr_crypto_engine_digest(root_identifier, node_identifier, digest);
    
    if (!digest_result) {
        return NULL;
    }
    
    wickr_cipher_key_t *cipher_key = wickr_cipher_key_create(cipher, digest_result);
    
    if (!cipher_key) {
        wickr_buffer_destroy(&digest_result);
    }
    
    return cipher_key;
}

wickr_ctx_gen_result_t *wickr_ctx_gen_new(const wickr_crypto_engine_t engine, wickr_dev_info_t *dev_info, wickr_buffer_t *identifier)
{
    if (!dev_info || !identifier) {
        return NULL;
    }
    
    wickr_root_keys_t *new_root_keys = wickr_root_keys_generate(&engine);
    
    if (!new_root_keys) {
        return NULL;
    }
    
    wickr_ctx_gen_result_t *new_ctx = wickr_ctx_gen_with_root_keys(engine, dev_info, new_root_keys, identifier);
    wickr_root_keys_destroy(&new_root_keys);
    
    return new_ctx;
}

wickr_ctx_gen_result_t *wickr_ctx_gen_new_with_sig_key(const wickr_crypto_engine_t engine, wickr_dev_info_t *dev_info, wickr_ec_key_t *sig_key, wickr_buffer_t *identifier)
{
    if (!dev_info || !identifier) {
        return NULL;
    }
    
    wickr_root_keys_t *new_root_keys = wickr_root_keys_generate(&engine);
    
    if (!new_root_keys) {
        return NULL;
    }
    
    /* Swap out the generated key for our provided one */
    wickr_ec_key_destroy(&new_root_keys->node_signature_root);
    new_root_keys->node_signature_root = wickr_ec_key_copy(sig_key);
    
    if (!new_root_keys->node_signature_root) {
        wickr_root_keys_destroy(&new_root_keys);
        return NULL;
    }
    
    wickr_ctx_gen_result_t *new_ctx = wickr_ctx_gen_with_root_keys(engine, dev_info, new_root_keys, identifier);
    wickr_root_keys_destroy(&new_root_keys);
    
    return new_ctx;
}

wickr_ctx_gen_result_t *wickr_ctx_gen_with_passphrase(const wickr_crypto_engine_t engine, wickr_dev_info_t *dev_info, wickr_buffer_t *exported_recovery_key, wickr_buffer_t *passphrase, wickr_buffer_t *recovery_data, wickr_buffer_t *identifier)
{
    if (!dev_info || !exported_recovery_key || !passphrase || !recovery_data || !identifier) {
        return NULL;
    }
    
    wickr_buffer_t *decrypted_recovery_bytes = wickr_crypto_engine_kdf_decipher(&engine, exported_recovery_key, passphrase);
    
    if (!decrypted_recovery_bytes) {
        return NULL;
    }
    
    wickr_cipher_key_t *recovery_key = wickr_cipher_key_from_buffer(decrypted_recovery_bytes);
    wickr_buffer_destroy(&decrypted_recovery_bytes);

    if (!recovery_key) {
        return NULL;
    }
    
    wickr_ctx_gen_result_t *gen_result = wickr_ctx_gen_with_recovery(engine, dev_info, recovery_data, recovery_key, identifier);
    wickr_cipher_key_destroy(&recovery_key);
    
    return gen_result;
}

wickr_root_keys_t *wickr_ctx_gen_import_recovery(const wickr_crypto_engine_t engine, const wickr_buffer_t *recovery_data, const wickr_cipher_key_t *recovery_key)
{
    if (!recovery_key || !recovery_data) {
        return NULL;
    }
    
    wickr_cipher_result_t *ciphered_keys = wickr_cipher_result_from_buffer(recovery_data);
    
    if (!ciphered_keys) {
        return NULL;
    }
    
    wickr_buffer_t *decrypt_result = engine.wickr_crypto_engine_cipher_decrypt(ciphered_keys, NULL, recovery_key, true);
    wickr_cipher_result_destroy(&ciphered_keys);
    
    if (!decrypt_result) {
        return NULL;
    }
    
    wickr_root_keys_t *root_keys = wickr_root_keys_create_from_buffer(&engine, decrypt_result);
    wickr_buffer_destroy_zero(&decrypt_result);
    
    return root_keys;
}

wickr_ctx_gen_result_t *wickr_ctx_gen_with_recovery(const wickr_crypto_engine_t engine, wickr_dev_info_t *dev_info, wickr_buffer_t *recovery_data, wickr_cipher_key_t *recovery_key, wickr_buffer_t *identifier)
{
    if (!dev_info || !recovery_data || !recovery_key || !identifier) {
        return NULL;
    }
    
    wickr_root_keys_t *root_keys = wickr_ctx_gen_import_recovery(engine, recovery_data, recovery_key);
    
    if (!root_keys) {
        return NULL;
    }
    
    wickr_ctx_gen_result_t *gen_result = wickr_ctx_gen_with_root_keys(engine, dev_info, root_keys, identifier);
    wickr_root_keys_destroy(&root_keys);
    
    return gen_result;
}

/* Makes a new context using existing root keys for signing */
wickr_ctx_gen_result_t *wickr_ctx_gen_with_root_keys(const wickr_crypto_engine_t engine, wickr_dev_info_t *dev_info, wickr_root_keys_t *root_keys, wickr_buffer_t *identifier)
{
    if (!dev_info || !root_keys || !identifier) {
        return NULL;
    }
    
    
    wickr_ec_key_t *sig_key_copy = wickr_ec_key_copy(root_keys->node_signature_root);
    
    if (!sig_key_copy) {
        return NULL;
    }
    
    wickr_buffer_t *identifier_copy = wickr_buffer_copy(identifier);

    if (!identifier_copy) {
        wickr_ec_key_destroy(&sig_key_copy);
        return NULL;
    }
    
    wickr_identity_t *root_identity = wickr_identity_create(IDENTITY_TYPE_ROOT, identifier_copy, sig_key_copy, NULL);
    
    if (!root_identity) {
        wickr_buffer_destroy(&identifier_copy);
        wickr_ec_key_destroy(&sig_key_copy);
        return NULL;
    }
    
    wickr_identity_t *new_node_identity = wickr_node_identity_gen(&engine, root_identity);
    
    if (!new_node_identity) {
        wickr_identity_destroy(&root_identity);
        return NULL;
    }
    
    wickr_identity_chain_t *new_id_chain = wickr_identity_chain_create(root_identity, new_node_identity);
    
    if (!new_id_chain || !wickr_identity_chain_validate(new_id_chain, &engine)) {
        wickr_identity_destroy(&new_node_identity);
        wickr_identity_destroy(&root_identity);
        return NULL;
    }
    
    wickr_storage_keys_t *new_storage_keys = wickr_root_keys_localize(root_keys, &engine, dev_info);
    
    if (!new_storage_keys) {
        wickr_identity_chain_destroy(&new_id_chain);
        return NULL;
    }
    
    wickr_dev_info_t *dev_info_copy = wickr_dev_info_copy(dev_info);
    
    if (!dev_info_copy) {
        wickr_identity_chain_destroy(&new_id_chain);
        wickr_storage_keys_destroy(&new_storage_keys);
        return NULL;
    }
    
    wickr_ctx_t *ctx = wickr_ctx_create(engine, dev_info_copy, new_id_chain, new_storage_keys);
    
    if (!ctx) {
        wickr_identity_chain_destroy(&new_id_chain);
        wickr_storage_keys_destroy(&new_storage_keys);
        wickr_dev_info_destroy(&dev_info_copy);
        return NULL;
    }
    
    wickr_cipher_key_t *recovery_key = engine.wickr_crypto_engine_cipher_key_random(engine.default_cipher);
    
    if (!recovery_key) {
        wickr_ctx_destroy(&ctx);
        return NULL;
    }
    
    wickr_root_keys_t *root_keys_copy = wickr_root_keys_copy(root_keys);
    
    if (!root_keys) {
        wickr_ctx_destroy(&ctx);
        wickr_cipher_key_destroy(&recovery_key);
        return NULL;
    }
    
    wickr_ctx_gen_result_t *final_result = __wickr_ctx_gen_result_create(ctx, recovery_key, root_keys_copy);
    
    if (!final_result) {
        wickr_ctx_destroy(&ctx);
        wickr_cipher_key_destroy(&recovery_key);
        wickr_root_keys_destroy(&root_keys_copy);
    }
    
    return final_result;
}

/* Exports the recovery key using a password + KDF function */
wickr_buffer_t *wickr_ctx_gen_export_recovery_key_passphrase(const wickr_ctx_gen_result_t *result, const wickr_buffer_t *passphrase)
{
    if (!result || !passphrase) {
        return NULL;
    }
    
    wickr_buffer_t *recovery_key_buffer = wickr_cipher_key_serialize(result->recovery_key);
    
    if (!recovery_key_buffer) {
        return NULL;
    }
    
    wickr_buffer_t *protected = wickr_crypto_engine_kdf_cipher(&result->ctx->engine, KDF_SCRYPT_2_17, result->ctx->engine.default_cipher, recovery_key_buffer, passphrase);
    wickr_buffer_destroy_zero(&recovery_key_buffer);
    
    return protected;
}

wickr_cipher_key_t *wickr_ctx_gen_import_recovery_key_passphrase(const wickr_crypto_engine_t engine, const wickr_buffer_t *exported_recovery_key, const wickr_buffer_t *passphrase)
{
    if (!exported_recovery_key || !passphrase) {
        return NULL;
    }
    
    wickr_buffer_t *decoded_recovery = wickr_crypto_engine_kdf_decipher(&engine, exported_recovery_key, passphrase);
    
    if (!decoded_recovery) {
        return NULL;
    }
    
    wickr_cipher_key_t *recovery_key = wickr_cipher_key_from_buffer(decoded_recovery);
    wickr_buffer_destroy(&decoded_recovery);
    
    return recovery_key;
}

/* Serializes root keys and ciphers them with the recovery key */
wickr_buffer_t *wickr_ctx_gen_result_make_recovery(const wickr_ctx_gen_result_t *result)
{
    if (!result || !result->ctx || !result->root_keys || !result->recovery_key) {
        return NULL;
    }
    
    wickr_cipher_result_t *export_result = wickr_root_keys_export(result->root_keys, &result->ctx->engine, result->recovery_key);
    
    if (!export_result) {
        return NULL;
    }
    
    wickr_buffer_t *serialized_cipher_result = wickr_cipher_result_serialize(export_result);
    wickr_cipher_result_destroy(&export_result);
    
    return serialized_cipher_result;
}

wickr_ctx_gen_result_t *wickr_ctx_gen_result_copy(const wickr_ctx_gen_result_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_ctx_t *ctx_copy = wickr_ctx_copy(source->ctx);
    
    if (!ctx_copy) {
        return NULL;
    }
    
    wickr_cipher_key_t *recovery_key_copy = wickr_cipher_key_copy(source->recovery_key);
    
    if (!recovery_key_copy) {
        wickr_ctx_destroy(&ctx_copy);
        return NULL;
    }
    
    wickr_root_keys_t *root_key_copy = wickr_root_keys_copy(source->root_keys);
    
    if (!root_key_copy) {
        wickr_ctx_destroy(&ctx_copy);
        wickr_cipher_key_destroy(&recovery_key_copy);
        return NULL;
    }
    
    wickr_ctx_gen_result_t *result_copy = __wickr_ctx_gen_result_create(ctx_copy, recovery_key_copy, root_key_copy);
    
    if (!result_copy) {
        wickr_ctx_destroy(&ctx_copy);
        wickr_cipher_key_destroy(&recovery_key_copy);
        wickr_root_keys_destroy(&root_key_copy);
    }
    return result_copy;
}

void wickr_ctx_gen_result_destroy(wickr_ctx_gen_result_t **result)
{
    if (!result || !*result) {
        return;
    }
    
    wickr_ctx_destroy(&(*result)->ctx);
    wickr_cipher_key_destroy(&(*result)->recovery_key);
    wickr_root_keys_destroy(&(*result)->root_keys);
    wickr_free(*result);
    *result = NULL;
}

/* Context Functions */

/* Creates a context given parameters that have either been created in memory with ctx_gen or pulled from an encrypted data store using storage_keys */
wickr_ctx_t *wickr_ctx_create(const wickr_crypto_engine_t engine, wickr_dev_info_t *dev_info, wickr_identity_chain_t *id_chain, wickr_storage_keys_t *storage_keys)
{
    if (!dev_info || !id_chain || !storage_keys) {
        return NULL;
    }
    
    wickr_cipher_key_t *packet_header_key = __wickr_ctx_gen_header_key(engine, engine.default_cipher, id_chain);
    
    if (!packet_header_key) {
        return NULL;
    }
    
    wickr_ctx_t *new_ctx = wickr_alloc_zero(sizeof(wickr_ctx_t));
    
    if (!new_ctx) {
        return NULL;
    }
    
    new_ctx->dev_info = dev_info;
    new_ctx->id_chain = id_chain;
    new_ctx->storage_keys = storage_keys;
    new_ctx->packet_header_key = packet_header_key;
    new_ctx->engine = engine;
    new_ctx->pkt_enc_version = DEFAULT_PKT_ENC_VERSION;
    
    if (!new_ctx->packet_header_key) {
        wickr_ctx_destroy(&new_ctx);
        return NULL;
    }
    
    return new_ctx;
}

wickr_ctx_t *wickr_ctx_copy(const wickr_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    
    wickr_dev_info_t *dev_info_copy = wickr_dev_info_copy(ctx->dev_info);
    
    if (!dev_info_copy) {
        return NULL;
    }
    
    wickr_identity_chain_t *id_chain_copy = wickr_identity_chain_copy(ctx->id_chain);
    
    if (!id_chain_copy) {
        wickr_dev_info_destroy(&dev_info_copy);
        return NULL;
    }
    
    wickr_storage_keys_t *storage_keys_copy = wickr_storage_keys_copy(ctx->storage_keys);
    
    if (!storage_keys_copy) {
        wickr_dev_info_destroy(&dev_info_copy);
        wickr_identity_chain_destroy(&id_chain_copy);
        return NULL;
    }
    
    wickr_ctx_t *copy = wickr_ctx_create(ctx->engine, dev_info_copy, id_chain_copy, storage_keys_copy);

    if (!copy) {
        wickr_dev_info_destroy(&dev_info_copy);
        wickr_identity_chain_destroy(&id_chain_copy);
        wickr_storage_keys_destroy(&storage_keys_copy);
    }
    
    copy->pkt_enc_version = ctx->pkt_enc_version;
    
    return copy;
}

void wickr_ctx_destroy(wickr_ctx_t **ctx)
{
    if (!ctx || !*ctx) {
        return;
    }
    
    wickr_dev_info_destroy(&(*ctx)->dev_info);
    wickr_identity_chain_destroy(&(*ctx)->id_chain);
    wickr_storage_keys_destroy(&(*ctx)->storage_keys);
    wickr_cipher_key_destroy(&(*ctx)->packet_header_key);
    
    wickr_free(*ctx);
    *ctx = NULL;
}

/* Exports storage keys for a context using a password + KDF function */
wickr_buffer_t *wickr_ctx_export_storage_keys(const wickr_ctx_t *ctx, const wickr_buffer_t *passphrase)
{
    if (!ctx || !passphrase) {
        return NULL;
    }
    
    wickr_buffer_t *serialized_storage_keys = wickr_storage_keys_serialize(ctx->storage_keys);
    
    if (!serialized_storage_keys) {
        return NULL;
    }
    
    wickr_buffer_t *protected = wickr_crypto_engine_kdf_cipher(&ctx->engine, KDF_SCRYPT_2_17, ctx->engine.default_cipher, serialized_storage_keys, passphrase);
    wickr_buffer_destroy_zero(&serialized_storage_keys);
    
    return protected;
}

wickr_storage_keys_t *wickr_ctx_import_storage_keys(const wickr_crypto_engine_t engine, const wickr_buffer_t *exported, const wickr_buffer_t *passphrase)
{
    if (!exported || !passphrase) {
        return NULL;
    }
    
    wickr_buffer_t *decoded_serialized_keys = wickr_crypto_engine_kdf_decipher(&engine, exported, passphrase);
    
    if (!decoded_serialized_keys) {
        return NULL;
    }
    
    wickr_storage_keys_t *storage_keys = wickr_storage_keys_create_from_buffer(decoded_serialized_keys);
    wickr_buffer_destroy(&decoded_serialized_keys);
    
    return storage_keys;
}

/* Encrypts data using the local storage key */
wickr_cipher_result_t *wickr_ctx_cipher_local(const wickr_ctx_t *ctx, const wickr_buffer_t *plaintext)
{
    if (!ctx || !plaintext) {
        return NULL;
    }
    
    return ctx->engine.wickr_crypto_engine_cipher_encrypt(plaintext, NULL, ctx->storage_keys->local, NULL);
}

wickr_buffer_t *wickr_ctx_decipher_local(const wickr_ctx_t *ctx, const wickr_cipher_result_t *cipher_text)
{
    if (!ctx || !cipher_text) {
        return NULL;
    }
    
    return ctx->engine.wickr_crypto_engine_cipher_decrypt(cipher_text, NULL, ctx->storage_keys->local, true);
}

/* Encrypts data using the remote storage key (used for account level backups such as contact / conversation information) */
wickr_cipher_result_t *wickr_ctx_cipher_remote(const wickr_ctx_t *ctx, const wickr_buffer_t *plaintext)
{
    if (!ctx || !plaintext) {
        return NULL;
    }
    
    return ctx->engine.wickr_crypto_engine_cipher_encrypt(plaintext, NULL, ctx->storage_keys->remote, NULL);
}

wickr_buffer_t *wickr_ctx_decipher_remote(const wickr_ctx_t *ctx, const wickr_cipher_result_t *cipher_text)
{
    if (!ctx || !cipher_text) {
        return NULL;
    }
    
    return ctx->engine.wickr_crypto_engine_cipher_decrypt(cipher_text, NULL, ctx->storage_keys->remote, true);
}

/* Generate ephemeral message keypairs */
wickr_ephemeral_keypair_t *wickr_ctx_ephemeral_keypair_gen(const wickr_ctx_t *ctx, uint64_t key_id)
{
    if (!ctx) {
        return NULL;
    }
    
    return wickr_ephemeral_keypair_generate_identity(&ctx->engine, key_id, ctx->id_chain->node);
}

/* Message Encode / Decode */

wickr_ctx_packet_t *wickr_ctx_packet_create(wickr_packet_t *packet, wickr_identity_chain_t *sender, wickr_parse_result_t *parse_result)
{
    if (!packet || !parse_result || !sender) {
        return NULL;
    }
    
    wickr_ctx_packet_t *ctx_packet = wickr_alloc_zero(sizeof(wickr_ctx_packet_t));
    
    if (!ctx_packet) {
        return NULL;
    }
    
    ctx_packet->packet = packet;
    ctx_packet->sender = sender;
    ctx_packet->parse_result = parse_result;
    
    return ctx_packet;
}

void wickr_ctx_packet_destroy(wickr_ctx_packet_t **packet)
{
    if (!packet || !*packet) {
        return;
    }
    
    wickr_packet_destroy(&(*packet)->packet);
    wickr_identity_chain_destroy(&(*packet)->sender);
    wickr_parse_result_destroy(&(*packet)->parse_result);
    wickr_free(*packet);
    *packet = NULL;
}

wickr_ctx_encode_t *wickr_ctx_encode_create(wickr_cipher_key_t *packet_key, wickr_buffer_t *encoded_packet)
{
    if (!packet_key || !encoded_packet) {
        return NULL;
    }
    
    wickr_ctx_encode_t *new_encode = wickr_alloc_zero(sizeof(wickr_ctx_encode_t));
    
    if (!new_encode) {
        return NULL;
    }
    
    new_encode->packet_key = packet_key;
    new_encode->encoded_packet = encoded_packet;
    
    return new_encode;
}

void wickr_ctx_encode_destroy(wickr_ctx_encode_t **encode)
{
    if (!encode || !*encode) {
        return;
    }
    
    wickr_cipher_key_destroy(&(*encode)->packet_key);
    wickr_buffer_destroy(&(*encode)->encoded_packet);
    wickr_free(*encode);
    *encode = NULL;
}

wickr_ctx_encode_t *wickr_ctx_encode_packet(const wickr_ctx_t *ctx, const wickr_payload_t *payload, const wickr_node_array_t *nodes)
{
    if (!ctx || !payload || !nodes) {
        return NULL;
    }
    
    /* Generate a random key to encode the payload for this packet */
    wickr_cipher_key_t *rnd_payload_key = ctx->engine.wickr_crypto_engine_cipher_key_random(ctx->engine.default_cipher);
    
    if (!rnd_payload_key) {
        return NULL;
    }
    
    /* Generate a random ec key pair to use for the key exchanges for this packet */
    wickr_ec_key_t *rnd_exchange_key = ctx->engine.wickr_crypto_engine_ec_rand_key(ctx->engine.default_curve);
    
    if (!rnd_exchange_key) {
        wickr_cipher_key_destroy(&rnd_payload_key);
        return NULL;
    }
    
    /* Pass our keys, payload, and recipient information to the packet generation function */
    wickr_packet_t *generated_packet = wickr_packet_create_from_components(&ctx->engine, ctx->packet_header_key, rnd_payload_key, rnd_exchange_key, payload, nodes, ctx->id_chain, ctx->pkt_enc_version);
    
    wickr_ec_key_destroy(&rnd_exchange_key);
    
    /* Serialize the packet */
    wickr_buffer_t *serialized_packet = wickr_packet_serialize(generated_packet);
    wickr_packet_destroy(&generated_packet);
    
    wickr_ctx_encode_t *ctx_encode = wickr_ctx_encode_create(rnd_payload_key, serialized_packet);
    
    if (!ctx_encode) {
        wickr_cipher_key_destroy(&rnd_payload_key);
        wickr_buffer_destroy(&serialized_packet);
    }
    
    return ctx_encode;
    
}

static wickr_ctx_packet_t *__wickr_ctx_read_packet(const wickr_ctx_t *ctx, const wickr_buffer_t *packet_buffer, const wickr_identity_chain_t *sender, bool for_decode)
{
    if (!ctx || !packet_buffer) {
        return NULL;
    }
    
    wickr_packet_t *packet = wickr_packet_create_from_buffer(packet_buffer);
    
    if (!packet) {
        return NULL;
    }
    
    /* If we just want to parse the packet structure, and not search for our node, pass null for receiver_node_id */
    wickr_buffer_t *node_search_id = for_decode ? ctx->id_chain->node->identifier : NULL;
    
    wickr_parse_result_t *result = wickr_parse_result_from_packet(&ctx->engine, packet, node_search_id, __wickr_ctx_gen_header_key, sender);
    
    if (!result) {
        wickr_packet_destroy(&packet);
        return NULL;
    }
    
    wickr_identity_chain_t *chain_copy = wickr_identity_chain_copy(sender);
    
    if (!chain_copy) {
        wickr_packet_destroy(&packet);
        wickr_parse_result_destroy(&result);
        return NULL;
    }
    
    wickr_ctx_packet_t *ctx_packet = wickr_ctx_packet_create(packet, chain_copy, result);
    
    if (!ctx_packet) {
        wickr_identity_chain_destroy(&chain_copy);
        wickr_packet_destroy(&packet);
        wickr_parse_result_destroy(&result);
    }
    
    return ctx_packet;
}

wickr_ctx_packet_t *wickr_ctx_parse_packet(const wickr_ctx_t *ctx, const wickr_buffer_t *packet_buffer, const wickr_identity_chain_t *sender)
{
    return __wickr_ctx_read_packet(ctx, packet_buffer, sender, true);
}

wickr_ctx_packet_t *wickr_ctx_parse_packet_no_decode(const wickr_ctx_t *ctx, const wickr_buffer_t *packet_buffer, const wickr_identity_chain_t *sender)
{
    return __wickr_ctx_read_packet(ctx, packet_buffer, sender, false);
}

wickr_decode_result_t *wickr_ctx_decode_packet(const wickr_ctx_t *ctx, const wickr_ctx_packet_t *packet, wickr_ec_key_t *keypair)
{
    if (!ctx || !packet || !packet->parse_result) {
        return NULL;
    }
    
    return wickr_decode_result_from_parse_result(packet->packet, &ctx->engine, packet->parse_result, ctx->dev_info->msg_proto_id, keypair, ctx->id_chain, packet->sender);
}
