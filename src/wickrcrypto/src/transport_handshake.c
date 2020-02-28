
#include "transport_handshake.h"
#include "memory.h"
#include "private/transport_priv.h"
#include "private/identity_priv.h"
#include "private/transport_handshake_priv.h"
#include "transport_root_key.h"
#include "private/buffer_priv.h"
#include "ecdh_cipher_ctx.h"
#include "private/transport_root_key_priv.h"
#include "private/buffer_priv.h"
#include "transport_packet.h"

struct wickr_transport_handshake_res_t {
    wickr_stream_key_t *local_key;
    wickr_stream_key_t *remote_key;
};

wickr_transport_handshake_res_t *wickr_transport_handshake_res_create(wickr_stream_key_t *local_key,
                                                                      wickr_stream_key_t *remote_key)
{
    if (!local_key || !remote_key) {
        return NULL;
    }
    
    wickr_transport_handshake_res_t *result = wickr_alloc_zero(sizeof(wickr_transport_handshake_res_t));
    
    if (!result) {
        return NULL;
    }
    
    result->local_key = local_key;
    result->remote_key = remote_key;
    
    return result;
}

wickr_transport_handshake_res_t *wickr_transport_handshake_res_copy(const wickr_transport_handshake_res_t *res)
{
    if (!res) {
        return NULL;
    }
    
    wickr_stream_key_t *local_copy = wickr_stream_key_copy(res->local_key);
    wickr_stream_key_t *remote_copy = wickr_stream_key_copy(res->remote_key);
    
    if (!local_copy || !remote_copy) {
        wickr_stream_key_destroy(&local_copy);
        wickr_stream_key_destroy(&remote_copy);
        return NULL;
    }
    
    wickr_transport_handshake_res_t *copy = wickr_transport_handshake_res_create(local_copy, remote_copy);
    
    if (!copy) {
        wickr_stream_key_destroy(&local_copy);
        wickr_stream_key_destroy(&remote_copy);
    }
    
    return copy;
}

void wickr_transport_handshake_res_destroy(wickr_transport_handshake_res_t **res)
{
    if (!res || !*res) {
        return;
    }
    
    wickr_stream_key_destroy(&(*res)->local_key);
    wickr_stream_key_destroy(&(*res)->remote_key);
    
    wickr_free(*res);
    *res = NULL;
}

const wickr_stream_key_t *wickr_transport_handshake_res_get_local_key(const wickr_transport_handshake_res_t *res)
{
    return res ? res->local_key : NULL;
}

const wickr_stream_key_t *wickr_transport_handshake_res_get_remote_key(const wickr_transport_handshake_res_t *res)
{
    return res ? res->remote_key : NULL;
}

static wickr_transport_handshake_t *__wickr_transport_handshake_create(wickr_crypto_engine_t engine,
                                                                       wickr_identity_chain_t *local_identity,
                                                                       wickr_identity_chain_t *remote_identity,
                                                                       wickr_array_t *packet_list,
                                                                       wickr_transport_handshake_identity_callback identity_callback,
                                                                       uint32_t evo_count,
                                                                       void *user)
{
    if (!local_identity || identity_callback == 0 || !packet_list || evo_count == 0) {
        return NULL;
    }
    
    wickr_transport_handshake_t *handshake = wickr_alloc_zero(sizeof(wickr_transport_handshake_t));
    
    if (!handshake) {
        return NULL;
    }
    
    handshake->user = user;
    handshake->engine = engine;
    handshake->is_initiator = false;
    handshake->protocol_version = 1;
    handshake->local_identity = local_identity;
    handshake->remote_identity = remote_identity;
    handshake->identity_callback = identity_callback;
    handshake->packet_list = packet_list;
    handshake->evo_count = evo_count;
    handshake->status = TRANSPORT_HANDSHAKE_STATUS_UNKNOWN;
    
    return handshake;
}

wickr_transport_handshake_t *wickr_transport_handshake_create(wickr_crypto_engine_t engine,
                                                              wickr_identity_chain_t *local_identity,
                                                              wickr_identity_chain_t *remote_identity,
                                                              wickr_transport_handshake_identity_callback identity_callback,
                                                              uint32_t evo_count,
                                                              void *user)
{
    wickr_array_t *packet_list = wickr_array_new(2,
                                                 0,
                                                 (wickr_array_copy_func)wickr_buffer_copy,
                                                 (wickr_array_destroy_func)wickr_buffer_destroy);
    
    if (!packet_list) {
        return NULL;
    }
    
    wickr_transport_handshake_t *return_handshake = __wickr_transport_handshake_create(engine, local_identity,
                                                                                       remote_identity, packet_list,
                                                                                       identity_callback, evo_count, user);
    
    if (!return_handshake) {
        wickr_array_destroy(&packet_list, true);
    }
    
    return return_handshake;
}

wickr_transport_handshake_t *wickr_transport_handshake_copy(const wickr_transport_handshake_t *handshake)
{
    if (!handshake) {
        return NULL;
    }
    
    wickr_identity_chain_t *local_copy = wickr_identity_chain_copy(handshake->local_identity);
    wickr_identity_chain_t *remote_copy = wickr_identity_chain_copy(handshake->remote_identity);
    wickr_array_t *packet_list_copy = wickr_array_copy(handshake->packet_list, true);
    
    if (!local_copy ||
        (!remote_copy && handshake->remote_identity) ||
        !packet_list_copy) {
        wickr_identity_chain_destroy(&local_copy);
        wickr_identity_chain_destroy(&remote_copy);
        wickr_array_destroy(&packet_list_copy, true);
        return NULL;
    }
    
    wickr_transport_handshake_t *copy = __wickr_transport_handshake_create(handshake->engine,
                                                                           local_copy,
                                                                           remote_copy,
                                                                           packet_list_copy,
                                                                           handshake->identity_callback,
                                                                           handshake->evo_count,
                                                                           handshake->user);
    
    if (!copy) {
        wickr_identity_chain_destroy(&local_copy);
        wickr_identity_chain_destroy(&remote_copy);
        wickr_array_destroy(&packet_list_copy, true);
        return NULL;
    }
    
    wickr_transport_root_key_t *root_key_copy = wickr_transport_root_key_copy(handshake->root_key);
    
    if (handshake->root_key && !root_key_copy) {
        wickr_transport_handshake_destroy(&copy);
        return NULL;
    }
    
    wickr_transport_packet_t *transport_packet_copy = wickr_transport_packet_copy(handshake->pending_identity_verify_packet);
    
    if (handshake->pending_identity_verify_packet && !transport_packet_copy) {
        wickr_transport_root_key_destroy(&root_key_copy);
        wickr_transport_handshake_destroy(&copy);
        return NULL;
    }
    
    wickr_ec_key_t *local_ephemeral_key_copy = wickr_ec_key_copy(handshake->local_ephemeral_key);
    
    if (handshake->local_ephemeral_key && !local_ephemeral_key_copy) {
        wickr_transport_root_key_destroy(&root_key_copy);
        wickr_transport_handshake_destroy(&copy);
        wickr_transport_packet_destroy(&transport_packet_copy);
        return NULL;
    }
    
    copy->local_ephemeral_key = local_ephemeral_key_copy;
    copy->pending_identity_verify_packet = transport_packet_copy;
    copy->root_key = root_key_copy;
    copy->status = handshake->status;
    copy->is_initiator = handshake->is_initiator;
    copy->protocol_version = handshake->protocol_version;
    
    return copy;
}

void wickr_transport_handshake_destroy(wickr_transport_handshake_t **handshake)
{
    if (!handshake || !*handshake) {
        return;
    }
    
    wickr_identity_chain_destroy(&(*handshake)->local_identity);
    wickr_identity_chain_destroy(&(*handshake)->remote_identity);
    wickr_array_destroy(&(*handshake)->packet_list, true);
    wickr_ec_key_destroy(&(*handshake)->local_ephemeral_key);
    wickr_transport_root_key_destroy(&(*handshake)->root_key);
    wickr_transport_packet_destroy(&(*handshake)->pending_identity_verify_packet);
    
    wickr_free(*handshake);
    *handshake = NULL;
}

static wickr_transport_packet_t *__wickr_transport_handshake_build_signed_packet(wickr_transport_handshake_t *handshake,
                                                                                 const Wickr__Proto__HandshakeV1 *packet_proto,
                                                                                 uint8_t packet_num)
{
    wickr_transport_packet_t *handshake_pkt = wickr_proto_handshake_to_packet(packet_proto);
    
    /* Sign the handshake packet */
    if (!handshake_pkt || !wickr_transport_packet_sign(handshake_pkt, &handshake->engine, handshake->local_identity)) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    /* Record this packet into the packet list for later use */
    wickr_array_set_item(handshake->packet_list, packet_num, handshake_pkt->network_buffer, true); //TODO: Use hash builder instead of array
    
    return handshake_pkt;
}

wickr_transport_packet_t *wickr_transport_handshake_start(wickr_transport_handshake_t *handshake)
{
    if (!handshake) {
        return NULL;
    }
    
    if (handshake->status != TRANSPORT_HANDSHAKE_STATUS_UNKNOWN) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    handshake->is_initiator = true;
    handshake->status = TRANSPORT_HANDSHAKE_STATUS_IN_PROGRESS;
    
    /* Generate a new ephemeral key for the handshake */
    handshake->local_ephemeral_key = handshake->engine.wickr_crypto_engine_ec_rand_key(handshake->engine.default_curve);
    
    if (!handshake->local_ephemeral_key) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
        
    /* Create a seed handshake packet */
    
    bool needs_remote_identity = handshake->remote_identity == NULL ? true : false;
    
    Wickr__Proto__HandshakeV1__Seed *seed = wickr_proto_handshake_seed_create(handshake->local_identity,
                                                                              handshake->local_ephemeral_key->pub_data,
                                                                              needs_remote_identity);
    
    if (!seed) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    Wickr__Proto__HandshakeV1 *handshake_seed = wickr_proto_handshake_create_with_seed(seed);
    
    if (!handshake_seed) {
        wickr_proto_handshake_seed_free(seed);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    wickr_transport_packet_t *handshake_pkt = __wickr_transport_handshake_build_signed_packet(handshake, handshake_seed, 0);
    wickr_proto_handshake_free(handshake_seed);
    
    if (!handshake_pkt) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    return handshake_pkt;
}

static wickr_kdf_meta_t *__wickr_transport_handshake_kdf_meta_gen(wickr_transport_handshake_t *handshake,
                                                                  wickr_ec_key_t *local_ephemeral,
                                                                  wickr_ec_key_t *remote_ephemeral)
{
    wickr_buffer_t *local_identity_data = wickr_identity_chain_serialize(handshake->local_identity);
    
    if (!local_identity_data) {
        return NULL;
    }
    
    wickr_buffer_t *remote_identity_data = wickr_identity_chain_serialize(handshake->remote_identity);

    if (!remote_identity_data) {
        wickr_buffer_destroy(&local_identity_data);
        return NULL;
    }
    
    wickr_buffer_t *components[4];
    
    if (handshake->is_initiator) {
        components[0] = local_identity_data;
        components[1] = remote_identity_data;
        components[2] = local_ephemeral->pub_data;
        components[3] = remote_ephemeral->pub_data;
    } else {
        components[0] = remote_identity_data;
        components[1] = local_identity_data;
        components[2] = remote_ephemeral->pub_data;
        components[3] = local_ephemeral->pub_data;
    }
    
    wickr_buffer_t *info_data = wickr_buffer_concat_multi(components, 4);
    
    wickr_buffer_destroy(&local_identity_data);
    wickr_buffer_destroy(&remote_identity_data);
    
    if (!info_data) {
        return NULL;
    }
    
    /* Reduce the size of info with a hash, because max length is 1024 for HKDF info */
    wickr_buffer_t *hashed_info = handshake->engine.wickr_crypto_engine_digest(info_data, NULL, DIGEST_SHA_512);
    wickr_buffer_destroy(&info_data);
    
    if (!hashed_info) {
        return NULL;
    }
    
    wickr_kdf_meta_t *kdf_meta = wickr_kdf_meta_create(KDF_HKDF_SHA512, NULL, hashed_info);
    
    if (!kdf_meta) {
        wickr_buffer_destroy(&info_data);
    }
    
    return kdf_meta;
}

static bool __wickr_transport_handshake_process_remote_identity(wickr_transport_handshake_t *handshake,
                                                                const wickr_transport_packet_t *packet,
                                                                const Wickr__Proto__IdentityChain *remote_identity_proto)
{
    /* If there is no identity set, we need to set it so that we can ask the user to verify it's authenticity later */
    if (!handshake->remote_identity) {
        handshake->remote_identity = wickr_identity_chain_create_from_proto(remote_identity_proto, &handshake->engine);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_PENDING_VERIFICATION;
        if (!handshake->remote_identity) {
            return false;
        }
    }
    
    /* Verify the authenticity of the packet */
    return wickr_transport_packet_verify(packet, &handshake->engine, handshake->remote_identity);
    
}

static void __wickr_transport_handshake_process_response(wickr_transport_handshake_t *handshake,
                                                         const wickr_transport_packet_t *packet)
{
    /* Record this packet into the packet list for later use */
    wickr_array_set_item(handshake->packet_list, 1, packet->network_buffer, true); //TODO: Use hash builder instead of array
    
    Wickr__Proto__HandshakeV1 *handshake_data = wickr_proto_handshake_from_packet(packet);
    
    if (!handshake_data) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return;
    }
    
    if (!handshake_data->response ||
        !handshake_data->response->has_encrypted_response_data ||
        !handshake_data->response->has_ephemeral_pubkey) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        return;
    }
    
    if (!handshake->remote_identity && !handshake_data->response->id_chain) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        return;
    }
    
    wickr_buffer_t *encrypted_data = wickr_buffer_from_protobytes(handshake_data->response->encrypted_response_data);
    
    wickr_cipher_result_t *encrypted_obj = wickr_cipher_result_from_buffer(encrypted_data);
    wickr_buffer_destroy(&encrypted_data);
    
    if (!encrypted_obj) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        return;
    }
    
    wickr_ec_key_t *local_key_copy = wickr_ec_key_copy(handshake->local_ephemeral_key);
    
    if (!local_key_copy) {
        wickr_cipher_result_destroy(&encrypted_obj);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        return;
    }
    
    wickr_ecdh_cipher_ctx_t *cipher_ctx = wickr_ecdh_cipher_ctx_create_key(handshake->engine,
                                                                           local_key_copy,
                                                                           encrypted_obj->cipher);
    
    if (!cipher_ctx) {
        wickr_ec_key_destroy(&local_key_copy);
        wickr_cipher_result_destroy(&encrypted_obj);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        return;
    }
    
    wickr_buffer_t *remote_ephemeral = wickr_buffer_from_protobytes(handshake_data->response->ephemeral_pubkey);
    wickr_ec_key_t *remote_ephemeral_key = handshake->engine.wickr_crypto_engine_ec_key_import(remote_ephemeral, false);
    
    wickr_buffer_destroy(&remote_ephemeral);
    
    if (!remote_ephemeral_key) {
        wickr_ecdh_cipher_ctx_destroy(&cipher_ctx);
        wickr_cipher_result_destroy(&encrypted_obj);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        return;
    }
    
    if (!__wickr_transport_handshake_process_remote_identity(handshake, packet, handshake_data->response->id_chain)) {
        wickr_ecdh_cipher_ctx_destroy(&cipher_ctx);
        wickr_cipher_result_destroy(&encrypted_obj);
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        wickr_ec_key_destroy(&remote_ephemeral_key);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return;
    }
    
    wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
    
    wickr_kdf_meta_t *kdf_meta = __wickr_transport_handshake_kdf_meta_gen(handshake, handshake->local_ephemeral_key, remote_ephemeral_key);
    
    if (!kdf_meta) {
        wickr_ec_key_destroy(&remote_ephemeral_key);
        wickr_ecdh_cipher_ctx_destroy(&cipher_ctx);
        wickr_cipher_result_destroy(&encrypted_obj);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return;
    }
    
    wickr_buffer_t *response_buffer = wickr_ecdh_cipher_ctx_decipher(cipher_ctx,
                                                                     encrypted_obj,
                                                                     remote_ephemeral_key,
                                                                     kdf_meta);
    
    wickr_ec_key_destroy(&remote_ephemeral_key);
    wickr_kdf_meta_destroy(&kdf_meta);
    wickr_ecdh_cipher_ctx_destroy(&cipher_ctx);
    wickr_cipher_result_destroy(&encrypted_obj);
    
    if (!response_buffer) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return;
    }
    
    Wickr__Proto__HandshakeV1ResponseData *response_data = wickr_proto_handshake_response_data_from_buffer(response_buffer);
    wickr_buffer_destroy(&response_buffer);
    
    if (!response_data || !response_data->root_key) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return;
    }
    
    handshake->root_key = wickr_transport_root_key_from_proto(response_data->root_key);
    wickr__proto__handshake_v1_response_data__free_unpacked(response_data, NULL);
    
    if (!handshake->root_key) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return;
    }
    
    if (handshake->status == TRANSPORT_HANDSHAKE_STATUS_IN_PROGRESS) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION;
    }
}

static wickr_transport_packet_t *__wickr_transport_handshake_process_initial(wickr_transport_handshake_t *handshake,
                                                                             const wickr_transport_packet_t *packet)
{
    /* Record this packet into the packet list for later use */
    wickr_array_set_item(handshake->packet_list, 0, packet->network_buffer, true); //TODO: Use hash builder instead of array
    
    Wickr__Proto__HandshakeV1 *handshake_data = wickr_proto_handshake_from_packet(packet);
    
    if (!handshake_data || !handshake_data->seed || !handshake_data->seed->has_ephemeral_pubkey
        || !handshake_data->seed->has_identity_required) {
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    if (!__wickr_transport_handshake_process_remote_identity(handshake, packet, handshake_data->seed->id_chain)) {
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    wickr_buffer_t *key_data = wickr_buffer_from_protobytes(handshake_data->seed->ephemeral_pubkey);
    
    /* Encrypt a response to the ephemeral key provided by the handshake seed */
    
    if (!key_data) {
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    wickr_ec_key_t *ephemeral_key = handshake->engine.wickr_crypto_engine_ec_key_import(key_data, false);
    wickr_buffer_destroy(&key_data);
    
    if (!ephemeral_key) {
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    wickr_ecdh_cipher_ctx_t *cipher_ctx = wickr_ecdh_cipher_ctx_create(handshake->engine, ephemeral_key->curve, handshake->engine.default_cipher);
    
    if (!cipher_ctx) {
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        wickr_ec_key_destroy(&ephemeral_key);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    /* Generate a root key to use for the handshake. In the future, we will allow the initiator to specify their own evo_count
       for now, the receiver who is specifying the root key material will dictate both */
    handshake->root_key = wickr_transport_root_key_create_random(&handshake->engine, handshake->engine.default_cipher,
                                                                 handshake->evo_count, handshake->evo_count);
    
    if (!handshake->root_key) {
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    Wickr__Proto__HandshakeV1ResponseData *response_data = wickr_proto_handshake_response_data_create(handshake->root_key);
    
    if (!response_data) {
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        wickr_ecdh_cipher_ctx_destroy(&cipher_ctx);
        wickr_ec_key_destroy(&ephemeral_key);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    wickr_buffer_t *serialized_response_data = wickr_proto_handshake_response_data_serialize(response_data);
    wickr_proto_handshake_response_data_free(response_data);
    
    if (!serialized_response_data) {
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        wickr_ecdh_cipher_ctx_destroy(&cipher_ctx);
        wickr_ec_key_destroy(&ephemeral_key);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
        
    wickr_kdf_meta_t *kdf_meta = __wickr_transport_handshake_kdf_meta_gen(handshake, cipher_ctx->local_key, ephemeral_key);
    wickr_cipher_result_t *result = wickr_ecdh_cipher_ctx_cipher(cipher_ctx, serialized_response_data, ephemeral_key, kdf_meta);
    
    wickr_kdf_meta_destroy(&kdf_meta);
    wickr_buffer_destroy(&serialized_response_data);
    wickr_ec_key_destroy(&ephemeral_key);
    
    if (!result) {
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        wickr_ecdh_cipher_ctx_destroy(&cipher_ctx);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    wickr_buffer_t *response_buffer = wickr_cipher_result_serialize(result);
    wickr_cipher_result_destroy(&result);
    
    if (!response_buffer) {
        wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
        wickr_ecdh_cipher_ctx_destroy(&cipher_ctx);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    wickr_identity_chain_t *response_identity = handshake_data->seed->identity_required ? handshake->local_identity : NULL;
    
    Wickr__Proto__HandshakeV1__Response *response = wickr_proto_handshake_response_create(cipher_ctx->local_key->pub_data,
                                                                                          response_buffer, response_identity);
    
    wickr__proto__handshake_v1__free_unpacked(handshake_data, NULL);
    wickr_ecdh_cipher_ctx_destroy(&cipher_ctx);
    wickr_buffer_destroy(&response_buffer);
    
    Wickr__Proto__HandshakeV1 *handshake_return = wickr_proto_handshake_create_with_response(response);
    
    if (!handshake_return) {
        wickr_proto_handshake_response_free(response);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    wickr_transport_packet_t *handshake_pkt = __wickr_transport_handshake_build_signed_packet(handshake, handshake_return, 1);
    wickr_proto_handshake_free(handshake_return);
    
    if (!handshake_pkt) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    if (handshake->status == TRANSPORT_HANDSHAKE_STATUS_UNKNOWN) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION;
    }
    
    return handshake_pkt;
}

static wickr_transport_packet_t *__wickr_transport_handshake_process_packet(wickr_transport_handshake_t *handshake, const wickr_transport_packet_t *packet)
{
    if (!handshake || !packet) {
        return NULL;
    }
    
    switch (handshake->status) {
        case TRANSPORT_HANDSHAKE_STATUS_UNKNOWN:
            return __wickr_transport_handshake_process_initial(handshake, packet);
        case TRANSPORT_HANDSHAKE_STATUS_IN_PROGRESS:
            __wickr_transport_handshake_process_response(handshake, packet);
            return NULL;
        default:
            handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
            return NULL;
    }
}

wickr_transport_packet_t *wickr_transport_handshake_verify_identity(const wickr_transport_handshake_t *handshake, bool is_valid)
{
    wickr_transport_handshake_t *_handshake = (wickr_transport_handshake_t *)handshake;
    
    if (!_handshake) {
        return NULL;
    }
    
    if (!is_valid || handshake->status != TRANSPORT_HANDSHAKE_STATUS_PENDING_VERIFICATION) {
        _handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        wickr_transport_root_key_destroy(&_handshake->root_key);
        return NULL;
    }
    
    if (_handshake->root_key) {
        _handshake->status = TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION;
    } else {
        _handshake->status = TRANSPORT_HANDSHAKE_STATUS_IN_PROGRESS;
    }
    
    wickr_transport_packet_t *return_packet = _handshake->pending_identity_verify_packet;
    _handshake->pending_identity_verify_packet = NULL;
    
    return return_packet;
}

wickr_transport_packet_t *wickr_transport_handshake_process(wickr_transport_handshake_t *handshake,
                                                            const wickr_transport_packet_t *packet)
{
    if (!handshake) {
        return NULL;
    }
    
    /* Make sure the packet is the right version */
    if (!packet || packet->meta.body_meta.handshake.protocol_version != handshake->protocol_version) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    /* Don't allow any further processing if we are in the wrong state */

    switch (handshake->status) {
        case TRANSPORT_HANDSHAKE_STATUS_UNKNOWN:
        case TRANSPORT_HANDSHAKE_STATUS_IN_PROGRESS:
            break;
        default:
            handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
            return NULL;
    }
    
    /* Process the packet first to ensure all remote identity information is established */
    wickr_transport_packet_t *return_packet = __wickr_transport_handshake_process_packet(handshake, packet);
    
    /* If processing failed, no more processing is necessary */
    if (handshake->status == TRANSPORT_HANDSHAKE_STATUS_FAILED) {
        return NULL;
    }
    
    /* If we are pending identity verification, perform that now */
    if (handshake->status == TRANSPORT_HANDSHAKE_STATUS_PENDING_VERIFICATION) {
        
        handshake->pending_identity_verify_packet = return_packet;
        
        wickr_identity_chain_t *identity_chain_copy = wickr_identity_chain_copy(handshake->remote_identity);
        
        if (handshake->status == TRANSPORT_HANDSHAKE_STATUS_FAILED || identity_chain_copy == NULL) {
            return NULL;
        }
        
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_PENDING_VERIFICATION;
        handshake->identity_callback((const wickr_transport_handshake_t *)handshake, identity_chain_copy, handshake->user);
        
        return NULL;
    } else {
        return return_packet;
    }
    
}

wickr_transport_handshake_res_t *wickr_transport_handshake_finalize(wickr_transport_handshake_t *handshake)
{
    if (!handshake) {
        return NULL;
    }
    
    if (!handshake->root_key || handshake->status != TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    wickr_buffer_t *transcript_data = wickr_buffer_concat(wickr_array_fetch_item(handshake->packet_list, 0, false), wickr_array_fetch_item(handshake->packet_list, 1, false));
    
    if (!transcript_data) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    wickr_buffer_t *transcript_hash = handshake->engine.wickr_crypto_engine_digest(transcript_data, NULL, DIGEST_SHA_512);
    wickr_buffer_destroy(&transcript_data);
    
    if (!transcript_hash) {
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    wickr_buffer_t sender_info = { .bytes = (uint8_t *)"sender", .length = 6 };
    wickr_buffer_t receiver_info = { .bytes = (uint8_t *)"receiver", .length = 8};
    
    wickr_stream_key_t *sender_key = wickr_transport_root_key_to_stream_key(handshake->root_key,
                                                                            &handshake->engine,
                                                                            transcript_hash,
                                                                            &sender_info,
                                                                            STREAM_DIRECTION_ENCODE);
    
    wickr_stream_key_t *receiver_key = wickr_transport_root_key_to_stream_key(handshake->root_key,
                                                                              &handshake->engine,
                                                                              transcript_hash,
                                                                              &receiver_info,
                                                                              STREAM_DIRECTION_DECODE);
    
    wickr_buffer_destroy(&transcript_hash);
    
    wickr_transport_handshake_res_t *result;
    
    if (handshake->is_initiator) {
        result = wickr_transport_handshake_res_create(sender_key, receiver_key);
    } else {
        result = wickr_transport_handshake_res_create(receiver_key, sender_key);
    }
    
    if (!result) {
        wickr_stream_key_destroy(&sender_key);
        wickr_stream_key_destroy(&receiver_key);
        handshake->status = TRANSPORT_HANDSHAKE_STATUS_FAILED;
        return NULL;
    }
    
    handshake->status = TRANSPORT_HANDSHAKE_STATUS_COMPLETE;
    
    return result;
}

const wickr_transport_handshake_status wickr_transport_handshake_get_status(const wickr_transport_handshake_t *handshake)
{
    return handshake ? handshake->status : TRANSPORT_HANDSHAKE_STATUS_UNKNOWN;
}

const wickr_identity_chain_t *wickr_transport_handshake_get_local_identity(const wickr_transport_handshake_t *handshake)
{
    return handshake ? handshake->local_identity : NULL;
}

const wickr_identity_chain_t *wickr_transport_handshake_get_remote_identity(const wickr_transport_handshake_t *handshake)
{
    return handshake ? handshake->remote_identity : NULL;
}

const void *wickr_transport_handshake_get_user_data(const wickr_transport_handshake_t *handshake)
{
    return handshake ? handshake->user : NULL;
}

void wickr_transport_set_user_data(wickr_transport_handshake_t *handshake, void *user)
{
    if (!handshake) {
        return;
    }
    handshake->user = user;
}
