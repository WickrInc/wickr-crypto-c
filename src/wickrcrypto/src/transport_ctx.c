//
//  stream.c
//  Crypto
//
//  Created by Tom Leavy on 4/11/17.
//
//

#include "transport_ctx.h"
#include "memory.h"
#include "stream.pb-c.h"
#include "stream_ctx.h"
#include "protocol.h"
#include "private/transport_priv.h"
#include "private/node_priv.h"
#include "private/identity_priv.h"
#include "private/ephemeral_keypair_priv.h"

static uint8_t __wickr_handshake_version_to_key_exchange(uint8_t handshake_version)
{
    switch (handshake_version) {
        case 1:
            return 4;
            break;
        default:
            return 0;
    }
}

static void __wickr_transport_ctx_update_status(wickr_transport_ctx_t *ctx, wickr_transport_status status)
{
    if (!ctx) {
        return;
    }
    
    ctx->status = status;
    ctx->callbacks.on_state(ctx, status, ctx->user);
}

static bool __wickr_transport_ctx_set_tx_stream(wickr_transport_ctx_t *ctx, wickr_stream_ctx_t *tx_stream)
{
    if (!ctx || !tx_stream || tx_stream->direction != STREAM_DIRECTION_ENCODE) {
        return false;
    }
    
    /* Make sure the new stream is picking up with the sequence number of the existing stream if necessary */
    if (ctx->tx_stream && tx_stream) {
        tx_stream->last_seq = ctx->tx_stream->last_seq;
    }
    
    wickr_stream_ctx_destroy(&ctx->tx_stream);
    ctx->tx_stream = tx_stream;
    
    return wickr_stream_ctx_ref_up(tx_stream);
}

static wickr_stream_ctx_t *__wickr_transport_ctx_rand_tx_stream(wickr_transport_ctx_t *ctx, wickr_buffer_t *user_data)
{
    if (!ctx) {
        return NULL;
    }
    
    wickr_stream_key_t *stream_key = wickr_stream_key_create_rand(ctx->engine,
                                                                  ctx->engine.default_cipher,
                                                                  PACKET_PER_EVO_DEFAULT);
    
    if (!stream_key) {
        return NULL;
    }
    
    stream_key->user_data = wickr_buffer_copy(user_data);
    
    if (!stream_key->user_data && user_data) {
        wickr_stream_key_destroy(&stream_key);
        return NULL;
    }
    
    wickr_stream_ctx_t *tx_stream = wickr_stream_ctx_create(ctx->engine, stream_key, STREAM_DIRECTION_ENCODE);
    
    if (!tx_stream) {
        wickr_stream_key_destroy(&stream_key);
    }
    
    return tx_stream;
}

wickr_transport_ctx_t *wickr_transport_ctx_create(const wickr_crypto_engine_t engine, wickr_node_t *local_identity, wickr_node_t *remote_identity, uint32_t evo_count, wickr_transport_callbacks_t callbacks, void *user)
{
    if (!local_identity) {
        return NULL;
    }
    
    if (evo_count != 0 && (evo_count > PACKET_PER_EVO_MAX || evo_count < PACKET_PER_EVO_MIN)) {
        return NULL;
    }
    
    wickr_transport_ctx_t *ctx = wickr_alloc_zero(sizeof(wickr_transport_ctx_t));
    
    if (!ctx) {
        return NULL;
    }
    
    ctx->status = TRANSPORT_STATUS_NONE;
    ctx->engine = engine;
    ctx->local_identity = local_identity;
    ctx->remote_identity = remote_identity;
    ctx->callbacks = callbacks;
    ctx->evo_count = evo_count == 0 ? PACKET_PER_EVO_DEFAULT : evo_count;
    ctx->user = user;
    ctx->data_flow = TRANSPORT_DATA_FLOW_BIDIRECTIONAL;
    
    return ctx;
}

wickr_transport_ctx_t *wickr_transport_ctx_copy(const wickr_transport_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    
    wickr_node_t *local_copy = wickr_node_copy(ctx->local_identity);
    
    if (!local_copy) {
        return NULL;
    }
    
    wickr_node_t *remote_copy = wickr_node_copy(ctx->remote_identity);
    
    if (!remote_copy) {
        wickr_node_destroy(&local_copy);
        return NULL;
    }
    
    wickr_stream_ctx_t *tx_copy = wickr_stream_ctx_copy(ctx->tx_stream);
    
    if (!tx_copy && ctx->tx_stream) {
        wickr_node_destroy(&local_copy);
        wickr_node_destroy(&remote_copy);
        return NULL;
    }
    
    wickr_stream_ctx_t *rx_copy = wickr_stream_ctx_copy(ctx->rx_stream);
    
    if (!rx_copy && ctx->rx_stream) {
        wickr_node_destroy(&local_copy);
        wickr_node_destroy(&remote_copy);
        wickr_stream_ctx_destroy(&tx_copy);
        return NULL;
    }
    
    wickr_transport_ctx_t *copy = wickr_alloc_zero(sizeof(wickr_transport_ctx_t));
    
    if (!copy) {
        wickr_node_destroy(&local_copy);
        wickr_node_destroy(&remote_copy);
        wickr_stream_ctx_destroy(&tx_copy);
        wickr_stream_ctx_destroy(&rx_copy);
        return NULL;
    }
    
    copy->engine = ctx->engine;
    copy->local_identity = local_copy;
    copy->remote_identity = remote_copy;
    copy->tx_stream = tx_copy;
    copy->rx_stream = rx_copy;
    copy->status = ctx->status;
    copy->callbacks = ctx->callbacks;
    copy->evo_count = ctx->evo_count;
    copy->user = ctx->user;
    copy->data_flow = ctx->data_flow;
    
    return copy;
}

void wickr_transport_ctx_destroy(wickr_transport_ctx_t **ctx)
{
    if (!ctx || !*ctx) {
        return;
    }
    
    wickr_node_destroy(&(*ctx)->local_identity);
    wickr_node_destroy(&(*ctx)->remote_identity);
    wickr_stream_ctx_destroy(&(*ctx)->tx_stream);
    wickr_stream_ctx_destroy(&(*ctx)->rx_stream);
    
    wickr_free(*ctx);
    *ctx = NULL;
}

static wickr_transport_packet_t *__wickr_transport_ctx_handshake_generate_tx_key_exchange(const wickr_transport_ctx_t *ctx,
                                                                                          Wickr__Proto__Handshake__PayloadCase phase,
                                                                                          const wickr_stream_key_t *tx_key,
                                                                                          uint8_t version)
{
    if (!ctx ||
        !tx_key ||
        version != CURRENT_HANDSHAKE_VERSION ||
        phase == WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED ||
        phase == WICKR__PROTO__HANDSHAKE__PAYLOAD__NOT_SET)
    {
        return NULL;
    }
    
    wickr_ec_key_t *packet_exchange_key = ctx->engine.wickr_crypto_engine_ec_rand_key(ctx->engine.default_curve);
    
    if (!packet_exchange_key) {
        return NULL;
    }
    
    wickr_buffer_t *tx_key_buffer = wickr_stream_key_serialize(tx_key);
    
    if (!tx_key_buffer) {
        wickr_ec_key_destroy(&packet_exchange_key);
        return NULL;
    }
    
    uint8_t key_ex_version = __wickr_handshake_version_to_key_exchange(CURRENT_HANDSHAKE_VERSION);
    
    if (!key_ex_version) {
        wickr_buffer_destroy(&tx_key_buffer);
        wickr_ec_key_destroy(&packet_exchange_key);
        return NULL;
    }
    
    wickr_buffer_t *psk = NULL;
    
    if (ctx->callbacks.on_psk_required) {
        psk = ctx->callbacks.on_psk_required(ctx, ctx->user);
    }
    
    wickr_key_exchange_t *key_exchange = wickr_key_exchange_create_with_data(&ctx->engine,
                                                                             ctx->local_identity->id_chain,
                                                                             ctx->remote_identity,
                                                                             packet_exchange_key,
                                                                             tx_key_buffer,
                                                                             ctx->engine.default_cipher,
                                                                             psk,
                                                                             key_ex_version);
    
    wickr_buffer_destroy_zero(&tx_key_buffer);
    
    if (!key_exchange) {
        wickr_ec_key_destroy(&packet_exchange_key);
        return NULL;
    }
    
    Wickr__Proto__Handshake__KeyExchange key_exchange_p = WICKR__PROTO__HANDSHAKE__KEY_EXCHANGE__INIT;
    key_exchange_p.has_sender_pub = true;
    key_exchange_p.sender_pub.data = packet_exchange_key->pub_data->bytes;
    key_exchange_p.sender_pub.len = packet_exchange_key->pub_data->length;
    key_exchange_p.has_exchange_data = true;
    
    wickr_buffer_t *key_exchange_data = wickr_cipher_result_serialize(key_exchange->exchange_ciphertext);
    
    if (!key_exchange_data) {
        wickr_ec_key_destroy(&packet_exchange_key);
        return NULL;
    }
    
    key_exchange_p.exchange_data.data = key_exchange_data->bytes;
    key_exchange_p.exchange_data.len = key_exchange_data->length;
    
    Wickr__Proto__Handshake__Response response = WICKR__PROTO__HANDSHAKE__RESPONSE__INIT;
    response.key_exchange = &key_exchange_p;
    
    Wickr__Proto__Handshake__Seed seed = WICKR__PROTO__HANDSHAKE__SEED__INIT;
    
    if (phase == WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE) {
        
        seed.node_info = wickr_node_to_proto(ctx->local_identity);
        
        if (!seed.node_info) {
            wickr_ec_key_destroy(&packet_exchange_key);
            wickr_buffer_destroy(&key_exchange_data);
            wickr_key_exchange_destroy(&key_exchange);
            return NULL;
        }
        
        response.response_key = &seed;
    }
    
    Wickr__Proto__Handshake return_handshake = WICKR__PROTO__HANDSHAKE__INIT;
    return_handshake.payload_case = phase;
    return_handshake.response = &response;
    return_handshake.version = version;
    
    
    wickr_transport_packet_t *packet = wickr_transport_packet_create_proto_handshake(ctx, &return_handshake);
    wickr_node_proto_free(seed.node_info);
    wickr_ec_key_destroy(&packet_exchange_key);
    wickr_key_exchange_destroy(&key_exchange);
    wickr_buffer_destroy(&key_exchange_data);

    if (!packet) {
        return NULL;
    }
    
    return packet;
}

static bool __wickr_transport_ctx_update_remote_keypair(wickr_transport_ctx_t *ctx, Wickr__Proto__Handshake__Seed *seed_data)
{
    if (!ctx || !seed_data) {
        return false;
    }

    wickr_ephemeral_keypair_t *remote_eph_keypair =  wickr_ephemeral_keypair_create_from_proto(seed_data->node_info->ephemeral_keypair, &ctx->engine);
    
    if (!wickr_node_rotate_keypair(ctx->remote_identity, remote_eph_keypair, false)) {
        wickr_ephemeral_keypair_destroy(&remote_eph_keypair);
        return false;
    }
    
    return true;
}

static void __wickr_transport_ctx_update_rx_stream(wickr_transport_ctx_t *ctx, wickr_stream_ctx_t *rx_stream)
{
    /* Make sure the new stream is picking up with the sequence number of the existing stream if necessary */
    if (ctx->rx_stream && rx_stream) {
        rx_stream->last_seq = ctx->rx_stream->last_seq;
    }
    
    wickr_stream_ctx_destroy(&ctx->rx_stream);
    ctx->rx_stream = rx_stream;
}

static bool __wickr_transport_ctx_set_handshake_key(wickr_transport_ctx_t *ctx, wickr_ec_key_t *exchange_key)
{
    if (!ctx || !exchange_key) {
        return false;
    }
    
    wickr_ephemeral_keypair_t *ephemeral_key = wickr_ephemeral_keypair_create(0, exchange_key, NULL);
    
    if (!ephemeral_key) {
        return false;
    }
    
    if (!wickr_node_rotate_keypair(ctx->local_identity, ephemeral_key, false)) {
        wickr_ephemeral_keypair_destroy(&ephemeral_key);
        return false;
    }
    
    return true;
}

static bool __wickr_transport_ctx_generate_keys(wickr_transport_ctx_t *ctx)
{
    if (!ctx) {
        return false;
    }
    
    wickr_ec_key_t *exchange_key = ctx->engine.wickr_crypto_engine_ec_rand_key(ctx->engine.default_curve);
    
    if (!__wickr_transport_ctx_set_handshake_key(ctx, exchange_key)) {
        wickr_ec_key_destroy(&exchange_key);
        return false;
    }
    
    wickr_stream_ctx_t *tx_ctx = __wickr_transport_ctx_rand_tx_stream(ctx, NULL);
    
    if (!tx_ctx) {
        return false;
    }
    
    bool swapped = false;
    
    if (ctx->callbacks.on_tx_stream_gen) {
        wickr_stream_ctx_t *new_ctx = ctx->callbacks.on_tx_stream_gen(ctx, tx_ctx, ctx->user);
        
        if (new_ctx != tx_ctx) {
            swapped = true;
            wickr_stream_ctx_destroy(&tx_ctx);
            tx_ctx = new_ctx;
        }
    }
    
    bool result = __wickr_transport_ctx_set_tx_stream(ctx, tx_ctx);
    
    if (!swapped) {
        wickr_stream_ctx_destroy(&tx_ctx);
    }
    
    return result;
}

static wickr_transport_packet_t *__wickr_transport_ctx_handshake_respond(wickr_transport_ctx_t *ctx, Wickr__Proto__Handshake__Seed *seed, uint8_t version)
{
    if (!ctx) {
        return NULL;
    }
    
    if (!__wickr_transport_ctx_update_remote_keypair(ctx, seed)) {
        return NULL;
    }
    
    Wickr__Proto__Handshake__PayloadCase phase = WICKR__PROTO__HANDSHAKE__PAYLOAD__NOT_SET;
    
    if (ctx->status == TRANSPORT_STATUS_NONE || ctx->status == TRANSPORT_STATUS_ACTIVE) {
        phase = WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE;
    }
    else {
        phase = WICKR__PROTO__HANDSHAKE__PAYLOAD_FINISH;
    }
    
    if (phase == WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE) {
        
        if (!__wickr_transport_ctx_generate_keys(ctx)) {
            return NULL;
        }
        
    }
    
    wickr_transport_packet_t *packet = __wickr_transport_ctx_handshake_generate_tx_key_exchange(ctx,
                                                                        phase,
                                                                        ctx->tx_stream->key,
                                                                        version);
    
    wickr_ephemeral_keypair_destroy(&ctx->remote_identity->ephemeral_keypair);
    
    return packet;
}

static wickr_transport_packet_t *__wickr_transport_ctx_handshake_seed_respond(wickr_transport_ctx_t *ctx, const wickr_transport_packet_t *handshake)
{
    if (!ctx || !handshake) {
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = wickr_transport_packet_to_proto_handshake(handshake, WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED);
    
    if (!handshake_data) {
        return NULL;
    }
    
    wickr_transport_packet_t *return_packet = __wickr_transport_ctx_handshake_respond(ctx, handshake_data->seed, handshake_data->version);
    wickr__proto__handshake__free_unpacked(handshake_data, NULL);
    
    return return_packet;
}

static wickr_stream_key_t *__wickr_transport_ctx_handshake_decode_rx_key(const wickr_transport_ctx_t *ctx,
                                                                  const Wickr__Proto__Handshake__KeyExchange *return_exchange,
                                                                  uint8_t version)
{
    if (!ctx || !return_exchange || version != CURRENT_HANDSHAKE_VERSION) {
        return NULL;
    }
    
    uint8_t key_ex_version = __wickr_handshake_version_to_key_exchange(version);
    
    if (!return_exchange->has_exchange_data || !return_exchange->has_sender_pub || !key_ex_version)
    {
        return NULL;
    }
    
    wickr_buffer_t *psk = NULL;
    
    if (ctx->callbacks.on_psk_required) {
        psk = ctx->callbacks.on_psk_required(ctx, ctx->user);
    }
    
    wickr_buffer_t key_exchange_buffer = { return_exchange->exchange_data.len, return_exchange->exchange_data.data };
    wickr_buffer_t exchange_key_buffer = { return_exchange->sender_pub.len, return_exchange->sender_pub.data };
    
    wickr_key_exchange_t exchange;
    exchange.key_id = 0;
    exchange.exchange_id = ctx->local_identity->id_chain->node->identifier;
    exchange.exchange_ciphertext = wickr_cipher_result_from_buffer(&key_exchange_buffer);
    
    if (!exchange.exchange_ciphertext || !exchange.exchange_ciphertext->cipher.is_authenticated) {
        return NULL;
    }
    
    wickr_ec_key_t *ec_key = ctx->engine.wickr_crypto_engine_ec_key_import(&exchange_key_buffer, false);
    
    if (!ec_key) {
        return NULL;
    }
    
    wickr_buffer_t *rx_key_buffer = wickr_key_exchange_derive_data(&ctx->engine,
                                                                   ctx->remote_identity->id_chain,
                                                                   ctx->local_identity,
                                                                   ec_key,
                                                                   &exchange,
                                                                   psk,
                                                                   key_ex_version);
    
    wickr_cipher_result_destroy(&exchange.exchange_ciphertext);
    wickr_ephemeral_keypair_destroy(&ctx->local_identity->ephemeral_keypair);
    wickr_ec_key_destroy(&ec_key);
    
    if (!rx_key_buffer) {
        return NULL;
    }
    
    wickr_stream_key_t *rx_key = wickr_stream_key_create_from_buffer(rx_key_buffer);
    wickr_buffer_destroy_zero(&rx_key_buffer);

    return rx_key;
}

static Wickr__Proto__Handshake *__wickr_transport_ctx_handshake_process_response(wickr_transport_ctx_t *ctx,
                                                                                 const wickr_transport_packet_t *return_handshake)
{
    if (!ctx || !return_handshake) {
        return NULL;
    }
    
    switch (ctx->status) {
        case TRANSPORT_STATUS_NONE:
        case TRANSPORT_STATUS_ERROR:
        case TRANSPORT_STATUS_ACTIVE:
            return NULL;
        default:
            break;
    }
    
    Wickr__Proto__Handshake__PayloadCase phase = ctx->status == TRANSPORT_STATUS_SEEDED ? WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE : WICKR__PROTO__HANDSHAKE__PAYLOAD_FINISH;
    
    Wickr__Proto__Handshake *handshake_data = wickr_transport_packet_to_proto_handshake(return_handshake,
                                                                                        phase);
    
    if (!handshake_data) {
        return NULL;
    }
    
    Wickr__Proto__Handshake__KeyExchange *key_exchange;
    
    switch (phase) {
        case WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE:
            key_exchange = handshake_data->response->key_exchange;
            break;
        case WICKR__PROTO__HANDSHAKE__PAYLOAD_FINISH:
            key_exchange = handshake_data->finish->key_exchange;
            break;
        default:
            wickr__proto__handshake__free_unpacked(handshake_data, NULL);
            return NULL;
    }
   
    wickr_stream_key_t *rx_key = __wickr_transport_ctx_handshake_decode_rx_key(ctx, key_exchange, handshake_data->version);
    
    if (!rx_key) {
        wickr__proto__handshake__free_unpacked(handshake_data, NULL);
        return NULL;
    }
    
    wickr_stream_ctx_t *rx_stream = wickr_stream_ctx_create(ctx->engine, rx_key, STREAM_DIRECTION_DECODE);
    
    if (!rx_stream) {
        wickr_stream_key_destroy(&rx_key);
        return NULL;
    }
    
    __wickr_transport_ctx_update_rx_stream(ctx, rx_stream);
    
    return handshake_data;
}

static wickr_transport_packet_t *__wickr_transport_ctx_handshake_process_return(wickr_transport_ctx_t *ctx, const wickr_transport_packet_t *return_handshake)
{
    if (!ctx || !return_handshake) {
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = __wickr_transport_ctx_handshake_process_response(ctx, return_handshake);
    
    if (!handshake_data) {
        return NULL;
    }
    
    wickr_transport_packet_t *return_packet = __wickr_transport_ctx_handshake_respond(ctx, handshake_data->response->response_key, handshake_data->version);
    
    wickr__proto__handshake__free_unpacked(handshake_data, NULL);
    
    return return_packet;
}

static bool __wickr_transport_ctx_handshake_finish(wickr_transport_ctx_t *ctx, const wickr_transport_packet_t *finish_handshake)
{
    if (!ctx || !finish_handshake) {
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = __wickr_transport_ctx_handshake_process_response(ctx, finish_handshake);
    
    if (!handshake_data) {
        return false;
    }
    
    wickr__proto__handshake__free_unpacked(handshake_data, NULL);

    return true;
}

static wickr_buffer_t *__wickr_transport_ctx_decode_pkt(const wickr_transport_ctx_t *ctx, const wickr_transport_packet_t *pkt)
{
    if (!ctx || !pkt) {
        return NULL;
    }
    
    wickr_cipher_result_t *cipher_result = wickr_cipher_result_from_buffer(pkt->body);
    
    if (!cipher_result) {
        return NULL;
    }
    
    if (pkt->mac_type != TRANSPORT_MAC_TYPE_AUTH_CIPHER) {
        wickr_cipher_result_destroy(&cipher_result);
        return NULL;
    }
    
    wickr_buffer_t *aad_buffer = wickr_transport_packet_make_meta_buffer(pkt);
    
    if (!aad_buffer) {
        wickr_cipher_result_destroy(&cipher_result);
        return NULL;
    }
    
    wickr_buffer_t *return_buffer = wickr_stream_ctx_decode(ctx->rx_stream, cipher_result, aad_buffer, pkt->seq_num);
    wickr_cipher_result_destroy(&cipher_result);
    wickr_buffer_destroy(&aad_buffer);
    
    return return_buffer;
}

static wickr_transport_packet_t *__wickr_transport_ctx_encode_pkt(const wickr_transport_ctx_t *ctx, const wickr_buffer_t *data)
{
    if (!ctx || !data) {
        return NULL;
    }
    
    uint64_t next_pkt_seq = ctx->tx_stream->last_seq + 1;
    
    wickr_buffer_t temp_body = { 0, NULL };
    wickr_transport_packet_t *pkt = wickr_transport_packet_create(next_pkt_seq, TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT, &temp_body);
    
    if (!pkt) {
        return NULL;
    }
    
    if (ctx->tx_stream->key->cipher_key->cipher.is_authenticated) {
        pkt->mac_type = TRANSPORT_MAC_TYPE_AUTH_CIPHER;
    }
    
    wickr_buffer_t *aad_buffer = wickr_transport_packet_make_meta_buffer(pkt);
    
    if (!aad_buffer) {
        wickr_transport_packet_destroy(&pkt);
        return NULL;
    }
    
    wickr_cipher_result_t *cipher_result = wickr_stream_ctx_encode(ctx->tx_stream, data, aad_buffer, next_pkt_seq);
    wickr_buffer_destroy(&aad_buffer);
    
    if (!cipher_result) {
        wickr_transport_packet_destroy(&pkt);
        return NULL;
    }
    
    wickr_buffer_t *serialized = wickr_cipher_result_serialize(cipher_result);
    wickr_cipher_result_destroy(&cipher_result);
    
    if (!serialized) {
        wickr_transport_packet_destroy(&pkt);
        return NULL;
    }
    
    pkt->body = serialized;
    
    return pkt;
}

void wickr_transport_ctx_start(wickr_transport_ctx_t *ctx)
{
    if (!ctx || ctx->status == TRANSPORT_STATUS_ERROR) {
        return;
    }
    
    bool result = __wickr_transport_ctx_generate_keys(ctx);
    
    if (!result) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    Wickr__Proto__Handshake__Seed seed = WICKR__PROTO__HANDSHAKE__SEED__INIT;
    seed.node_info = wickr_node_to_proto(ctx->local_identity);
    
    if (!seed.node_info) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    Wickr__Proto__Handshake handshake = WICKR__PROTO__HANDSHAKE__INIT;
    handshake.payload_case = WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED;
    handshake.seed = &seed;
    handshake.version = CURRENT_HANDSHAKE_VERSION;
    
    wickr_transport_packet_t *handshake_pkt = wickr_transport_packet_create_proto_handshake(ctx, &handshake);
    wickr_node_proto_free(seed.node_info);
    
    if (!handshake_pkt) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    wickr_buffer_t *serialized_packet = wickr_transport_packet_serialize(handshake_pkt);
    wickr_transport_packet_destroy(&handshake_pkt);
    
    if (!serialized_packet) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return;
    }
    
    __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_SEEDED);
    
    ctx->callbacks.tx(ctx, serialized_packet, TRANSPORT_PAYLOAD_TYPE_HANDSHAKE, ctx->user);
    
}

wickr_buffer_t *wickr_transport_ctx_process_tx_buffer(wickr_transport_ctx_t *ctx, const wickr_buffer_t *buffer)
{
    if (!ctx || !buffer || ctx->status == TRANSPORT_STATUS_ERROR) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return NULL;
    }
    
    if (ctx->status != TRANSPORT_STATUS_ACTIVE) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return NULL;
    }
    
    /* Don't allow sending a packet if the context is in READ_ONLY mode.
       Currently this is a silent failure */
    if (ctx->data_flow == TRANSPORT_DATA_FLOW_READ_ONLY) {
        return NULL;
    }
    
    wickr_transport_packet_t *tx_packet = __wickr_transport_ctx_encode_pkt(ctx, buffer);
    
    if (!tx_packet) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return NULL;
    }
    
    wickr_buffer_t *out_buffer = wickr_transport_packet_serialize(tx_packet);
    wickr_transport_packet_destroy(&tx_packet);
    
    if (!out_buffer) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return NULL;
    }
    
    ctx->callbacks.tx(ctx, out_buffer, TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT, ctx->user);
    
    return out_buffer;
}

static bool __wickr_transport_handshake_set_remote_identity(wickr_transport_ctx_t *ctx, wickr_transport_packet_t *pkt)
{
    if (!ctx || !pkt || ctx->remote_identity) {
        return false;
    }
    
    Wickr__Proto__Handshake__PayloadCase expected_case = WICKR__PROTO__HANDSHAKE__PAYLOAD__NOT_SET;
    
    switch (ctx->status) {
        case TRANSPORT_STATUS_TX_INIT:
        case TRANSPORT_STATUS_ERROR:
        case TRANSPORT_STATUS_ACTIVE:
            return false;
        case TRANSPORT_STATUS_SEEDED:
            expected_case = WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE;
            break;
        case TRANSPORT_STATUS_NONE:
            expected_case = WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED;
            break;
    }
    
    Wickr__Proto__Handshake *handshake_data = wickr_transport_packet_to_proto_handshake(pkt, expected_case);
    
    if (!handshake_data) {
        return false;
    }
    
    Wickr__Proto__Node *node = NULL;
    
    switch (expected_case) {
        case WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE:
        {
            if (!handshake_data->response || !handshake_data->response->response_key) {
                return false;
            }
            node = handshake_data->response->response_key->node_info;
        }
            break;
        case WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED:
        {
            if (!handshake_data->seed) {
                return false;
            }
            node = handshake_data->seed->node_info;
        }
            break;
        default:
            return false;
    }
    
    wickr_node_t *remote_node = wickr_node_create_from_proto(node, &ctx->engine);
    wickr__proto__handshake__free_unpacked(handshake_data, NULL);
    
    if (!remote_node) {
        return false;
    }
    
    if (!wickr_identity_chain_validate(remote_node->id_chain, &ctx->engine)) {
        wickr_node_destroy(&remote_node);
        return false;
    }
    
    if (!ctx->callbacks.on_identity_verify(ctx, remote_node->id_chain, ctx->user)) {
        wickr_node_destroy(&remote_node);
        return false;
    }
    
    ctx->remote_identity = remote_node;
    
    return true;
}

wickr_buffer_t *wickr_transport_ctx_process_rx_buffer(wickr_transport_ctx_t *ctx, const wickr_buffer_t *buffer)
{
    if (!ctx || !buffer || ctx->status == TRANSPORT_STATUS_ERROR) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return NULL;
    }
    
    wickr_transport_packet_t *packet = wickr_transport_packet_create_from_buffer(buffer);
    
    if (!packet) {
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return NULL;
    }
    
    if (!ctx->remote_identity) {
        if (!__wickr_transport_handshake_set_remote_identity(ctx, packet)) {
            wickr_transport_packet_destroy(&packet);
            __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
            return NULL;
        }
    }
    
    bool valid_mac = wickr_transport_packet_verify(packet, buffer, &ctx->engine, ctx->remote_identity->id_chain->node);
    
    /* The mac is not required in the condition that we are passed the handshake, the body type of the packet is ciphertext,
       and the cipher of the rx stream is authenticated. In this scenario we rely on the cipher level authentication instead of an explicit mac
     */
    if (!valid_mac) {
        if (ctx->status == TRANSPORT_STATUS_ACTIVE && packet->body_type == TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT &&
            ctx->rx_stream->key->cipher_key->cipher.is_authenticated) {
            valid_mac = true;
        }
    }
    
    if (!valid_mac) {
        wickr_transport_packet_destroy(&packet);
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return NULL;
    }
    
    /* Make sure the sequence number is always moving forward */
    if (ctx->rx_stream && packet->seq_num <= ctx->rx_stream->last_seq) {
        wickr_transport_packet_destroy(&packet);
        __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        return NULL;
    }
    
    wickr_transport_packet_t *volley_packet = NULL;
    wickr_buffer_t *return_buffer = NULL;
    
    switch (ctx->status) {
        case TRANSPORT_STATUS_NONE:
            volley_packet = __wickr_transport_ctx_handshake_seed_respond(ctx, packet);
            
            if (!volley_packet) {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
            }
            else {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_TX_INIT);
            }
            
            break;
        case TRANSPORT_STATUS_TX_INIT:
            if (!__wickr_transport_ctx_handshake_finish(ctx, packet)) {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
            }
            else {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ACTIVE);
            }
            break;
        case TRANSPORT_STATUS_SEEDED:
            volley_packet = __wickr_transport_ctx_handshake_process_return(ctx, packet);
            
            if (!volley_packet) {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
            }
            else {
                __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ACTIVE);
            }
            break;
        case TRANSPORT_STATUS_ACTIVE:
            
            if (packet->body_type == TRANSPORT_PAYLOAD_TYPE_HANDSHAKE) {
                volley_packet = __wickr_transport_ctx_handshake_seed_respond(ctx, packet);
                
                if (!volley_packet) {
                    __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
                }
                else {
                    __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_TX_INIT);
                }
            }
            else {
                
                /* Don't allow processing a non-header packet if the context is in WRITE_ONLY mode.
                 Currently this is a silent failure */
                if (ctx->data_flow == TRANSPORT_DATA_FLOW_WRITE_ONLY) {
                    break;
                }
                
                return_buffer = __wickr_transport_ctx_decode_pkt(ctx, packet);
                
                if (!return_buffer) {
                    __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
                }
            }
            
            break;
        default:
            break;
    }
    
    /* Make sure to adjust the rx_stream seq num to compensate for any control messages received */
    if (ctx->rx_stream && ctx->rx_stream->last_seq != packet->seq_num) {
        ctx->rx_stream->last_seq = packet->seq_num;
    }
    
    wickr_transport_packet_destroy(&packet);
    
    if (volley_packet) {
        wickr_buffer_t *packet_buffer = wickr_transport_packet_serialize(volley_packet);
        wickr_transport_packet_destroy(&volley_packet);
        
        if (!packet_buffer) {
            __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
            return NULL;
        }
        ctx->callbacks.tx(ctx, packet_buffer, TRANSPORT_PAYLOAD_TYPE_HANDSHAKE, ctx->user);
    }
    
    if (!return_buffer) {
        return NULL;
    }
    
    ctx->callbacks.rx(ctx, return_buffer, ctx->user);
    
    return return_buffer;
}

wickr_transport_status wickr_transport_ctx_get_status(const wickr_transport_ctx_t *ctx)
{
    if (!ctx) {
        return TRANSPORT_STATUS_NONE;
    }
    
    return ctx->status;
}

const wickr_buffer_t *wickr_transport_ctx_get_rxstream_user_data(const wickr_transport_ctx_t *ctx)
{
    if (!ctx || !ctx->rx_stream || !ctx->rx_stream->key) {
        return NULL;
    }
    
    return ctx->rx_stream->key->user_data;
}

const wickr_node_t *wickr_transport_ctx_get_local_node_ptr(const wickr_transport_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    
    return ctx->local_identity;
}

const wickr_node_t *wickr_transport_ctx_get_remote_node_ptr(const wickr_transport_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    
    return ctx->remote_identity;
}

const void *wickr_transport_ctx_get_user_ctx(const wickr_transport_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    
    return ctx->user;
}

void wickr_transport_ctx_set_user_ctx(wickr_transport_ctx_t *ctx, void *user)
{
    if (!ctx) {
        return;
    }
    
    ctx->user = user;
}

wickr_transport_data_flow wickr_transport_ctx_get_data_flow_mode(const wickr_transport_ctx_t *ctx)
{
    return ctx->data_flow;
}

void wickr_transport_ctx_set_data_flow_mode(wickr_transport_ctx_t *ctx, wickr_transport_data_flow flow_mode)
{
    if (!ctx) {
        return;
    }
    
    ctx->data_flow = flow_mode;
}

const wickr_transport_callbacks_t *wickr_transport_ctx_get_callbacks(const wickr_transport_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    
    return &ctx->callbacks;
}

void wickr_transport_ctx_set_callbacks(wickr_transport_ctx_t *ctx, const wickr_transport_callbacks_t *callbacks)
{
    if (!ctx || !callbacks) {
        return;
    }
    
    ctx->callbacks = *callbacks;
}

bool wickr_transport_ctx_force_tx_key_evo(wickr_transport_ctx_t *ctx)
{
    if (!ctx || ctx->status != TRANSPORT_STATUS_ACTIVE) {
        return false;
    }
    
    uint64_t curr_evo = ctx->tx_stream->last_seq / ctx->tx_stream->key->packets_per_evolution;
    ctx->tx_stream->last_seq = ((curr_evo + 1) * ctx->tx_stream->key->packets_per_evolution) - 1;
    
    return true;
}
