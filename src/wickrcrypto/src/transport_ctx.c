
#include "transport_ctx.h"
#include "memory.h"
#include "stream.pb-c.h"
#include "stream_ctx.h"
#include "transport_handshake.h"
#include "transport_packet.h"
#include "transport_error.h"
#include "private/transport_priv.h"
#include "private/node_priv.h"
#include "private/identity_priv.h"
#include "private/ephemeral_keypair_priv.h"

static void __wickr_transport_ctx_update_status(wickr_transport_ctx_t *ctx, wickr_transport_status status)
{
    if (!ctx || ctx->status == status) {
        return;
    }
    
    ctx->status = status;
    ctx->callbacks.on_state(ctx, status);
}

static void __wickr_transport_ctx_set_error(wickr_transport_ctx_t *ctx, wickr_transport_error err)
{
    if (ctx) {
        ctx->err = err;
    }
    __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
}

wickr_transport_ctx_t *wickr_transport_ctx_create(const wickr_crypto_engine_t engine,
                                                  wickr_identity_chain_t *local_identity,
                                                  wickr_identity_chain_t *remote_identity,
                                                  uint32_t evo_count,
                                                  wickr_transport_callbacks_t callbacks,
                                                  void *user)
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
    ctx->err = TRANSPORT_ERROR_NONE;
    
    return ctx;
}

wickr_transport_ctx_t *wickr_transport_ctx_copy(const wickr_transport_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    
    wickr_identity_chain_t *local_copy = wickr_identity_chain_copy(ctx->local_identity);
    
    if (!local_copy) {
        return NULL;
    }
    
    wickr_identity_chain_t *remote_copy = wickr_identity_chain_copy(ctx->remote_identity);
    
    if (!remote_copy) {
        wickr_identity_chain_destroy(&local_copy);
        return NULL;
    }
    
    wickr_stream_ctx_t *tx_copy = wickr_stream_ctx_copy(ctx->tx_stream);
    
    if (!tx_copy && ctx->tx_stream) {
        wickr_identity_chain_destroy(&local_copy);
        wickr_identity_chain_destroy(&remote_copy);
        return NULL;
    }
    
    wickr_stream_ctx_t *rx_copy = wickr_stream_ctx_copy(ctx->rx_stream);
    
    if (!rx_copy && ctx->rx_stream) {
        wickr_identity_chain_destroy(&local_copy);
        wickr_identity_chain_destroy(&remote_copy);
        wickr_stream_ctx_destroy(&tx_copy);
        return NULL;
    }
    
    wickr_transport_ctx_t *copy = wickr_alloc_zero(sizeof(wickr_transport_ctx_t));
    
    if (!copy) {
        wickr_identity_chain_destroy(&local_copy);
        wickr_identity_chain_destroy(&remote_copy);
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
    
    return copy;
}

void wickr_transport_ctx_destroy(wickr_transport_ctx_t **ctx)
{
    if (!ctx || !*ctx) {
        return;
    }
    
    wickr_identity_chain_destroy(&(*ctx)->local_identity);
    wickr_identity_chain_destroy(&(*ctx)->remote_identity);
    wickr_stream_ctx_destroy(&(*ctx)->tx_stream);
    wickr_stream_ctx_destroy(&(*ctx)->rx_stream);
    wickr_transport_handshake_destroy(&(*ctx)->pending_handshake);
    
    wickr_free(*ctx);
    *ctx = NULL;
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
    
    if (pkt->meta.mac_type != TRANSPORT_MAC_TYPE_AUTH_CIPHER) { /* Only allow authenticated ciphers */
        wickr_cipher_result_destroy(&cipher_result);
        return NULL;
    }
    
    wickr_buffer_t *aad_buffer = wickr_transport_packet_meta_serialize(&pkt->meta);
    
    if (!aad_buffer) {
        wickr_cipher_result_destroy(&cipher_result);
        return NULL;
    }
    
    wickr_buffer_t *return_buffer = wickr_stream_ctx_decode(ctx->rx_stream, cipher_result, aad_buffer, pkt->meta.body_meta.data.sequence_number);
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
    
    wickr_transport_packet_meta_t meta;
    wickr_transport_packet_meta_initialize_data(&meta, next_pkt_seq, TRANSPORT_MAC_TYPE_AUTH_CIPHER);
    
    wickr_buffer_t *aad_buffer = wickr_transport_packet_meta_serialize(&meta);
    
    if (!aad_buffer) {
        return NULL;
    }
    
    wickr_cipher_result_t *cipher_result = wickr_stream_ctx_encode(ctx->tx_stream, data, aad_buffer, next_pkt_seq);
    wickr_buffer_destroy(&aad_buffer);
    
    if (!cipher_result) {
        return NULL;
    }
    
    wickr_buffer_t *serialized = wickr_cipher_result_serialize(cipher_result);
    wickr_cipher_result_destroy(&cipher_result);
    
    if (!serialized) {
        return NULL;
    }
    
    wickr_transport_packet_t *pkt = wickr_transport_packet_create(meta, serialized);
    
    if (!pkt) {
        wickr_buffer_destroy(&serialized);
    }
        
    return pkt;
}

static bool __wickr_transport_ctx_finalize_handshake(wickr_transport_ctx_t *ctx)
{
    wickr_transport_handshake_res_t *res = wickr_transport_handshake_finalize(ctx->pending_handshake);
    
    if (!res) {
        return false;
    }
    
    wickr_transport_handshake_destroy(&ctx->pending_handshake);
    
    wickr_stream_key_t *tx_key = wickr_stream_key_copy(wickr_transport_handshake_res_get_local_key(res));
    wickr_stream_ctx_t *tx_stream = wickr_stream_ctx_create(ctx->engine, tx_key, STREAM_DIRECTION_ENCODE);
    
    if (!tx_stream) {
        wickr_stream_key_destroy(&tx_key);
        return false;
    }
    
    wickr_stream_key_t *rx_key = wickr_stream_key_copy(wickr_transport_handshake_res_get_remote_key(res));
    wickr_stream_ctx_t *rx_stream = wickr_stream_ctx_create(ctx->engine, rx_key, STREAM_DIRECTION_DECODE);
    
    wickr_transport_handshake_res_destroy(&res);
    
    if (!rx_stream) {
        wickr_stream_ctx_destroy(&tx_stream);
        wickr_stream_key_destroy(&rx_key);
        return false;
    }
    
    wickr_stream_ctx_destroy(&ctx->rx_stream);
    wickr_stream_ctx_destroy(&ctx->tx_stream);
    
    ctx->rx_stream = rx_stream;
    ctx->tx_stream = tx_stream;
    
    __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ACTIVE);
    
    return true;
}

static void __wickr_transport_validate_identity_complete(const wickr_transport_ctx_t *ctx, bool is_valid)
{
    /* Remove const for internal work */
    wickr_transport_ctx_t *_ctx = (wickr_transport_ctx_t *)ctx;
    
    wickr_transport_packet_t *volley_packet = wickr_transport_handshake_verify_identity(_ctx->pending_handshake, is_valid);
    
    if (wickr_transport_handshake_get_status(_ctx->pending_handshake) == TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION) {
        __wickr_transport_ctx_finalize_handshake(_ctx);
    }
    
    if (wickr_transport_handshake_get_status(_ctx->pending_handshake) == TRANSPORT_HANDSHAKE_STATUS_FAILED) {
        __wickr_transport_ctx_set_error(_ctx, TRANSPORT_ERROR_HANDSHAKE_FAILED);
        return;
    }
    
    if (volley_packet) {
        wickr_buffer_t *volley_buffer = wickr_transport_packet_serialize(volley_packet);
        wickr_transport_packet_destroy(&volley_packet);
        
        if (!volley_buffer) {
            __wickr_transport_ctx_set_error(_ctx, TRANSPORT_ERROR_HANDSHAKE_VOLLEY_FAILED);
            return;
        }
        
        _ctx->callbacks.tx(ctx, volley_buffer);
    }
    
}

static void __wickr_transport_handshake_identity_callback(const wickr_transport_handshake_t *handshake,
                                                          wickr_identity_chain_t *identity,
                                                          void *user)
{
    wickr_transport_ctx_t *ctx = (wickr_transport_ctx_t *)user;
    ctx->callbacks.on_identity_verify(ctx, identity, __wickr_transport_validate_identity_complete);
}

static wickr_transport_handshake_t *__wickr_transport_ctx_create_handshake(const wickr_transport_ctx_t *ctx)
{
    wickr_identity_chain_t *local_copy = wickr_identity_chain_copy(ctx->local_identity);
    wickr_identity_chain_t *remote_copy = wickr_identity_chain_copy(ctx->remote_identity);
    
    wickr_transport_handshake_t *handshake = wickr_transport_handshake_create(ctx->engine,
                                                                              local_copy,
                                                                              remote_copy,
                                                                              __wickr_transport_handshake_identity_callback,
                                                                              ctx->evo_count,
                                                                              (void *)ctx);
    
    if (!handshake) {
        wickr_identity_chain_destroy(&local_copy);
        wickr_identity_chain_destroy(&remote_copy);
    }
    
    return handshake;
}

void wickr_transport_ctx_start(wickr_transport_ctx_t *ctx)
{
    if (!ctx || ctx->status != TRANSPORT_STATUS_NONE) {
        __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_BAD_START_STATUS);
        return;
    }
    
    ctx->pending_handshake = __wickr_transport_ctx_create_handshake(ctx);
    
    if (!ctx->pending_handshake) {
        __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_CREATE_HANDSHAKE_FAILED);
        return;
    }
    
    wickr_transport_packet_t *handshake_start_packet = wickr_transport_handshake_start(ctx->pending_handshake);
    
    if (!handshake_start_packet ||
        wickr_transport_handshake_get_status(ctx->pending_handshake) == TRANSPORT_HANDSHAKE_STATUS_FAILED) {
        wickr_transport_handshake_destroy(&ctx->pending_handshake);
        __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_START_HANDSHAKE_FAILED);
        return;
    }
    
    wickr_buffer_t *serialized_packet = wickr_transport_packet_serialize(handshake_start_packet);
    wickr_transport_packet_destroy(&handshake_start_packet);
    
    if (!serialized_packet) {
        wickr_transport_handshake_destroy(&ctx->pending_handshake);
        __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_PACKET_SERIALIZATION_FAILED);
        return;
    }
    
    __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_INITIAL_HANDSHAKE);
    ctx->callbacks.tx(ctx, serialized_packet);
}

void wickr_transport_ctx_process_tx_buffer(wickr_transport_ctx_t *ctx, const wickr_buffer_t *buffer)
{
    if (!ctx || !buffer || ctx->status != TRANSPORT_STATUS_ACTIVE) {
        __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_BAD_TX_STATE);
        return;
    }
    
    wickr_transport_packet_t *tx_packet = __wickr_transport_ctx_encode_pkt(ctx, buffer);
    
    if (!tx_packet) {
        __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_PACKET_ENCODE_FAILED);
        return;
    }
    
    wickr_buffer_t *out_buffer = wickr_transport_packet_serialize(tx_packet);
    wickr_transport_packet_destroy(&tx_packet);
    
    if (!out_buffer) {
       __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_PACKET_SERIALIZATION_FAILED);
        return;
    }
    
    /* Execute the callback to provide the buffer to the user */
    ctx->callbacks.tx(ctx, out_buffer);
}

static void __wickr_transport_ctx_process_handshake_packet(wickr_transport_ctx_t *ctx,
                                                            const wickr_transport_packet_t *packet)
{
    /* Create the handshake if necessary */
    if (!ctx->pending_handshake) {
        wickr_transport_handshake_t *handshake = __wickr_transport_ctx_create_handshake(ctx);
        
        if (!handshake) {
            __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_CREATE_HANDSHAKE_FAILED);
            return;
        }
        
        ctx->pending_handshake = handshake;
    }
    
    /* Process the packet with the handshake */
    wickr_transport_packet_t *volley_packet = wickr_transport_handshake_process(ctx->pending_handshake, packet);
    
    if (wickr_transport_handshake_get_status(ctx->pending_handshake) == TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION) {
        __wickr_transport_ctx_finalize_handshake(ctx);
    }
    
    if (wickr_transport_handshake_get_status(ctx->pending_handshake) == TRANSPORT_HANDSHAKE_STATUS_FAILED) {
        __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_PROCESS_HANDSHAKE_FAILED);
        return;
    }
    
    if (volley_packet) {
        wickr_buffer_t *volley_buffer = wickr_transport_packet_serialize(volley_packet);
        wickr_transport_packet_destroy(&volley_packet);
        
        if (!volley_buffer) {
            __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_PACKET_SERIALIZATION_FAILED);
            return;
        }
        
        ctx->callbacks.tx(ctx, volley_buffer);
    }
    
}

static bool __wickr_transport_ctx_can_process_handshake(const wickr_transport_ctx_t *ctx)
{
    return ctx->pending_handshake || ctx->status == IDENTITY_CHAIN_STATUS_UNKNOWN;
}

void wickr_transport_ctx_process_rx_buffer(wickr_transport_ctx_t *ctx, const wickr_buffer_t *buffer)
{
    if (!ctx || !buffer || ctx->status == TRANSPORT_STATUS_ERROR) {
        if (!buffer) {
            __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_INVALID_RXDATA);
        } else {
            __wickr_transport_ctx_update_status(ctx, TRANSPORT_STATUS_ERROR);
        }
        return;
    }
    
    wickr_transport_packet_t *packet = wickr_transport_packet_create_from_buffer(buffer);
    
    if (!packet) {
        __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_INVALID_RXDATA);
        return;
    }
    
    wickr_buffer_t *return_buffer = NULL;
    
    if (__wickr_transport_ctx_can_process_handshake(ctx) && packet->meta.body_type == TRANSPORT_PAYLOAD_TYPE_HANDSHAKE) {
        __wickr_transport_ctx_process_handshake_packet(ctx, packet);
    } else if (ctx->rx_stream) {
        return_buffer = __wickr_transport_ctx_decode_pkt(ctx, packet);
        
        if (!return_buffer) {
            __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_PACKET_DECODE_FAILED);
        }
    } else {
        __wickr_transport_ctx_set_error(ctx, TRANSPORT_ERROR_BAD_RX_STATE);
    }
    
    wickr_transport_packet_destroy(&packet);
    
    /* Execute the callback if there is data for the user */
    
    if (return_buffer) {
        ctx->callbacks.rx(ctx, return_buffer);
    }
}

wickr_transport_status wickr_transport_ctx_get_status(const wickr_transport_ctx_t *ctx)
{
    return ctx ? ctx->status : TRANSPORT_STATUS_NONE;
}

const wickr_identity_chain_t *wickr_transport_ctx_get_local_identity_ptr(const wickr_transport_ctx_t *ctx)
{
    return ctx ? ctx->local_identity : NULL;
}

const wickr_identity_chain_t *wickr_transport_ctx_get_remote_identity_ptr(const wickr_transport_ctx_t *ctx)
{
    return ctx ? ctx->remote_identity : NULL;
}

const void *wickr_transport_ctx_get_user_ctx(const wickr_transport_ctx_t *ctx)
{
    return ctx ? ctx->user : NULL;
}

void wickr_transport_ctx_set_user_ctx(wickr_transport_ctx_t *ctx, void *user)
{
    if (!ctx) {
        return;
    }
    
    ctx->user = user;
}

wickr_transport_error wickr_transport_ctx_get_last_error(const wickr_transport_ctx_t *ctx)
{
    return ctx ? ctx->err : TRANSPORT_ERROR_NONE;
}
