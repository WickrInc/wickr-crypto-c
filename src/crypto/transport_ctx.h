/*
 * Copyright © 2012-2017 Wickr Inc.  All rights reserved.
 *
 * This code is being released for EDUCATIONAL, ACADEMIC, AND CODE REVIEW PURPOSES
 * ONLY.  COMMERCIAL USE OF THE CODE IS EXPRESSLY PROHIBITED.  For additional details,
 * please see LICENSE
 *
 * THE CODE IS MADE AVAILABLE "AS-IS" AND WITHOUT ANY EXPRESS OR
 * IMPLIED GUARANTEES AS TO FITNESS, MERCHANTABILITY, NON-
 * INFRINGEMENT OR OTHERWISE. IT IS NOT BEING PROVIDED IN TRADE BUT ON
 * A VOLUNTARY BASIS ON BEHALF OF THE AUTHOR’S PART FOR THE BENEFIT
 * OF THE LICENSEE AND IS NOT MADE AVAILABLE FOR CONSUMER USE OR ANY
 * OTHER USE OUTSIDE THE TERMS OF THIS LICENSE. ANYONE ACCESSING THE
 * CODE SHOULD HAVE THE REQUISITE EXPERTISE TO SECURE THEIR SYSTEM
 * AND DEVICES AND TO ACCESS AND USE THE CODE FOR REVIEW PURPOSES
 * ONLY. LICENSEE BEARS THE RISK OF ACCESSING AND USING THE CODE. IN
 * PARTICULAR, AUTHOR BEARS NO LIABILITY FOR ANY INTERFERENCE WITH OR
 * ADVERSE EFFECT THAT MAY OCCUR AS A RESULT OF THE LICENSEE
 * ACCESSING AND/OR USING THE CODE ON LICENSEE’S SYSTEM.
 */

#ifndef transport_h
#define transport_h

#include "crypto_engine.h"
#include "node.h"

struct wickr_transport_ctx;
typedef struct wickr_transport_ctx wickr_transport_ctx_t;

typedef enum {
    TRANSPORT_STATUS_NONE,
    TRANSPORT_STATUS_SEEDED,
    TRANSPORT_STATUS_TX_INIT,
    TRANSPORT_STATUS_ACTIVE,
    TRANSPORT_STATUS_ERROR
} wickr_transport_status;

/* Function callback to handle sending / receiving / errors via an actual transport, eg socket */
typedef void (*wickr_transport_tx_func)(const wickr_transport_ctx_t *ctx, const wickr_buffer_t *data, void *user);
typedef void (*wickr_transport_rx_func)(const wickr_transport_ctx_t *ctx, const wickr_buffer_t *data, void *user);
typedef void (*wickr_transport_state_change_func)(const wickr_transport_ctx_t *ctx, wickr_transport_status status, void *user);
typedef bool (*wickr_transport_validate_identity_func)(const wickr_transport_ctx_t *ctx, wickr_identity_chain_t *identity, void *user);

struct wickr_transport_callbacks {
    wickr_transport_tx_func tx;
    wickr_transport_rx_func rx;
    wickr_transport_state_change_func on_state;
    wickr_transport_validate_identity_func on_identity_verify;
};

typedef struct wickr_transport_callbacks wickr_transport_callbacks_t;

wickr_transport_ctx_t *wickr_transport_ctx_create(const wickr_crypto_engine_t engine,
                                                  wickr_node_t *local_identity,
                                                  wickr_node_t *remote_identity,
                                                  uint32_t evo_count,
                                                  wickr_transport_callbacks_t callbacks,
                                                  void *user);

wickr_transport_ctx_t *wickr_transport_ctx_copy(const wickr_transport_ctx_t *stream);
void wickr_transport_ctx_destroy(wickr_transport_ctx_t **ctx);
void wickr_transport_ctx_start(wickr_transport_ctx_t *ctx);
void wickr_transport_ctx_process_tx_buffer(wickr_transport_ctx_t *ctx, const wickr_buffer_t *buffer);
void wickr_transport_ctx_process_rx_buffer(wickr_transport_ctx_t *ctx, const wickr_buffer_t *buffer);

#endif /* transport_h */
