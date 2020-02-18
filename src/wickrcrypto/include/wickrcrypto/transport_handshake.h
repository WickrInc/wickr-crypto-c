/*
* Copyright © 2012-2018 Wickr Inc.  All rights reserved.
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

#ifndef transport_handshake_h
#define transport_handshake_h

#include "identity.h"
#include "stream_key.h"
#include "transport_packet.h"

typedef enum {
    TRANSPORT_HANDSHAKE_STATUS_UNKNOWN,
    TRANSPORT_HANDSHAKE_STATUS_IN_PROGRESS,
    TRANSPORT_HANDSHAKE_STATUS_PENDING_VERIFICATION,
    TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION,
    TRANSPORT_HANDSHAKE_STATUS_COMPLETE,
    TRANSPORT_HANDSHAKE_STATUS_FAILED
} wickr_transport_handshake_status;

struct wickr_transport_handshake_res_t;
typedef struct wickr_transport_handshake_res_t wickr_transport_handshake_res_t;

wickr_transport_handshake_res_t *wickr_transport_handshake_res_create(wickr_stream_key_t *local_key,
                                                                      wickr_stream_key_t *remote_key);
wickr_transport_handshake_res_t *wickr_transport_handshake_res_copy(const wickr_transport_handshake_res_t *res);
void wickr_transport_handshake_res_destroy(wickr_transport_handshake_res_t **res);

const wickr_stream_key_t *wickr_transport_handshake_res_get_local_key(const wickr_transport_handshake_res_t *res);
const wickr_stream_key_t *wickr_transport_handshake_res_get_remote_key(const wickr_transport_handshake_res_t *res);

struct wickr_transport_handshake_t;
typedef struct wickr_transport_handshake_t wickr_transport_handshake_t;

typedef void (*wickr_transport_handshake_identity_callback)(const wickr_transport_handshake_t *handshake,
                                                            wickr_identity_chain_t *identity,
                                                            void *user);

wickr_transport_handshake_t *wickr_transport_handshake_create(wickr_crypto_engine_t engine,
                                                              wickr_identity_chain_t *local_identity,
                                                              wickr_identity_chain_t *remote_identity,
                                                              wickr_transport_handshake_identity_callback identity_callback,
                                                              uint32_t evo_count,
                                                              void *user);

wickr_transport_handshake_t *wickr_transport_handshake_copy(const wickr_transport_handshake_t *handshake);
void wickr_transport_handshake_destroy(wickr_transport_handshake_t **handshake);

wickr_transport_packet_t *wickr_transport_handshake_start(wickr_transport_handshake_t *handshake);

wickr_transport_packet_t *wickr_transport_handshake_process(wickr_transport_handshake_t *handshake,
                                                            const wickr_transport_packet_t *packet);

wickr_transport_packet_t *wickr_transport_handshake_verify_identity(const wickr_transport_handshake_t *handshake, bool is_valid);

wickr_transport_handshake_res_t *wickr_transport_handshake_finalize(wickr_transport_handshake_t *handshake);

const wickr_transport_handshake_status wickr_transport_handshake_get_status(const wickr_transport_handshake_t *handshake);
const wickr_identity_chain_t *wickr_transport_handshake_get_local_identity(const wickr_transport_handshake_t *handshake);
const wickr_identity_chain_t *wickr_transport_handshake_get_remote_identity(const wickr_transport_handshake_t *handshake);
const void *wickr_transport_handshake_get_user_data(const wickr_transport_handshake_t *handshake);
void wickr_transport_set_user_data(wickr_transport_handshake_t *handshake, void *user);


#endif /* transport_handshake_h */
