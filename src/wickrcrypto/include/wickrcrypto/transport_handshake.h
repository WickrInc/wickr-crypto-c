/*
* Copyright © 2012-2020 Wickr Inc.  All rights reserved.
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 @addtogroup wickr_transport_handshake
 */

struct wickr_transport_handshake_res_t;
typedef struct wickr_transport_handshake_res_t wickr_transport_handshake_res_t;

/**
 @ingroup wickr_transport_handshake
 
 @enum wickr_transport_handshake_status
 
 Current status of a transport handshake
 
 @var wickr_transport_handshake_status::TRANSPORT_HANDSHAKE_STATUS_UNKNOWN
 Handshake has been created, but has not been started or received any packets
 @var wickr_transport_handshake_status::TRANSPORT_HANDSHAKE_STATUS_IN_PROGRESS
 Handshake has been started, but has not yet received any packets
 @var wickr_transport_handshake_status::TRANSPORT_HANDSHAKE_STATUS_PENDING_VERIFICATION
 Handshake processing has been paused pending a call to `wickr_transport_handshake_verify_identity`
 @var wickr_transport_handshake_status::TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION
 Handshake is complete and pending a call to `wickr_transport_handshake_finalize` to generate keys
 @var wickr_transport_handshake_status::TRANSPORT_HANDSHAKE_STATUS_COMPLETE
 Handshake has been finalized, and no further processing is allowed
 @var wickr_transport_handshake_status::TRANSPORT_HANDSHAKE_STATUS_FAILED
 Handshake has encountered an error and can no longer process any packets or be finalized
 */
typedef enum {
    TRANSPORT_HANDSHAKE_STATUS_UNKNOWN,
    TRANSPORT_HANDSHAKE_STATUS_IN_PROGRESS,
    TRANSPORT_HANDSHAKE_STATUS_PENDING_VERIFICATION,
    TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION,
    TRANSPORT_HANDSHAKE_STATUS_COMPLETE,
    TRANSPORT_HANDSHAKE_STATUS_FAILED
} wickr_transport_handshake_status;

/**
 @ingroup wickr_transport_handshake

 Create a new transport handshake result from parameters
 
 @param local_key local stream key to use for the result
 @param remote_key remote stream key to use for the result
 @return a newly allocated `wickr_transport_handshake_res_t` using `local_key` and `remote_key`. Takes ownership of the passed inputs
*/
wickr_transport_handshake_res_t *wickr_transport_handshake_res_create(wickr_stream_key_t *local_key,
                                                                      wickr_stream_key_t *remote_key);

/**
 @ingroup wickr_transport_handshake
 
 Make a deep copy of a transport handshake result
 
 @param res the handshake result to make a copy of
 @return a newly allocated transport handshake result set holding a deep copy of the properties of 'res'
*/
wickr_transport_handshake_res_t *wickr_transport_handshake_res_copy(const wickr_transport_handshake_res_t *res);

/**
 @ingroup wickr_transport_handshake
 
 Destroy a transport handshake result
 @param res a pointer to the transport handshake result set to destroy. All properties of `*res` will also be destroyed
 */
void wickr_transport_handshake_res_destroy(wickr_transport_handshake_res_t **res);

/**
 @ingroup wickr_transport_handshake
 
 Get a pointer to the handshake result's local key
 
 @param res the transport handshake to get the local key of
 @return a reference to the handshake result's local key
 */
const wickr_stream_key_t *wickr_transport_handshake_res_get_local_key(const wickr_transport_handshake_res_t *res);

/**
@ingroup wickr_transport_handshake

Get a pointer to the handshake result's remote key

@param res the transport handshake to get the remote key of
@return a reference to the handshake result's remote key
*/
const wickr_stream_key_t *wickr_transport_handshake_res_get_remote_key(const wickr_transport_handshake_res_t *res);

/**
@ingroup wickr_transport_handshake
@struct wickr_transport_handshake

@brief Transport handshake to manage the state of a handshake within the context of a wickr transport context

The transport handshake manages a 2-way handshake that is used to establish a set of stream keys for use within a transport context.
In an exchange between Alice and Bob, the first packet sent by Alice contains an ephemeral public key along with identity information and is signed by Alice's identity chain.
After receiving and validating the packet from Alice, Bob uses the ephemeral public key to encrypt a randomly chosen root key for the handshake and sends the resulting ciphertext back to Alice
along with his own identity chain data (if requested). Once both sides are aware of the chosen root key, they may both finalize the handshake to derive their respective rx / tx keys for data transmission.
This struct is only used within the `wickr_transport_ctx` and is not used for the Wickr Messaging Protocol itself.
*/

struct wickr_transport_handshake_t;
typedef struct wickr_transport_handshake_t wickr_transport_handshake_t;

/* Callback used to tell the parent transport ctx that the handshake requires a call to `wickr_transport_handshake_verify_identity` to continue */
typedef void (*wickr_transport_handshake_identity_callback)(const wickr_transport_handshake_t *handshake,
                                                            wickr_identity_chain_t *identity,
                                                            void *user);

/**
 @ingroup wickr_transport_handshake
 
 Create a new transport handshake. Will retain ownership of all pointer inputs will be owned except for `user`
 
 @param engine a crypto engine to use for underlying crypto operations
 @param local_identity the identity chain of the current local user, must include private keys for signing
 @param remote_identity a known identity chain of the recipient of the handshake request. This will prevent calls to `identity_callback` (optional)
 @param identity_callback if no `remote_identity` is specified, the learned identity of the remote party will be validated by the transport ctx using a callback
 @param evo_count used to negotiate the key evolution protocol that will be used by either party after the handshake is over
 @param user a pointer to user data that can be held for use in the identity callback
 @return a newly allocated transport handshake or NULL if non-optional values are improperly set
 */
wickr_transport_handshake_t *wickr_transport_handshake_create(wickr_crypto_engine_t engine,
                                                              wickr_identity_chain_t *local_identity,
                                                              wickr_identity_chain_t *remote_identity,
                                                              wickr_transport_handshake_identity_callback identity_callback,
                                                              uint32_t evo_count,
                                                              void *user);

/**
 @ingroup wickr_transport_handshake
 
 Make a deep copy of a transport handshake result
 
 @param handshake the handshake  to make a copy of
 @return a newly allocated transport handshake holding a deep copy of the properties of 'handshake'
*/
wickr_transport_handshake_t *wickr_transport_handshake_copy(const wickr_transport_handshake_t *handshake);

/**
@ingroup wickr_transport_handshake

Destroy a transport handshake
@param handshake a pointer to the transport handshake to destroy. All properties of `*handshake` will also be destroyed
*/
void wickr_transport_handshake_destroy(wickr_transport_handshake_t **handshake);

/**
 @ingroup wickr_transport_handshake
 
 Start the handshake process. Calling this function will change the status of the handshake to `TRANSPORT_HANDSHAKE_STATUS_IN_PROGRESS`.
 This function can **only** be called if the handshake is currently in the TRANSPORT_HANDSHAKE_STATUS_UNKNOWN state (saw no other activity)
 
 @param handshake the transport handshake to start
 @return the transport packet to relay back to transport_ctx to send to the remote party. Returns NULL on failure, along with setting the transport status
 to TRANSPORT_HANDSHAKE_STATUS_FAILED
 */
wickr_transport_packet_t *wickr_transport_handshake_start(wickr_transport_handshake_t *handshake);

/**
 @ingroup wickr_transport_handshake
 
 Process an inbound transport packet for a handshake. This function cause the handshake to move to the failure state on error.
 If a handshake is starting by receiving a packet rather than starting, this will be the first function called after being constructed
 
 @param handshake the handshake to process the packet in
 @param packet the packet to process with `handshake`
 @return a return packet to send back to the sender of `packet`. NULL on error **or** no further packet response required. Call wickr_transport_handshake_get_status to differentiate
 */
wickr_transport_packet_t *wickr_transport_handshake_process(wickr_transport_handshake_t *handshake,
                                                            const wickr_transport_packet_t *packet);

/**
 @ingroup wickr_transport_handshake
 
 Tell the handshake if a remote identity is valid or not to move on from the TRANSPORT_HANDSHAKE_STATUS_PENDING_VERIFICATION state
 
 @param handshake the handshake to verify the remote identity of
 @param is_valid tell the handshake if the remote identity is valid or not
 @return a return packet to send back to the remote side (if needed). NULL on `is_valid` being false, no further communication required or other error
 Call wickr_transport_handshake_get_status to differentiate
 */
wickr_transport_packet_t *wickr_transport_handshake_verify_identity(const wickr_transport_handshake_t *handshake, bool is_valid);

/**
 @ingroup wickr_transport_handshake
 
 Finalize a handshake to complete it (can only be called when the handshake is in the TRANSPORT_HANDSHAKE_STATUS_PENDING_FINALIZATION state)
 A handshake can only be finalized once, at which point it's status will change to TRANSPORT_HANDSHAKE_STATUS_COMPLETE and no other operations are valid
 
 @param handshake the handshake to finalize
 @return the result of the handshake on success, or NULL on failure
 */
wickr_transport_handshake_res_t *wickr_transport_handshake_finalize(wickr_transport_handshake_t *handshake);

/**
 @ingroup wickr_transport_handshake
 
 Get the current status of a handshake
 
 @param handshake the handshake to get the status of
 @return the current status of the handshake
 */
const wickr_transport_handshake_status wickr_transport_handshake_get_status(const wickr_transport_handshake_t *handshake);

/**
 @ingroup wickr_transport_handshake

 Get the local identity chain of a handshake

 @param handshake the handshake to get the local identity chain of
 @return the current status of the handshake
*/
const wickr_identity_chain_t *wickr_transport_handshake_get_local_identity(const wickr_transport_handshake_t *handshake);

/**
 @ingroup wickr_transport_handshake

 Get the remote identity chain of a handshake

 @param handshake the handshake to get the remote identity chain of
 @return the current status of the handshake
*/
const wickr_identity_chain_t *wickr_transport_handshake_get_remote_identity(const wickr_transport_handshake_t *handshake);

/**
 @ingroup wickr_transport_handshake

 Get the current user provided data of a handshake

 @param handshake the handshake to get the user provided data of
 @return the current user provided data of the handshake
*/
const void *wickr_transport_handshake_get_user_data(const wickr_transport_handshake_t *handshake);

/**
 @ingroup wickr_transport_handshake

 Set the current user provided data of a handshake

 @param handshake the handshake to get the user provided data of
 @param user the new user provided data
*/
void wickr_transport_set_user_data(wickr_transport_handshake_t *handshake, void *user);

#ifdef __cplusplus
}
#endif

#endif /* transport_handshake_h */
