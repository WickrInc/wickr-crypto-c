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

#ifndef protocol_h
#define protocol_h

#include <stdlib.h>
#include "node.h"
#include "key_exchange.h"
#include "payload.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 @addtogroup wickr_protocol Wickr Protocol
 */

/**
 @ingroup wickr_protocol
 The oldest packet version supported is version 2
 */
#define OLDEST_PACKET_VERSION 2

/**
 @ingroup wickr_protocol
 The most recent version of the protocol is version 4
 */
#define CURRENT_PACKET_VERSION 4

typedef enum {
    E_SUCCESS,
    ERROR_INVALID_INPUT,
    ERROR_NODE_NOT_FOUND,
    ERROR_CORRUPT_PACKET,
    ERROR_KEY_EXCHANGE_FAILED,
    ERROR_MAC_INVALID
} wickr_decode_error;

typedef enum {
    PACKET_SIGNATURE_UNKNOWN,
    PACKET_SIGNATURE_VALID,
    PACKET_SIGNATURE_INVALID
} wickr_packet_signature_status;

/**
 
 @ingroup wickr_protocol
 
 Compute a key exchange given sender/receiver information and a packet key to protect (Sender Encoding)
 Thie function is a convience function around 'wickr_key_exchange_create_with_data' that determines exchange_cipher automaticallly
 based on 'packet_key' cipher and also takes care of serializing 'packet_key'
 
 See Wickr white paper 'Prepare Key Exchange Data' for more information
 
 NOTE: This is a low level function that should not be called directly from this API if it can be avoided. Please use the 'wickr_ctx' API instead since it is a higher level and safer set of functions

 @param engine a crypto engine supporting ECDH key exchanges
 @param sender the identity chain of the sender
 @param receiver the node this key exchange is destined for
 @param packet_exchange_key an EC key to use for the sender side of the ECDH function, the private component of this key is no longer needed after this function is called. The public component of it will get forwarded in the message key exchange set to the receiver
 @param packet_key the cipher key to use for encrypting the payload of the message that is being created. This is the data we are protecting
 @param psk optional pre-shared key data to put into the 'salt' field of HKDF
 @param version the version of the packet being generated
 @return a newly allocated key exchange object holding public metadata about this exchange and the computed exchange data
 */
wickr_key_exchange_t *wickr_key_exchange_create_with_packet_key(const wickr_crypto_engine_t *engine,
                                                                const wickr_identity_chain_t *sender,
                                                                const wickr_node_t *receiver,
                                                                wickr_ec_key_t *packet_exchange_key,
                                                                const wickr_cipher_key_t *packet_key,
                                                                const wickr_buffer_t *psk,
                                                                uint8_t version);

/**
 
 @ingroup wickr_protocol
 
 Compute a key exchange given sender/receiver information and bytes to protect (Sender Encoding)
 This method at a high level creates a shared secret between a sender and receiver (ECDH), runs the shared secret through a kdf (HKDF)
 and then uses the resulting secret as a cipher key to encrypt bytes of data. 'wickr_key_exchange_create_with_packet_key' also exists as
 a version of this function to specifically wrap cipher_keys instead of raw data
 
 See Wickr white paper 'Prepare Key Exchange Data' for more information
 
 NOTE: This is a low level function that should not be called directly from this API if it can be avoided. Please use the 'wickr_ctx' API instead since it is a higher level and safer set of functions
 
 @param engine a crypto engine supporting ECDH key exchanges
 @param sender the identity chain of the sender
 @param receiver the node this key exchange is destined for
 @param packet_exchange_key an EC key to use for the sender side of the ECDH function, the private component of this key is no longer needed after this function is called. The public component of it will get forwarded in the message key exchange set to the receiver
 @param data_to_wrap This is the data we are protecting by the output of the key exchange
 @param exchange_cipher the cipher that the exchange should use protect 'data_to_wrap' with
 @param psk optional pre-shared key data to put into the 'salt' field of HKDF
 @param version the version of the packet being generated
 @return a newly allocated key exchange object holding public metadata about this exchange and the computed exchange data
 */
wickr_key_exchange_t *wickr_key_exchange_create_with_data(const wickr_crypto_engine_t *engine,
                                                          const wickr_identity_chain_t *sender,
                                                          const wickr_node_t *receiver,
                                                          wickr_ec_key_t *packet_exchange_key,
                                                          const wickr_buffer_t *data_to_wrap,
                                                          wickr_cipher_t exchange_cipher,
                                                          const wickr_buffer_t *psk,
                                                          uint8_t version);

/**
 Derive a packet key given a key exchange, and a receiver private exchange key (Receiver Decoding)
 This function is a conveinence function around 'wickr_key_exchange_derive_packet_key'. The returned key is created
 by treating the output of 'wickr_key_exchange_derive_packet_key' as a serialized wickr_cipher_key
 
 See Wickr white paper 'Receiving a Message' for more information
 
 NOTE: This is a low level function that should not be called directly from this API if it can be avoided. Please use the 'wickr_ctx' API instead since it is a higher level and safer set of functions

 @param engine a crypto engine supporting ECDH key exchanges
 @param sender the identity chain of the original creator of the key exchange
 @param receiver a node representing the receiver, including an 'ephemeral_keyair' property that has a matching identifier to 'ephemeral_key_id' in the key exchange, and the proper private key materal associated with it
 @param packet_exchange_key the public EC key information that was used for the 'packet_exchange_key' param of 'wickr_key_exchange_create_with_packet_key'
 @param exchange the key exchange to decode into a cipher key
 @param psk optional pre-shared key data to put into the 'salt' field of HKDF
 @param version the version of the packet being decoded
 @return a cipher key or NULL if provided receiver key is incorrect and a cipher key cannot be decoded
 */
wickr_cipher_key_t *wickr_key_exchange_derive_packet_key(const wickr_crypto_engine_t *engine,
                                                         const wickr_identity_chain_t *sender,
                                                         const wickr_node_t *receiver,
                                                         wickr_ec_key_t *packet_exchange_key,
                                                         const wickr_key_exchange_t *exchange,
                                                         const wickr_buffer_t *psk,
                                                         uint8_t version);

/**
 Decode data that was protected by a key exchnage, this is the decode side of 'wickr_key_exchange_create_with_data' (Receiver Decoding)
 
 See Wickr white paper 'Receiving a Message' for more information
 
 NOTE: This is a low level function that should not be called directly from this API if it can be avoided. Please use the 'wickr_ctx' API instead since it is a higher level and safer set of functions
 
 @param engine a crypto engine supporting ECDH key exchanges
 @param sender the identity chain of the original creator of the key exchange
 @param receiver a node representing the receiver, including an 'ephemeral_keyair' property that has a matching identifier to 'ephemeral_key_id' in the key exchange, and the proper private key materal associated with it
 @param packet_exchange_key the public EC key information that was used for the 'packet_exchange_key' param of 'wickr_key_exchange_create_with_packet_key'
 @param exchange the key exchange to decode into a cipher key
 @param psk optional pre-shared key data to put into the 'salt' field of HKDF
 @param version the version of the packet being decoded
 @return buffer or NULL if provided receiver key is incorrect and the wrapped data can't be decoded
 */
wickr_buffer_t *wickr_key_exchange_derive_data(const wickr_crypto_engine_t *engine,
                                               const wickr_identity_chain_t *sender,
                                               const wickr_node_t *receiver,
                                               wickr_ec_key_t *packet_exchange_key,
                                               const wickr_key_exchange_t *exchange,
                                               const wickr_buffer_t *psk,
                                               uint8_t version);

/**
 @ingroup wickr_protocol
 @struct wickr_packet
 @brief An encrypted packet made with the Wickr protocol
 
 @var wickr_packet::version
 the protocol version of the packet
 @var wickr_packet::content
 the content of the packet including the serialized key exchange set, and payload
 @var wickr_packet::signature
 the ECDSA signature of 'content'
 */
struct wickr_packet {
    uint8_t version;
    wickr_buffer_t *content;
    wickr_ecdsa_result_t *signature;
};

typedef struct wickr_packet wickr_packet_t;

/**
 @ingroup wickr_protocol
 
 Create a packet from components

 @param version see 'wickr_protocol' property documentation property documentation
 @param content see 'wickr_protocol' property documentation property documentation
 @param signature see 'wickr_protocol' property documentation property documentation
 @return a newly allocated packet owning the properties passed in
 */
wickr_packet_t *wickr_packet_create(uint8_t version, wickr_buffer_t *content, wickr_ecdsa_result_t *signature);

/**
 @ingroup wickr_protocol
 
 Parse a packet from a buffer generated by 'wickr_packet_serialize'

 @param buffer a buffer output from 'wickr_packet_serialize'
 @return a newly allocated packet using parsed data from 'buffer' or NULL if parsing fails
 */
wickr_packet_t *wickr_packet_create_from_buffer(const wickr_buffer_t *buffer);

/**
 @ingroup wickr_protocol
 
 Serialize a packet to a buffer

 @param packet the packet to serialize
 @return a buffer representing the packet in the following format:
    | VERSION (4BITS) SIGNATURE_CURVE_ID (4BITS) | CONTENT | SIGNATURE OF CONTENT |
 */
wickr_buffer_t *wickr_packet_serialize(const wickr_packet_t *packet);

/**
 
 @ingroup wickr_protocol
 
 Copy a packet
 
 @param source the packet to copy
 @return a newly allocated packet holding a deep copy of the properties of 'source'
 */
wickr_packet_t *wickr_packet_copy(const wickr_packet_t *source);

/**
 
 @ingroup wickr_protocol
 
 Destroy a packet
 
 @param packet a pointer to the packet to destroy. All properties of '*packet' will also be destroyed
 */
void wickr_packet_destroy(wickr_packet_t **packet);

/**
 @ingroup wickr_protocol
 @struct wickr_parse_result
 @brief result from parsing an inbound packet
 
 @var wickr_parse_result::err
 status of the parse operation
 @var wickr_parse_result::signature_status
 status of the message signature
 @var wickr_parse_result::key_exchange_set
 parsed key exchange set for the message after decrypting it with the header key
 @var wickr_parse_result::key_exchange
 if requested, a key exchange belonging to your node will be copied to this property and a failed search will lead to a decode error. If not requested key_exchange will be NULL
 @var wickr_parse_result::enc_payload
 the encrypted payload of the message, to decrypt the payload you must call 'wickr_decode_result_from_parse_result' with the private key matching the 'ephemeral_key_id' from 'key_exchange'
 */
struct wickr_parse_result {
    wickr_decode_error err;
    wickr_packet_signature_status signature_status;
    wickr_key_exchange_set_t *key_exchange_set;
    wickr_key_exchange_t *key_exchange;
    wickr_cipher_result_t *enc_payload;
};

typedef struct wickr_parse_result wickr_parse_result_t;

/**
 @ingroup wickr_protocol
 
 Create a negative parse result due to a failure

 @param signature_status status of packet signature validation
 @param error error message related to parsing the packet
 @return a parse result containing the provided status information and NULL properties
 */
wickr_parse_result_t *wickr_parse_result_create_failure(wickr_packet_signature_status signature_status,
                                                        wickr_decode_error error);

/**
 @ingroup wickr_protocol
 
 Create a positive parse result

 @param key_exchange_set the parsed public key exchange set for all recipients
 @param key_exchange discovered key exchange for a particular requested node, or NULL if no node was specified
 @param enc_payload the encrypted payload parsed from the message
 @return a parse result containing the provided information and non-error codes for 'signature_status' and 'err'
 */
wickr_parse_result_t *wickr_parse_result_create_success(wickr_key_exchange_set_t *key_exchange_set,
                                                        wickr_key_exchange_t *key_exchange,
                                                        wickr_cipher_result_t *enc_payload);

/**
 
 @ingroup wickr_protocol
 
 Copy a parse result
 
 @param source the parse result to copy
 @return a newly allocated parse result holding a deep copy of the properties of 'source'
 */
wickr_parse_result_t *wickr_parse_result_copy(const wickr_parse_result_t *source);

/**
 
 @ingroup wickr_protocol
 
 Destroy a parse result
 
 @param result a pointer to the parse result to destroy. All properties of '*result' will also be destroyed
 */
void wickr_parse_result_destroy(wickr_parse_result_t **result);

/**
 @ingroup wickr_protocol
 @struct wickr_decode_result
 @brief a packet decoding result
 @var wickr_decode_result::err
 error status for the decode
 @var wickr_decode_result::payload_key
 the payload key that was derived from the key exchange during decoding
 @var wickr_decode_result::decrypted_payload 
 the payload that was decrypted from the packet using payload_key
 */
struct wickr_decode_result {
    wickr_decode_error err;
    wickr_cipher_key_t *payload_key;
    wickr_payload_t *decrypted_payload;
};

typedef struct wickr_decode_result wickr_decode_result_t;

/**
 @ingroup wickr_protocol
 
 Create a negative decode result

 @param decode_error the error found during decoding
 @return a newly allocated decode result with error 'decode_error' and NULL for other properties
 */
wickr_decode_result_t *wickr_decode_result_create_failure(wickr_decode_error decode_error);

/**
 @ingroup wickr_protocol
 
 Create a positive decode result

 @param decrypted_payload the decrypted payload found during decoding
 @param payload_key the payload key derived during decoding
 @return a newly allocated decode result with no error
 */
wickr_decode_result_t *wickr_decode_result_create_success(wickr_payload_t *decrypted_payload,
                                                          wickr_cipher_key_t *payload_key);

/**
 
 @ingroup wickr_protocol
 
 Copy a decode result
 
 @param result the decode result to copy
 @return a newly allocated decode result holding a deep copy of the properties of 'source'
 */
wickr_decode_result_t *wickr_decode_result_copy(const wickr_decode_result_t *result);

/**
 
 @ingroup wickr_protocol
 
 Destroy a decode result
 
 @param result a pointer to the decode result to destroy. All properties of '*result' will also be destroyed
 */
void wickr_decode_result_destroy(wickr_decode_result_t **result);

/**
 @ingroup wickr_protocol

 Generate a packet given components
 
 For more information see Wickr white paper (Sending a Message)
 
 NOTE: This is a low level function that should not be called directly from this API if it can be avoided. Please use the 'wickr_ctx' API instead since it is a higher level and safer set of functions

 @param engine a crypto engine capable of ECDH and signing operations using exchange_key, and cipher operations using payload_key
 @param header_key the key to encrypt the key exchange set of the message with
 @param payload_key the key to encrypt the payload of the message with
 @param exchange_key the key to use as the local key exchange keypair, the public side of this key will wind up in the resulting packet key exchange set
 @param payload the plaintext payload to encrypt and bundle into the packet
 @param recipients the array of nodes that the
 @param sender_signing_identity the identity chain belonging to the creator of the packet
 @param version the version of the protocol encoding to use for this packet
 @return a 'sender_signing_identity' signed packet containing encrypted payload 'payload, and key exchange set for 'recipients'
 */
wickr_packet_t *wickr_packet_create_from_components(const wickr_crypto_engine_t *engine,
                                                    const wickr_cipher_key_t *header_key,
                                                    const wickr_cipher_key_t *payload_key,
                                                    wickr_ec_key_t *exchange_key,
                                                    const wickr_payload_t *payload,
                                                    const wickr_node_array_t *recipients,
                                                    const wickr_identity_chain_t *sender_signing_identity,
                                                    uint8_t version);

typedef wickr_cipher_key_t *(*wickr_header_keygen_func)(const wickr_crypto_engine_t engine, wickr_cipher_t cipher, const wickr_identity_chain_t *id_chain);

/**
 
 @ingroup wickr_protocol
 Parse a received packet and validate it's signature
 
 For more information see Wickr white paper (Receiving a Message 1-5)
 
 NOTE: This is a low level function that should not be called directly from this API if it can be avoided. Please use the 'wickr_ctx' API instead since it is a higher level and safer set of functions

 @param engine a crypto engine
 @param packet the packet to parse
 @param receiver_node_id node_id of the recipient. If set, parsing will fail if a node_id labeled key exchange is not found in the key exchange list. If not set, the resulting parse result will contain NULL for the key exchange and simply return all other properties
 @param header_keygen_func a function that can generate a header key for this packet
 @param sender_signing_identity the sender of the packet
 @return a parse result containing a successful or unsuccessful error and signature status
 */
wickr_parse_result_t *wickr_parse_result_from_packet(const wickr_crypto_engine_t *engine,
                                                     const wickr_packet_t *packet,
                                                     const wickr_buffer_t *receiver_node_id,
                                                     wickr_header_keygen_func header_keygen_func,
                                                     const wickr_identity_chain_t *sender_signing_identity);

/**
 @ingroup wickr_protocol
 
 Decode a parsed packet payload using a fetched ephemeral decode_key
 
 For more information see Wickr white paper (Receiving a Message 6-9)
 
 NOTE: This is a low level function that should not be called directly from this API if it can be avoided. Please use the 'wickr_ctx' API instead since it is a higher level and safer set of functions

 @param packet the packet to decode
 @param engine a crypto engine
 @param parse_result a previously generated parse result from 'packet'
 @param receiver_dev_id the 'msg_proto_id' of 'wickr_dev_info' of the recipient
 @param receiver_decode_key the key to attempt to complete the key exchange for discovered in the parse phase, so that the payload can be decoded
 @param receiver_signing_identity the recipient of the packet
 @param sender_signing_identity the sender of the packet used
 @return a decode result containing decrypted packet information if decode succeeded
 */
wickr_decode_result_t *wickr_decode_result_from_parse_result(const wickr_packet_t *packet,
                                                             const wickr_crypto_engine_t *engine,
                                                             const wickr_parse_result_t *parse_result,
                                                             wickr_buffer_t *receiver_dev_id,
                                                             wickr_ec_key_t *receiver_decode_key,
                                                             wickr_identity_chain_t *receiver_signing_identity,
                                                             const wickr_identity_chain_t *sender_signing_identity);

#ifdef __cplusplus
}
#endif

#endif /* protocol_h */
