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

#ifndef protocol_h
#define protocol_h

#include <stdlib.h>
#include "node.h"
#include "ecdh.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 @defgroup wickr_protocol Wickr Protocol
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
 @struct wickr_ephemeral_info
 @brief Message destruction control metadata
 @var wickr_ephemeral_info::ttl
 time-to-live is the amount of time from the time of sending that a message should live
 @var wickr_ephemeral_info::bor
 burn-on-read is the amount of time from decryption that a message should live
 */
struct wickr_ephemeral_info {
    uint64_t ttl;
    uint64_t bor;
};

typedef struct wickr_ephemeral_info wickr_ephemeral_info_t;


/**
 @ingroup wickr_protocol
 @struct wickr_packet_meta
 @brief control metadata found in the encrypted payload of a packet
 @var wickr_packet_meta::ephemerality_settings
 message destruction control information
 @var wickr_packet_meta::channel_tag
 a value used to help group messages together with a tag
 @var wickr_packet_meta::content_type
 a helper value optionally used to give some context to parsing the body. Currently, message body data is a serialized protocol buffer using the one-of type in all cases, and thus content_type is more of a legacy feature
 */
struct wickr_packet_meta {
    wickr_ephemeral_info_t ephemerality_settings;
    wickr_buffer_t *channel_tag;
    uint16_t content_type;
};

typedef struct wickr_packet_meta wickr_packet_meta_t;

/**
 
 @ingroup wickr_protocol
 
 Construct packet metadata from components

 @param ephemerality_settings see 'wickr_packet_meta' property documentation property documentation
 @param channel_tag see 'wickr_packet_meta' property documentation property documentation
 @param content_type see 'wickr_packet_meta' property documentation property documentation
 @return a newly allocated packet metadata set owning the properties passed in
 */
wickr_packet_meta_t *wickr_packet_meta_create(wickr_ephemeral_info_t ephemerality_settings,
                                              wickr_buffer_t *channel_tag,
                                              uint16_t content_type);

/**
 
 @ingroup wickr_protocol
 
 Copy an packet metadata set
 
 @param source the packet metadata set to copy
 @return a newly packet metadata set holding a deep copy of the properties of 'source'
 */
wickr_packet_meta_t *wickr_packet_meta_copy(const wickr_packet_meta_t *source);

/**
 
 @ingroup wickr_protocol
 
 Destroy packet metadata set
 
 @param meta a pointer to the result to destroy. All properties of '*meta' will also be destroyed
 */
void wickr_packet_meta_destroy(wickr_packet_meta_t **meta);

/**
 @ingroup wickr_protocol
 @struct wickr_key_exchange
 @brief Node-bound public key exchange data to put in a message header
 @var wickr_key_exchange::node_id
 the identifier of the node this key exchange is addressed to
 @var wickr_key_exchange::ephemeral_key_id
 the identifier of the 'wickr_ephemeral_key' owned by 'node_id' that was used to create the 'exchange_data'
 @var wickr_key_exchange::exchange_data
 computed key exchange data destined for 'node_id'
 */
struct wickr_key_exchange {
    wickr_buffer_t *node_id;
    uint64_t ephemeral_key_id;
    wickr_buffer_t *exchange_data;
};

typedef struct wickr_key_exchange wickr_key_exchange_t;

/**
 
 @ingroup wickr_protocol
 
 Create a key exchange from properties

 @param node_id see 'wickr_key_exchange' property documentation property documentation
 @param ephemeral_key_id see 'wickr_key_exchange' property documentation property documentation
 @param exchange_data see 'wickr_key_exchange' property documentation property documentation
 @return a newly allocated packet metadata set owning the properties passed in
 */
wickr_key_exchange_t *wickr_key_exchange_create(wickr_buffer_t *node_id,
                                                uint64_t ephemeral_key_id,
                                                wickr_buffer_t *exchange_data);

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
 @param packet_exchange_key an EC key to use for the sender side of the ECDH function, the private component of this key is no longer needed after this function is called. The public component of it will get forwarded in the message header to the receiver
 @param packet_key the cipher key to use for encrypting the payload of the message that is being created. This is the data we are protecting
 @param version the version of the packet being generated
 @return a newly allocated key exchange object holding public metadata about this exchange and the computed exchange data
 */
wickr_key_exchange_t *wickr_key_exchange_create_with_packet_key(const wickr_crypto_engine_t *engine,
                                                                const wickr_identity_chain_t *sender,
                                                                const wickr_node_t *receiver,
                                                                wickr_ec_key_t *packet_exchange_key,
                                                                const wickr_cipher_key_t *packet_key,
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
 @param packet_exchange_key an EC key to use for the sender side of the ECDH function, the private component of this key is no longer needed after this function is called. The public component of it will get forwarded in the message header to the receiver
 @param data_to_wrap This is the data we are protecting by the output of the key exchange
 @param exchange_cipher the cipher that the exchange should use protect 'data_to_wrap' with
 @param version the version of the packet being generated
 @return a newly allocated key exchange object holding public metadata about this exchange and the computed exchange data
 */
wickr_key_exchange_t *wickr_key_exchange_create_with_data(const wickr_crypto_engine_t *engine,
                                                          const wickr_identity_chain_t *sender,
                                                          const wickr_node_t *receiver,
                                                          wickr_ec_key_t *packet_exchange_key,
                                                          const wickr_buffer_t *data_to_wrap,
                                                          wickr_cipher_t exchange_cipher,
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
 @param version the version of the packet being decoded
 @return a cipher key or NULL if provided receiver key is incorrect and a cipher key cannot be decoded
 */
wickr_cipher_key_t *wickr_key_exchange_derive_packet_key(const wickr_crypto_engine_t *engine,
                                                         const wickr_identity_chain_t *sender,
                                                         const wickr_node_t *receiver,
                                                         wickr_ec_key_t *packet_exchange_key,
                                                         const wickr_key_exchange_t *exchange,
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
 @param version the version of the packet being decoded
 @return buffer or NULL if provided receiver key is incorrect and the wrapped data can't be decoded
 */
wickr_buffer_t *wickr_key_exchange_derive_data(const wickr_crypto_engine_t *engine,
                                               const wickr_identity_chain_t *sender,
                                               const wickr_node_t *receiver,
                                               wickr_ec_key_t *packet_exchange_key,
                                               const wickr_key_exchange_t *exchange,
                                               uint8_t version);

/**
 
 @ingroup wickr_protocol
 
 Copy a key exchange
 
 @param source the key exchange to copy
 @return a newly allocated node holding a deep copy of the properties of 'source'
 */
wickr_key_exchange_t *wickr_key_exchange_copy(const wickr_key_exchange_t *source);

/**
 
 @ingroup wickr_protocol
 
 Destroy a key exchange
 
 @param exchange a pointer to the key exchange to destroy. All properties of '*exchange' will also be destroyed
 */
void wickr_key_exchange_destroy(wickr_key_exchange_t **exchange);

typedef wickr_array_t wickr_exchange_array_t;

/**
 
 @ingroup wickr_protocol
 
 Allocate a new key exchange array

 @param exchange_count the number of exchanges the array should hold
 @return a newly allocated wickr_array for key exchange objects
 */
wickr_exchange_array_t *wickr_exchange_array_new(uint32_t exchange_count);

/**
 @ingroup wickr_protocol
 
 Set an item in a key exchange array

 NOTE: Calling this function does not make a copy of 'exchange', the array simply takes ownership of it
 
 @param array the array to set 'exchange' into
 @param index the location in 'array' to set exchange
 @param exchange the exchange to set at position 'index' in 'array'
 @return true if setting succeeds, false if the index is out of bounds
 */
bool wickr_exchange_array_set_item(wickr_exchange_array_t *array, uint32_t index, wickr_key_exchange_t *exchange);

/**
 @ingroup wickr_protocol
 
 Fetch a key exchange from an exchange array
 
 NOTE: Calling this function does not make a copy of the exchange being returned, the array still owns it

 @param array the array to fetch 'index' from
 @param index the index to fetch from 'array'
 @return a key exchange representing 'index' from the array
 */
wickr_key_exchange_t *wickr_exchange_array_fetch_item(wickr_exchange_array_t *array, uint32_t index);

/**
 @ingroup wickr_protocol

 @param array the array to copy
 @return a newly allocated key exchange array that contains deep copies of the items from 'array'
 */
wickr_array_t *wickr_exchange_array_copy(wickr_exchange_array_t *array);

/**
 @ingroup wickr_protocol

 @param array a pointer to the array to destroy, all items of '*array' are also destroyed
 */
void wickr_exchange_array_destroy(wickr_exchange_array_t **array);

/**
 @ingroup wickr_protocol
 @struct wickr_packet_header
 @brief The public header of Wickr Packets. Packets can be sent to multiple nodes, the key for the packet body is derived by each recipient node using an individualized key exchange. See Wickr white paper 'Prepare Packet Header' section for more information.
 
 @var wickr_packet_header::sender_pub
 the public EC key that the sender used to derive the key exchanges contained within 'exchanges'
 @var wickr_packet_header::exchanges
 an array of key exchanges, one for each node that will be receiving this message
 */
struct wickr_packet_header {
    wickr_ec_key_t *sender_pub;
    wickr_exchange_array_t *exchanges;
};

typedef struct wickr_packet_header wickr_packet_header_t;

/**
 @ingroup wickr_protocol
 
 Create a packet header from components

 @param sender_pub see 'wickr_packet_header' property documentation property documentation
 @param exchanges see 'wickr_packet_header' property documentation property documentation
 @return a newly allocated packet header owning the properties passed in
 */
wickr_packet_header_t *wickr_packet_header_create(wickr_ec_key_t *sender_pub, wickr_exchange_array_t *exchanges);

/**
 @ingroup wickr_protocol
 
 Find a particular entry in the exchange list of a packet header

 @param header the header to search
 @param node_id the node identifier of the exchange to find
 @return the key exchange for 'node_id' or NULL if it cannot be found
 */
wickr_key_exchange_t *wickr_packet_header_find(const wickr_packet_header_t *header, const wickr_buffer_t *node_id);

/**
 
 @ingroup wickr_protocol
 
 Copy a packet header
 
 @param source the packet header to copy
 @return a newly allocated packet header holding a deep copy of the properties of 'source'
 */
wickr_packet_header_t *wickr_packet_header_copy(const wickr_packet_header_t *source);

/**
 
 @ingroup wickr_protocol
 
 Destroy a packet header
 
 @param header a pointer to the packet header to destroy. All properties of '*header' will also be destroyed
 */
void wickr_packet_header_destroy(wickr_packet_header_t **header);

/**
 @ingroup wickr_protocol
 
 Serialize-Then-Encrypt a packet header
 
 Packet headers are serialized using protocol buffers (message.pb-c.h)
 
 NOTE: This is a low level function that should not be called directly from this API if it can be avoided. Please use the 'wickr_ctx' API instead since it is a higher level and safer set of functions


 @param header the header to encrypt
 @param engine a crypto engine capable of encryption using header_key
 @param header_key the key to encrypt the header with
 @return an encrypted header
 */
wickr_cipher_result_t *wickr_packet_header_encrypt(const wickr_packet_header_t *header,
                                                   const wickr_crypto_engine_t *engine,
                                                   const wickr_cipher_key_t *header_key);

/**
 @ingroup wickr_protocol
 
 Decrypt-Then-Deserialize a packet header
 
 NOTE: This is a low level function that should not be called directly from this API if it can be avoided. Please use the 'wickr_ctx' API instead since it is a higher level and safer set of functions

 @param engine a crypto engine capable of decryption using header_key
 @param cipher_result an encrypted packet header
 @param header_key the key to use for decryption
 @return a decrypted packet header or NULL if the decryption key is incorrect
 */
wickr_packet_header_t *wickr_packet_header_create_from_cipher(const wickr_crypto_engine_t *engine,
                                                              const wickr_cipher_result_t *cipher_result,
                                                              const wickr_cipher_key_t *header_key);

/**
 @ingroup wickr_protocol
 @struct wickr_payload
 @brief The encrypted body content of a Wickr packet
 @var wickr_payload::meta
 protected metadata for the body
 @var wickr_payload::body
 the body content of the message as provided by the sender
 */
struct wickr_payload {
    wickr_packet_meta_t *meta;
    wickr_buffer_t *body;
};

typedef struct wickr_payload wickr_payload_t;

/**
 @ingroup wickr_protocol
 
 Create a payload from components

 @param meta see 'wickr_payload' property documentation property documentation
 @param body see 'wickr_payload' property documentation property documentation
 @return a newly allocated payload owning the properties passed in
 */
wickr_payload_t *wickr_payload_create(wickr_packet_meta_t *meta, wickr_buffer_t *body);

/**
 
 @ingroup wickr_protocol
 
 Copy a payload
 
 @param source the payload to copy
 @return a newly allocated payload holding a deep copy of the properties of 'source'
 */
wickr_payload_t *wickr_payload_copy(const wickr_payload_t *source);

/**
 
 @ingroup wickr_protocol
 
 Destroy a payload
 
 @param payload a pointer to the payload to destroy. All properties of '*payload' will also be destroyed
 */
void wickr_payload_destroy(wickr_payload_t **payload);

/**
 @ingroup wickr_protocol
 
 Serialize-Then-Encrypt a payload
 
 Payloads are serialized using protocol buffers (message.pb-c.h)
 NOTE: This is a low level function that should not be called directly from this API if it can be avoided. Please use the 'wickr_ctx' API instead since it is a higher level and safer set of functions


 @param payload the payload to encrypt
 @param engine a crypto engine capable of encryption using payload_key
 @param payload_key the key to use for encryption
 @return an encrypted payload
 */
wickr_cipher_result_t *wickr_payload_encrypt(const wickr_payload_t *payload,
                                             const wickr_crypto_engine_t *engine,
                                             const wickr_cipher_key_t *payload_key);

/**
 @ingroup wickr_protocol
 
 Decrypt-Then-Deserialize
 
 NOTE: This is a low level function that should not be called directly from this API if it can be avoided. Please use the 'wickr_ctx' API instead since it is a higher level and safer set of functions

 @param engine a crypto engine capable of decryption using payload_key
 @param cipher_result an encrypted payload
 @param payload_key the key to use for decrypting 'cipher_result'
 @return a payload or NULL if an incorrect key is provided
 */
wickr_payload_t *wickr_payload_create_from_cipher(const wickr_crypto_engine_t *engine,
                                                  const wickr_cipher_result_t *cipher_result,
                                                  const wickr_cipher_key_t *payload_key);

/**
 @ingroup wickr_protocol
 @struct wickr_packet
 @brief An encrypted packet made with the Wickr protocol
 
 @var wickr_packet::version
 the protocol version of the packet
 @var wickr_packet::content
 the content of the packet including the serialized header, and payload
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
 @var wickr_parse_result::header
 parsed header content of the message after decrypting it with the header key
 @var wickr_parse_result::key_exchange
 if requested, a key exchange belonging to your node will be copied to this property and a failed search will lead to a decode error. If not requested key_exchange will be NULL
 @var wickr_parse_result::enc_payload
 the encrypted payload of the message, to decrypt the payload you must call 'wickr_decode_result_from_parse_result' with the private key matching the 'ephemeral_key_id' from 'key_exchange'
 */
struct wickr_parse_result {
    wickr_decode_error err;
    wickr_packet_signature_status signature_status;
    wickr_packet_header_t *header;
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

 @param header the parsed header information
 @param key_exchange discovered key exchange for a particular requested node, or NULL if no node was specified
 @param enc_payload the encrypted payload parsed from the message
 @return a parse result containing the provided information and non-error codes for 'signature_status' and 'err'
 */
wickr_parse_result_t *wickr_parse_result_create_success(wickr_packet_header_t *header,
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
 @param header_key the key to encrypt the header of the message with
 @param payload_key the key to encrypt the payload of the message with
 @param exchange_key the key to use as the local key exchange keypair, the public side of this key will wind up in the resulting packet header
 @param payload the plaintext payload to encrypt and bundle into the packet
 @param recipients the array of nodes that the
 @param sender_signing_identity the identity chain belonging to the creator of the packet
 @return a 'sender_signing_identity' signed packet containing encrypted payload 'payload, and header containing key exchanges for 'recipients'
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
 @param receiver_node_id node_id of the recipient. If set, parsing will fail if a node_id labeled key exchange is not found in the decoded header's key exchange list. If not set, the resulting parse result will contain NULL for the key exchange and simply return all other properties
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
