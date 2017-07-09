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

#ifndef protobuf_util_h
#define protobuf_util_h

#include <stdio.h>
#include "cipher.h"
#include "storage.pb-c.h"
#include "crypto_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 
 @defgroup protobuf_utils protobuf utilities
 
 @ingroup protobuf_utils
 
 Create a cipher key from protocol buffers binary data object

 @param buffer the protocol buffers binary data object to create the cipher key with
 @return a cipher key created from serialized bytes within 'buffer' or NULL if parsing buffer fails
 */
wickr_cipher_key_t *wickr_cipher_key_from_protobytes(ProtobufCBinaryData buffer);

/**
 
 @ingroup protobuf_utils
 
 Create an EC Key from protocol buffers binary data object

 @param buffer the protocol buffers binary data object to create the EC key with
 @param engine a crypto engine that supports the parsing / importing of EC keys
 @param is_private are the bytes in buffer a private or public key
 @return an EC key created from serialized bytes within 'buffer' or NULL if parsing buffer fails
 */
    wickr_ec_key_t *wickr_ec_key_from_protobytes(ProtobufCBinaryData buffer, const wickr_crypto_engine_t *engine, bool is_private);
    
/**
 
 @ingroup protobuf_utils
 
 Create an ECDSA result from protocol buffers binary data object
 
 @param buffer the protocol buffers binary data object to create the ecdsa result with
 @return an ecdsa result created from serialized bytes within 'buffer' or NULL if parsing buffer fails
 */
wickr_ecdsa_result_t *wickr_ecdsa_result_from_protobytes(ProtobufCBinaryData buffer);

/**
 
 @ingroup protobuf_utils
 
 Create a wickr buffer from a protocol buffer binary data structure
 
 @param buffer the protocol buffer binary data to create the wickr_buffer from
 @return a wickr_buffer containing the contents of 'buffer' or NULL
 */
wickr_buffer_t *wickr_buffer_from_protobytes(ProtobufCBinaryData buffer);
    
#ifdef __cplusplus
}
#endif

#endif /* protobuf_util_h */
