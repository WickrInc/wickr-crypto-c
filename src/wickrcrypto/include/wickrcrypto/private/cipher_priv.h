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

#ifndef cipher_priv_h
#define cipher_priv_h

#include "cipher.h"
#include <protobuf-c/protobuf-c.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 
 @ingroup wickr_cipher
 
 Create a cipher key from protocol buffers binary data object

 @param buffer the protocol buffers binary data object to create the cipher key with
 @return a cipher key created from serialized bytes within 'buffer' or NULL if parsing buffer fails
 */
wickr_cipher_key_t *wickr_cipher_key_from_protobytes(ProtobufCBinaryData buffer);

/**
 
 @ingroup wickr_cipher
 
 Create a cipher result from protocol buffers binary data object
 
 @param buffer the protocol buffers binary data object to create the cipher result with
 @return a cipher result created from serialized bytes within 'buffer' or NULL if parsing buffer fails
 */
wickr_cipher_result_t *wickr_cipher_result_from_protobytes(ProtobufCBinaryData buffer);
    
/**
 
 @ingroup wickr_cipher
 
 Serialize a cipher key to a Protobuf data object
 
 @param proto_bin a pointer to the protobuf binary data to fill
 @param cipher_key the cipher key to serialize into 'proto_bin'
 @return true if 'proto_bin' can be filled and false if 'cipher_key' fails serialization
 
 */
bool wickr_cipher_key_to_protobytes(ProtobufCBinaryData *proto_bin, const wickr_cipher_key_t *cipher_key);

/**
 
 @ingroup wickr_cipher
 
 Serialize a cipher key to a Protobuf data object
 
 @param proto_bin a pointer to the protobuf binary data to fill
 @param cipher_result the cipher result to serialize into 'proto_bin'
 @return true if 'proto_bin' can be filled and false if 'cipher_result' fails serialization
 
 */
bool wickr_cipher_result_to_protobytes(ProtobufCBinaryData *proto_bin, const wickr_cipher_result_t *cipher_result);
    
#ifdef __cplusplus
}
#endif

#endif /* cipher_priv_h */
