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

#ifndef eckey_priv_h
#define eckey_priv_h

#include <protobuf-c/protobuf-c.h>
#include "eckey.h"
#include "crypto_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 
 @ingroup wickr_ec_curve
 
 Create an EC Key from protocol buffers binary data object

 @param buffer the protocol buffers binary data object to create the EC key with
 @param engine a crypto engine that supports the parsing / importing of EC keys
 @param is_private are the bytes in buffer a private or public key
 @return an EC key created from serialized bytes within 'buffer' or NULL if parsing buffer fails
 */
wickr_ec_key_t *wickr_ec_key_from_protobytes(ProtobufCBinaryData buffer,
                                             const wickr_crypto_engine_t *engine,
                                             bool is_private);
    
#ifdef __cplusplus
}
#endif

#endif /* eckey_priv_h */
