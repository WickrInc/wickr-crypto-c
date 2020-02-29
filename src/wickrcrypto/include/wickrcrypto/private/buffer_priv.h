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

#ifndef buffer_priv_h
#define buffer_priv_h

#include "buffer.h"
#include <protobuf-c/protobuf-c.h>

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 
 @ingroup wickr_buffer
 
 Create a wickr buffer from a protocol buffer binary data structure
 
 @param buffer the protocol buffer binary data to create the wickr_buffer from
 @return a wickr_buffer containing the contents of 'buffer' or NULL
 */
wickr_buffer_t *wickr_buffer_from_protobytes(ProtobufCBinaryData buffer);
    
/**
 @ingroup wickr_buffer

 Fill a protobuf binary data object with bytes from a wickr_buffer
 
 @param proto_bin pointer to the protobuf binary data to fill with bytes from 'buffer'
 @param buffer the buffer to copy into 'proto_bin'
 @return true if copy into 'proto_bin' is successful
 */
bool wickr_buffer_to_protobytes(ProtobufCBinaryData *proto_bin, const wickr_buffer_t *buffer);
    
#ifdef __cplusplus
}
#endif

#endif /* buffer_priv_h */
