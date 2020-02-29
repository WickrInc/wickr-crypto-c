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

#ifndef util_h
#define util_h

#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 
 @addtogroup data_conversion_utilities Data Conversion Utilities
 
 */

/**
 
 @ingroup data_conversion_utilities
 
 Convert data to base64 format

 @param objData the buffer to convert
 @return a buffer containing a null-terminated base64 string representation of objData
 */
wickr_buffer_t * getBase64FromData(const wickr_buffer_t * objData);

/**
 
 @ingroup data_conversion_utilities
 
 Convert a base64 string to data

 @param strBase64 a null terminated base64 buffer
 @return a buffer containing the data represented by the base64 buffer
 */
wickr_buffer_t * getDataFromBase64(const wickr_buffer_t * strBase64);

/**
 
 @ingroup data_conversion_utilities
 
 Convert data to hex format

 @param objData the buffer to convert
 @return a buffer containing a null-terminated hex string representation of objData
 */
wickr_buffer_t * getHexStringFromData(const wickr_buffer_t *objData);

/**
 
 @ingroup data_conversion_utilities
 
 Convert a hex string to data

 @param hexString a null terminated hex buffer
 @return a buffer containing the data represented by the hex buffer
 */
wickr_buffer_t * getDataFromHexString(const wickr_buffer_t *hexString);

#ifdef __cplusplus
}
#endif

#endif /* util_h */
