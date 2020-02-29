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

#ifndef packet_meta_h
#define packet_meta_h

#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 @addtogroup wickr_packet_meta wickr_packet_meta
 */

/**
 @ingroup wickr_packet_meta
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
 @ingroup wickr_packet_meta
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
 
 @ingroup wickr_packet_meta
 
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
 
 @ingroup wickr_packet_meta
 
 Copy an packet metadata set
 
 @param source the packet metadata set to copy
 @return a newly packet metadata set holding a deep copy of the properties of 'source'
 */
wickr_packet_meta_t *wickr_packet_meta_copy(const wickr_packet_meta_t *source);

/**
 
 @ingroup wickr_packet_meta
 
 Destroy packet metadata set
 
 @param meta a pointer to the result to destroy. All properties of '*meta' will also be destroyed
 */
void wickr_packet_meta_destroy(wickr_packet_meta_t **meta);
    
#ifdef __cplusplus
}
#endif

#endif /* packet_meta_h */
