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

#ifndef stream_info_h
#define stream_info_h

#include "stream_cipher.h"

struct wickr_stream_info {
    wickr_stream_key_t *key;
    wickr_buffer_t *user_data;
};

typedef struct wickr_stream_info wickr_stream_info_t;

wickr_stream_info_t *wickr_stream_info_create(wickr_stream_key_t *key, wickr_buffer_t *user_data);
wickr_stream_info_t *wickr_stream_info_copy(const wickr_stream_info_t *info);
void wickr_stream_info_destroy(wickr_stream_info_t **info);

wickr_buffer_t *wickr_stream_info_serialize(const wickr_stream_info_t *info);
wickr_stream_info_t *wickr_stream_info_create_from_buffer(const wickr_buffer_t *buffer);

#endif /* stream_info_h */
