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

#ifndef shared_secret_h
#define shared_secret_h

#include "buffer.h"

struct wickr_shared_secret {
    wickr_buffer_t *secret;
    wickr_buffer_t *ctx;
};

typedef struct wickr_shared_secret wickr_shared_secret_t;

wickr_shared_secret_t *wickr_shared_secret_create(wickr_buffer_t *secret, wickr_buffer_t *ctx);
wickr_shared_secret_t *wickr_shared_secret_copy(const wickr_shared_secret_t *secret);
void wickr_shared_secret_destroy(wickr_shared_secret_t **secret);

wickr_shared_secret_t *wickr_shared_secret_merge(const wickr_shared_secret_t *secret_a, const wickr_shared_secret_t *secret_b);

#endif /* shared_secret_h */
