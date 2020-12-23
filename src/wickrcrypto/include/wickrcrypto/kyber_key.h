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

#ifndef kyber_key_h
#define kyber_key_h

#include "buffer.h"

typedef enum { KYBER_MODE_ID_1024 } wickr_kyber_mode_id_t;

struct wickr_kyber_mode {
    wickr_kyber_mode_id_t identifier;
    uint16_t public_key_len;
    uint16_t secret_key_len;
    uint16_t ciphertext_len;
    uint8_t shared_secret_len;
};

typedef struct wickr_kyber_mode wickr_kyber_mode_t;

const wickr_kyber_mode_t *wickr_kyber_mode_find(uint8_t mode_id);

static const wickr_kyber_mode_t KYBER_MODE_1024 = {
    .identifier = KYBER_MODE_ID_1024,
    .public_key_len = 1568,
    .secret_key_len = 3168,
    .ciphertext_len = 1568,
    .shared_secret_len = 32,
};

struct wickr_kyber_pub_key {
    wickr_kyber_mode_t mode;
    wickr_buffer_t *key_data;
};

typedef struct wickr_kyber_pub_key wickr_kyber_pub_key_t;

wickr_kyber_pub_key_t *wickr_kyber_pub_key_create(wickr_kyber_mode_t mode, wickr_buffer_t *key_data);

wickr_kyber_pub_key_t *wickr_kyber_pub_key_copy(const wickr_kyber_pub_key_t *key);

void wickr_kyber_pub_key_destroy(wickr_kyber_pub_key_t **key);

wickr_buffer_t *wickr_kyber_pub_key_serialize(const wickr_kyber_pub_key_t *key);

wickr_kyber_pub_key_t *wickr_kyber_pub_key_create_from_buffer(const wickr_buffer_t *buffer);

struct wickr_kyber_secret_key {
    wickr_kyber_mode_t mode;
    wickr_buffer_t *key_data;
};

typedef struct wickr_kyber_secret_key wickr_kyber_secret_key_t;

wickr_kyber_secret_key_t *wickr_kyber_secret_key_create(wickr_kyber_mode_t mode, wickr_buffer_t *key_data);

wickr_kyber_secret_key_t *wickr_kyber_secret_key_copy(const wickr_kyber_secret_key_t *key);

void wickr_kyber_secret_key_destroy(wickr_kyber_secret_key_t **key);

wickr_buffer_t *wickr_kyber_secret_key_serialize(const wickr_kyber_secret_key_t *key);

wickr_kyber_secret_key_t *wickr_kyber_secret_key_create_from_buffer(const wickr_buffer_t *buffer);

struct wickr_kyber_keypair {
    wickr_kyber_mode_t mode;
    wickr_kyber_pub_key_t *public_key;
    wickr_kyber_secret_key_t *secret_key;
};

typedef struct wickr_kyber_keypair wickr_kyber_keypair_t;

wickr_kyber_keypair_t *wickr_kyber_keypair_create(wickr_kyber_mode_t mode, wickr_kyber_pub_key_t *public_key, wickr_kyber_secret_key_t *secret_key);

wickr_kyber_keypair_t *wickr_kyber_keypair_copy(const wickr_kyber_keypair_t *keypair);

void wickr_kyber_keypair_destroy(wickr_kyber_keypair_t **keypair);


#endif /* kyber_key_h */
