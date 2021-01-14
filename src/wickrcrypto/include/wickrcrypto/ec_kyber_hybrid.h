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

#ifndef ec_kyber_hybrid_h
#define ec_kyber_hybrid_h

#include "eckey.h"
#include "kyber_key.h"
#include "crypto_engine.h"

#define HYBRID_IDENTIFIER_SIZE (sizeof(uint8_t))
#define HYBRID_KEY_HEADER_SIZE (HYBRID_IDENTIFIER_SIZE + sizeof(uint8_t))

static const wickr_ec_curve_t EC_CURVE_P521_KYBER_HYBRID = { EC_CURVE_ID_P521_KYBER1024_HYBRID, 0, 0 };

wickr_ec_key_t *wickr_ec_key_hybrid_create_with_components(wickr_ec_key_t *ec_key,
                                                           wickr_kyber_keypair_t *kyber_key);

wickr_ec_key_t *wickr_ec_key_hybrid_get_ec_keypair(const wickr_ec_key_t *hbrd_key, wickr_ec_key_import_func import_func);


wickr_kyber_pub_key_t *wickr_ec_key_hybrid_get_kyber_pub(const wickr_ec_key_t *hbrd_key);

wickr_kyber_secret_key_t *wickr_ec_key_hybrid_get_kyber_pri(const wickr_ec_key_t *hbrd_key);

#endif /* ec_kyber_hybrid_h */
