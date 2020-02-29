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

#ifndef ephemeral_keypair_priv_h
#define ephemeral_keypair_priv_h

#include "ephemeral_keypair.h"
#include "ephemeral_keypair.pb-c.h"

void wickr_ephemeral_keypair_proto_free(Wickr__Proto__EphemeralKeypair *proto_keypair);

Wickr__Proto__EphemeralKeypair *wickr_ephemeral_keypair_to_proto(const wickr_ephemeral_keypair_t *keypair);

wickr_ephemeral_keypair_t *wickr_ephemeral_keypair_create_from_proto(const Wickr__Proto__EphemeralKeypair *proto,
                                                                     const wickr_crypto_engine_t *engine);

#endif /* ephemeral_keypair_priv_h */
