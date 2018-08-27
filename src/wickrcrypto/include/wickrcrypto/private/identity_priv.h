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

#ifndef identity_priv_h
#define identity_priv_h

#include "identity.h"
#include "stream.pb-c.h"

void wickr_identity_proto_free(Wickr__Proto__Identity *proto);
void wickr_identity_chain_proto_free(Wickr__Proto__IdentityChain *proto);

Wickr__Proto__Identity *wickr_identity_to_proto(const wickr_identity_t *identity);

Wickr__Proto__Identity *wickr_identity_to_private_proto(const wickr_identity_t *identity);

wickr_identity_t *wickr_identity_create_from_proto(const Wickr__Proto__Identity *proto_identity,
                                                   const wickr_crypto_engine_t *engine);


wickr_identity_chain_t *wickr_identity_chain_create_from_proto(const Wickr__Proto__IdentityChain *proto_chain,
                                                          const wickr_crypto_engine_t *engine);

Wickr__Proto__IdentityChain *wickr_identity_chain_to_proto(const wickr_identity_chain_t *chain);

Wickr__Proto__IdentityChain *wickr_identity_chain_to_private_proto(const wickr_identity_chain_t *chain);

#endif /* identity_priv_h */
