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

#ifndef transport_root_key_priv_h
#define transport_root_key_priv_h

#include "stream.pb-c.h"
#include "transport_root_key.h"

Wickr__Proto__TransportRootKey *wickr_transport_root_key_to_proto(const wickr_transport_root_key_t *root_key);
wickr_transport_root_key_t *wickr_transport_root_key_from_proto(const Wickr__Proto__TransportRootKey *root_key_proto);
void wickr_transport_root_key_proto_free(Wickr__Proto__TransportRootKey *root_key_proto);

#endif /* transport_root_key_priv_h */
