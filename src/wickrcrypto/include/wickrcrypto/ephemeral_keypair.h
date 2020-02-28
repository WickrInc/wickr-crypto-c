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

#ifndef ephemeral_keypair_h
#define ephemeral_keypair_h

#include <stdlib.h>
#include "ecdsa.h"
#include "eckey.h"
#include "crypto_engine.h"
#include "identity.h"

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 @addtogroup wickr_ephemeral_keypair
 */

/**
 
 @ingroup wickr_ephemeral_keypair
 
 @struct wickr_ephemeral_keypair
 
 @brief Represents a key pair used for message key exchanges within the Wickr Messaging Protocol
 
 Ephemeral kaypairs are identifiable by an integer value, and are signed by the node that generated the key.
 The additional properties outside of the key material itself provide clarity for both a message sender and receiver. 
 For the sender, the signature can provide authenticity of the public key material if the key pair is 
 retrived from a public place such as a server.
 The identifier can be passed as metadata by the sender so that the receiver has knowledge of which private key 
 from their active pool to use decode the message. 
 The goal of ephemeral keypairs is to provide an as constant as possible rotation / destruction cycle
 
 @var wickr_ephemeral_keypair::identifier
 identifier to associate with this key pair so it can be cataloged and later recalled when used
 @var wickr_ephemeral_keypair::ec_key
 underlying Elliptic curve key pair to use
 @var wickr_ephemeral_keypair::signature
 a signature of the 'ec_key' public component
 */
struct wickr_ephemeral_keypair {
    uint64_t identifier;
    wickr_ec_key_t *ec_key;
    wickr_ecdsa_result_t *signature;
};

typedef struct wickr_ephemeral_keypair wickr_ephemeral_keypair_t;

/**
 
 @ingroup wickr_ephemeral_keypair
 
 Create an Ephemeral Keypair from components

 @param identifier the numerical identifier of the keypair
 @param ec_key an Elliptic Curve public keypair
 @param signature a signature of the public key material in 'ec_key' by the owner of this key
 @return a newly allocated Ephemeral Keypair, owning the properties that were passed in
 */
wickr_ephemeral_keypair_t *wickr_ephemeral_keypair_create(uint64_t identifier, wickr_ec_key_t *ec_key, wickr_ecdsa_result_t *signature);

/**
 
 @ingroup wickr_ephemeral_keypair
 
 Copy an ephemeral keypair
 
 @param source the ephemeral key pair to copy
 @return a newly allocated ephemeral key pair holding a deep copy of the properties of 'source'
 */
wickr_ephemeral_keypair_t *wickr_ephemeral_keypair_copy(const wickr_ephemeral_keypair_t *source);

/**
 
 @ingroup wickr_ephemeral_keypair
 
 Generate a new ephemeral key pair given an owner identity.
 
 This method will use the 'default_curve' property of the crypto engine provided as the curve for the resulting keypair

 @param engine crypto engine supporting random Elliptic Curve generation, and ECDSA signatures
 @param identifier the identifier to assign to the generated output keypair
 @param identity the identity to sign the generated output key pair with
 @return a newly generated random Elliptic Curve key pair with identifier 'identifier' and a signature using the 'sig_key' property of the identity provided as the signing key
 */
wickr_ephemeral_keypair_t *wickr_ephemeral_keypair_generate_identity(const wickr_crypto_engine_t *engine, uint64_t identifier, const wickr_identity_t *identity);

/**
 
 @ingroup wickr_ephemeral_keypair
 
 Verify the owner of an ephemeral key pair is a particular identity

 @param keypair the key pair to verify the owner of
 @param engine a crypto engine that supports verifying signatures generated with the curve associated with the 'sig_key' property of owner
 @param owner the proposed owner of this keypair
 @return true if the signature of key pair can be verified with the sig_key of owner
 */
bool wickr_ephemeral_keypair_verify_owner(const wickr_ephemeral_keypair_t *keypair, const wickr_crypto_engine_t *engine, const wickr_identity_t *owner);


/**
 @ingroup wickr_ephemeral_keypair
 
 Destroy the private components of the keypair

 @param keypair the key pair to make public
 */
void wickr_ephemeral_keypair_make_public(const wickr_ephemeral_keypair_t *keypair);
    
/**
 
 @ingroup wickr_ephemeral_keypair
 
 Serialize an ephemeral keypair to bytes
 
 @param keypair the ephemeral keypair to serialize
 @return a buffer containing a serialized representation of 'keypair' or null if serialization fails
 */
wickr_buffer_t *wickr_ephemeral_keypair_serialize(const wickr_ephemeral_keypair_t *keypair);

/**
 
 @ingroup wickr_ephemeral_keypair
 
 Create an ephemeral keypair from a buffer that was created with 'wickr_ephemeral_keypair_serialize'
 
 @param buffer the buffer that contains a serialized representation of an identity chain
 @param engine the crypto engine to use to import the key components of the ephemeral keypair
 @return deserialized ephemeral keypair or null if the deserialization fails
 */
wickr_ephemeral_keypair_t *wickr_ephemeral_keypair_create_from_buffer(const wickr_buffer_t *buffer, const wickr_crypto_engine_t *engine);

/**
 
 @ingroup wickr_ephemeral_keypair
 
 Destroy an ephemeral keypair
 
 @param keypair a pointer to the key pair to destroy. All properties of '*keypair' will also be destroyed
 */
void wickr_ephemeral_keypair_destroy(wickr_ephemeral_keypair_t **keypair);

#ifdef __cplusplus
}
#endif

#endif /* ephemeral_keypair_h */
