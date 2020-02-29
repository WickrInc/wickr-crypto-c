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

#ifndef devinfo_h
#define devinfo_h

#include <stdlib.h>
#include "buffer.h"
#include "crypto_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 @addtogroup wickr_dev_info
 */
    
/**
 
 @ingroup wickr_dev_info
 
 @struct wickr_dev_info
 
 @brief Device Information used to make a uniquely identifying set of data for each context running the Wickr Protocol.
 
 These identifiers are not required to be absolutely unique from a security perspective, but having a good amount of entropy in them is a nice property to attempt to achieve.
 
 @var wickr_dev_info::dev_salt
 a random salt used in generating 'msg_proto_id' and 'srv_comm_id'. Ideally, this salt value is generated
 and stored on the device in a way it is quickly retrived. It does not need to be transmitted off the device, 
 as it simply provides some entropy to Wickr specific identifier generation.
 @var wickr_dev_info::system_salt
 a salt that is optimally bound to a hardware context of the device the library is executing on. On systems where getting hardware specific values are not available, this salt can also be randomly generated and stored on the device. The system salt is used to salt your device storage key, and thus binding to a hardware value that is not recorded on disk could increase security of your local storage in some scenarios.
 @var wickr_dev_info::msg_proto_id
 messaging protocol identifier shared with devices transmitting data to you. Used as context within key exchanges where a context using the associated 'dev_salt' and 'system_salt' is the recipient
 @var wickr_dev_info::srv_comm_id 
 server communication identifier transmitted to the server and used for salting operations outside of the messaging component of Wickr, such as communicating with the Wickr Server API.
 */
struct wickr_dev_info {
    wickr_buffer_t *dev_salt;
    wickr_buffer_t *system_salt;
    wickr_buffer_t *msg_proto_id;
    wickr_buffer_t *srv_comm_id;
};

typedef struct wickr_dev_info wickr_dev_info_t;

/**
 
 @ingroup wickr_dev_info
 
 Create a device info set from components

 @param dev_salt random salt, see property declaration of 'wickr_dev_info'
 @param system_salt system bound salt, see property declaration of 'wickr_dev_info'
 @param msg_proto_id messaging protocol identifier, see property declaration of 'wickr_dev_info'
 @param srv_comm_id server communication identifier, see property declaration of 'wickr_dev_info'
 @return a newly allocated device info set owning the properties passed in
 */
wickr_dev_info_t *wickr_dev_info_create(wickr_buffer_t *dev_salt, wickr_buffer_t *system_salt, wickr_buffer_t *msg_proto_id, wickr_buffer_t *srv_comm_id);

/**
 
 @ingroup wickr_dev_info
 
 Generate a new randomized device info set from a system identifier. This function uses crypto engine 'crypto' to generate a random 'dev_salt' value, and then calls 'wickr_dev_info_derive' with the resulting random 'dev_salt', crypto engine, and provided 'system_id' values

 @param crypto a crypto engine that supports a PRNG, SHA512, and SHA256 functions
 @param system_id a buffer representing data optimally unique to your system. It is used as the basis of generating the 'system_salt' property. See property declaration of 'system_salt' in 'wickr_dev_info'
 @return the output of 'wickr_dev_info_derive' with a randomly generated 'dev_salt'
 */
wickr_dev_info_t *wickr_dev_info_create_new(const wickr_crypto_engine_t *crypto, const wickr_buffer_t *system_id);


/**
 
 @ingroup wickr_dev_info
 
 Derive a set of salt values and identifiers. Creates 'system_salt' by taking a SHA256 hash of the system_id. Creates 'msg_proto_id', and 'srv_comm_id' properties by taking a SHA512 of of 'system_id' using 'dev_salt' as a salt, and then splits by using the first 32 bytes as 'msg_proto_id', and the last 32 bytes as 'srv_comm_id'

 @param crypto a crypto engine that supports a PRNG, SHA512, and SHA256 functions
 @param dev_salt a randomly generated device salt to be used as input for generating identifiers
 @param system_id a system level identifier to be used as input to generating a 'system_salt' value, as well as identifiers
 @return a newly allocated device info set owning the reference to dev_salt, and with newly generated values for 'system_salt', 'msg_proto_id', and 'srv_comm_id'. NULL if derivation fails
 */
wickr_dev_info_t *wickr_dev_info_derive(const wickr_crypto_engine_t *crypto, wickr_buffer_t *dev_salt, const wickr_buffer_t *system_id);

/**
 
 @ingroup wickr_dev_info
 
 Copy a device info set

 @param info the source info to copy
 @return a newly allocated device info set containing deep copies of the properties of 'info'
 */
wickr_dev_info_t *wickr_dev_info_copy(const wickr_dev_info_t *info);

/**
 
 @ingroup wickr_dev_info
 
 Destroy a device info set

 @param info a pointer to a device info set to destroy. Properties of '*info' will also be destroyed
 */
void wickr_dev_info_destroy(wickr_dev_info_t **info);

#ifdef __cplusplus
}
#endif

#endif /* devinfo_h */
