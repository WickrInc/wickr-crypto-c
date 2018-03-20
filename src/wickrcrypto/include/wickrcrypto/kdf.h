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

#ifndef kdf_h
#define kdf_h

#include "buffer.h"
#include "digest.h"

#ifdef __cplusplus
extern "C" {
#endif
    

/**
 @addtogroup wickr_kdf wickr_kdf
 */

/**
 
 @ingroup wickr_kdf
 
 KDF Algorithm ID
 
 Define the base algorithm a particular kdf function uses. Scrypt, Bcrypt, and HKDF are currently supported.
 The preferred default is to use scrypt, with a minimum of n = 2^17
 
 */
typedef enum { KDF_BCRYPT, KDF_SCRYPT, KDF_HMAC_SHA2 } wickr_kdf_algo_id;

typedef enum { KDF_ID_SCRYPT_17 = 1, KDF_ID_SCRYPT_18, KDF_ID_SCRYPT_19, KDF_ID_SCRYPT_20, KDF_ID_BCRYPT_15, KDF_ID_HKDF_SHA256, KDF_ID_HKDF_SHA384, KDF_ID_HKDF_SHA512 } wickr_kdf_id;

/**
 
 @ingroup wickr_kdf
 @struct wickr_kdf_algo
 
 @brief Metadata associated with a particular KDF function
 
 The algorithm is defined by a base algorithm, as well as a specific sub-algorithm associated with it. As an example KDF_SCRYPT as the algo_id with KDF_ID_SCRYPT_17 as the kdf_id.
 
 @var wickr_kdf_algo::algo_id
 the base algorithm used by this kdf function
 @var wickr_kdf_algo::kdf_id
 the specific sub-algorithm used by this kdf function
 @var wickr_kdf_algo::salt_size
 the number of bytes this algorithm expects for a salt value
 @var wickr_kdf_algo::output_size
 the number of bytes this algorithm will produce as an ouput
 @var wickr_kdf_algo::cost
 a number representing the difficulty of calculating the KDF function as either CPU power, Memory use, or a combination of both
 */
struct wickr_kdf_algo {
    wickr_kdf_algo_id algo_id;
    wickr_kdf_id kdf_id;
    uint8_t salt_size;
    uint8_t output_size;
    uint32_t cost;
};

typedef struct wickr_kdf_algo wickr_kdf_algo_t;

/**
 
 @ingroup wickr_kdf
 
 Scrypt Cost
 
 In order to conform to MCF format, scrypt provides a method of compressing its parameters 
 into a single uint32 value. This calculation is leveraged here for the simplicity of having a single value
 represent N, r, and p values
 
 */
#define SCRYPT_2_17_COST 1116161
#define SCRYPT_2_18_COST 1181697
#define SCRYPT_2_19_COST 1247233
#define SCRYPT_2_20_COST 1312769

/* Truncate the output size of scrypt to give us 32byte values we can use as a cipher key */
#define SCRYPT_OUTPUT_SIZE 32

#define SCRYPT_SALT_SIZE 16
#define BCRYPT_15_COST 15
#define BCRYPT_HASH_SIZE 64

/* Passed without the $2y$15$. It will be injected internally */
#define BCRYPT_SALT_SIZE 22

/* SCRYPT Mode Definitions */
static const wickr_kdf_algo_t KDF_SCRYPT_2_17 = { KDF_SCRYPT, KDF_ID_SCRYPT_17, SCRYPT_SALT_SIZE, SCRYPT_OUTPUT_SIZE, SCRYPT_2_17_COST };
static const wickr_kdf_algo_t KDF_SCRYPT_2_18 = { KDF_SCRYPT, KDF_ID_SCRYPT_18, SCRYPT_SALT_SIZE, SCRYPT_OUTPUT_SIZE, SCRYPT_2_18_COST };
static const wickr_kdf_algo_t KDF_SCRYPT_2_19 = { KDF_SCRYPT, KDF_ID_SCRYPT_19, SCRYPT_SALT_SIZE, SCRYPT_OUTPUT_SIZE, SCRYPT_2_19_COST };
static const wickr_kdf_algo_t KDF_SCRYPT_2_20 = { KDF_SCRYPT, KDF_ID_SCRYPT_20, SCRYPT_SALT_SIZE, SCRYPT_OUTPUT_SIZE, SCRYPT_2_20_COST };

/* BCRYPT Mode Definitions */
static const wickr_kdf_algo_t KDF_BCRYPT_15 = { KDF_BCRYPT, KDF_ID_BCRYPT_15, BCRYPT_SALT_SIZE, BCRYPT_HASH_SIZE, BCRYPT_15_COST };
    
/* HKDF Mode Definitions */
static const wickr_kdf_algo_t KDF_HKDF_SHA256 = { KDF_HMAC_SHA2, KDF_ID_HKDF_SHA256, SHA256_DIGEST_SIZE, SHA256_DIGEST_SIZE, 0 };
static const wickr_kdf_algo_t KDF_HKDF_SHA384 = { KDF_HMAC_SHA2, KDF_ID_HKDF_SHA384, SHA384_DIGEST_SIZE, SHA384_DIGEST_SIZE, 0 };
static const wickr_kdf_algo_t KDF_HKDF_SHA512 = { KDF_HMAC_SHA2, KDF_ID_HKDF_SHA512, SHA512_DIGEST_SIZE, SHA512_DIGEST_SIZE, 0 };

/**
 
 @ingroup wickr_kdf
 @struct wickr_kdf_meta
 
 @brief Represents the information the KDF function will need along with it's input to derive a particular output
 
 @var wickr_kdf_meta::algo
 serialized algorithm identifier to help define the set of parameters for the KDF as an integer
 @var wickr_kdf_meta::salt
 value that should be / was used as an input to the KDF function
 @var wickr_kdf_meta::info
 context information that can be used as part of the KDF function. INFO varies from SALT as it is not intended to be random, and instead holds contextual information. May be NULL if no context information is provided
 */
struct wickr_kdf_meta {
    wickr_kdf_algo_t algo;
    wickr_buffer_t *salt;
    wickr_buffer_t *info;
};

typedef struct wickr_kdf_meta wickr_kdf_meta_t;

/**
 
 @ingroup wickr_kdf
 @struct wickr_kdf_result
 
 @brief Represents the result of a KDF function execution
 
 @var wickr_kdf_result::meta
 metadata describing the type of algorithm used, it's parameters, and the salt value that was used to produce the result. See 'wickr_kdf_meta' documentation.
 @var wickr_kdf_result::hash 
 the output of the KDF function as a buffer of size 'meta->algo.output_size'
 */
struct wickr_kdf_result {
    wickr_kdf_meta_t *meta;
    wickr_buffer_t *hash;
};

typedef struct wickr_kdf_result wickr_kdf_result_t;

/**
 
 @ingroup wickr_kdf
 
 Create a KDF Metadata set from components

 @param algo see 'wickr_kdf_meta' property documentation
 @param salt see 'wickr_kdf_meta' property documentation
 @param info see 'wickr_kdf_meta' property documentation
 @return a newly allocated KDF Metadata set, owning the properties that were passed in
 */
wickr_kdf_meta_t *wickr_kdf_meta_create(wickr_kdf_algo_t algo, wickr_buffer_t *salt, wickr_buffer_t *info);

/**
 
 @ingroup wickr_kdf
 
 Determine the size of serialized metadata given a serialized KDF Metadata buffer
 
 This function is useful for determining the number of bytes within a larger buffer are part of the KDF metadata
 
 @param buffer a buffer beginning with bytes generated from 'wickr_kdf_meta_serialize'
 @return the number of bytes consumed by a piece of serialized metadata at the beginning of buffer 'buffer'. 0 if the buffer does not start with a valid piece of serialized metadata
 */
uint8_t wickr_kdf_meta_size_with_buffer(const wickr_buffer_t *buffer);

/**
 
 @ingroup wickr_kdf
 
 Serialize a KDF Metadata set

 @param meta metadata set to serialize to a buffer
 @return a buffer containing serialized bytes from 'meta' in the following format:
    | ALGO_ID | SALT |
 */
wickr_buffer_t *wickr_kdf_meta_serialize(const wickr_kdf_meta_t *meta);

/**
 
 @ingroup wickr_kdf
 
 Create a KDF Metadata set from a buffer created by 'wickr_kdf_meta_serialize'

 @param buffer a buffer containing a bytes created by 'wickr_kdf_meta_serialize'
 @return a newly allocated KDF Metadata set. NULL if parsing fails because buffer does not contain valid bytes
 */
wickr_kdf_meta_t *wickr_kdf_meta_create_with_buffer(const wickr_buffer_t *buffer);

/**
 
 @ingroup wickr_kdf
 
 Copy a KDF Metadata set
 
 @param source the metadata set to copy
 @return a newly allocated metadata set holding a deep copy of the properties of 'source'
 */
wickr_kdf_meta_t *wickr_kdf_meta_copy(const wickr_kdf_meta_t *source);

/**
 
 @ingroup wickr_kdf
 
 Destroy a KDF Metadata set
 
 @param meta a pointer to the metadata set to destroy. All properties of '*meta' will also be destroyed
 */
void wickr_kdf_meta_destroy(wickr_kdf_meta_t **meta);

/**
 
 @ingroup wickr_kdf
 
 Create a KDF Result from components

 @param meta see 'wickr_kdf_result' property documentation
 @param hash see 'wickr_kdf_result' property documentation
 @return a newly allocated KDF result, owning the properties that were passed in
 */
wickr_kdf_result_t *wickr_kdf_result_create(wickr_kdf_meta_t *meta, wickr_buffer_t *hash);

/**
 
 @ingroup wickr_kdf
 
 Copy a KDF result
 
 @param source the metadata set to copy
 @return a newly allocated kdf result holding a deep copy of the properties of 'source'
 */
wickr_kdf_result_t *wickr_kdf_result_copy(const wickr_kdf_result_t *source);

/**
 
 @ingroup wickr_kdf
 
 Destroy a KDF result
 
 @param result a pointer to the result to destroy. All properties of '*result' will also be destroyed
 */
void wickr_kdf_result_destroy(wickr_kdf_result_t **result);

/**
 
 @ingroup wickr_kdf
 
 Execute a KDF function given an input buffer

 @param algo the algorithm info to use for execution of the KDF
 @param passphrase bytes to use as input to the KDF function. There are no restrictions for the content of the buffer
 @return the output of the KDF function, including the generated random salt that was used for the computation
 */
wickr_kdf_result_t *wickr_perform_kdf(wickr_kdf_algo_t algo, const wickr_buffer_t *passphrase);

/**
 
 @ingroup wickr_kdf
 
 Execute a KDF function given an input buffer and specified parameters
 
 @param existing_meta the parameters to use for execution, including a specific salt
 @param passphrase bytes to use as input to the KDF function. There are no restrictions for the content of the buffer
 @return the output of the KDF function, including the generated random salt that was used for the computation
 */
wickr_kdf_result_t *wickr_perform_kdf_meta(const wickr_kdf_meta_t *existing_meta, const wickr_buffer_t *passphrase);
 
/**
 
 @ingroup wickr_kdf
 
 Find the HKDF wickr_kdf_algo that matches a specific digest
 
 @param digest the digest to search for
 @return HKDF wickr_kdf_algo that uses 'digest'
 */
const wickr_kdf_algo_t *wickr_hkdf_algo_for_digest(wickr_digest_t digest);

#ifdef __cplusplus
}
#endif

#endif /* kdf_h */
