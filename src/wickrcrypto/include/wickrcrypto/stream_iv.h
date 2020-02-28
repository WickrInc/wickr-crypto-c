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

#ifndef stream_iv_h
#define stream_iv_h

#include "crypto_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 @addtogroup wickr_stream_iv
 */

/**
 @ingroup wickr_stream_iv
 @struct wickr_stream_iv
 
 @brief A deterministic random IV generator using a 64 byte secure random seed and HMAC-SHA512
 
 On each call to generate, the IV generator will be called with HMAC(gen_count, seed)
 The gen count value is incremented by one each time the generate method is called
 
 @var wickr_stream_iv::engine
 crypto engine engine used to supply secure random bytes and HMAC functions
 @var wickr_stream_iv::seed
 a 64 byte secure random seed generated at creation of the stream_iv generator
 @var wickr_stream_iv::cipher
 the cipher that this engine is generating IV's for, this will determine the output length of the generated IV values
 @var wickr_stream_iv::gen_count
 an internal count value used as the HMAC value to deterministically generate unique IVs
 */
struct wickr_stream_iv {
    wickr_crypto_engine_t engine;
    wickr_buffer_t *seed;
    wickr_cipher_t cipher;
    uint64_t gen_count;
};

typedef struct wickr_stream_iv wickr_stream_iv_t;

/**
 @ingroup wickr_stream_iv
 
 Create a stream iv generator using an engine and cipher
 
 @param engine see 'wickr_stream_iv' property documentation
 @param cipher see 'wickr_stream_iv' property documentation
 
 @return a newly allocated stream iv generator
 */
wickr_stream_iv_t *wickr_stream_iv_create(const wickr_crypto_engine_t engine, wickr_cipher_t cipher);

/**
 
 @ingroup wickr_stream_iv
 
 Copy a stream iv generator
 
 @param iv the stream iv generator to copy
 @return a newly allocated stream iv generator set holding a deep copy of the properties of 'source'
 */
wickr_stream_iv_t *wickr_stream_iv_copy(const wickr_stream_iv_t *iv);

/**
 @ingroup wickr_stream_iv
 
 Destroy a stream iv generator
 
 @param iv a pointer to a stream iv generator to destroy. Will destroy the sub properties of '*iv' as well
 */
void wickr_stream_iv_destroy(wickr_stream_iv_t **iv);


/**
 
 @ingroup wickr_stream_iv
 
 Generate a new unique IV. gen_count will be increamented after calling this method, so subsequent calls will output unique values
 
 @param iv the stream iv generator to use for IV generation
 @return an IV of length 'cipher'->iv_len generated using HMAC(gen_count, seed)
 */
wickr_buffer_t *wickr_stream_iv_generate(wickr_stream_iv_t *iv);

#ifdef __cplusplus
}
#endif

#endif /* stream_iv_h */
