/**
 * @file p25519/f_field.h
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Field-specific code for 2^255 - 19.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */

#ifndef __P25519_F_FIELD_H__
#define __P25519_F_FIELD_H__ 1

#include "constant_time.h"
#include <string.h>
#include <assert.h>

#include "word.h"

#define __DECAF_25519_GF_DEFINED__ 1
#define NLIMBS (40/sizeof(word_t))
#define X_SER_BYTES 32
#define SER_BYTES 32
typedef struct gf_25519_s {
    word_t limb[NLIMBS];
} __attribute__((aligned(32))) gf_25519_s, gf_25519_t[1];

#define GF_LIT_LIMB_BITS  51
#define GF_BITS           255
#define ZERO              gf_25519_ZERO
#define ONE               gf_25519_ONE
#define MODULUS           gf_25519_MODULUS
#define gf                gf_25519_t
#define gf_s              gf_25519_s
#define gf_eq             gf_25519_eq
#define gf_hibit          gf_25519_hibit
#define gf_lobit          gf_25519_lobit
#define gf_copy           gf_25519_copy
#define gf_add            gf_25519_add
#define gf_sub            gf_25519_sub
#define gf_add_RAW        gf_25519_add_RAW
#define gf_sub_RAW        gf_25519_sub_RAW
#define gf_bias           gf_25519_bias
#define gf_weak_reduce    gf_25519_weak_reduce
#define gf_strong_reduce  gf_25519_strong_reduce
#define gf_mul            gf_25519_mul
#define gf_sqr            gf_25519_sqr
#define gf_mulw_unsigned  gf_25519_mulw_unsigned
#define gf_isr            gf_25519_isr
#define gf_serialize      gf_25519_serialize
#define gf_deserialize    gf_25519_deserialize

/* RFC 7748 support */
#define X_PUBLIC_BYTES  X_SER_BYTES
#define X_PRIVATE_BYTES X_PUBLIC_BYTES
#define X_PRIVATE_BITS  255

#define SQRT_MINUS_ONE    P25519_SQRT_MINUS_ONE /* might not be defined */

#define INLINE_UNUSED __inline__ __attribute__((unused,always_inline))

#ifdef __cplusplus
extern "C" {
#endif

/* Defined below in f_impl.h */
static INLINE_UNUSED void gf_copy (gf out, const gf a) { *out = *a; }
static INLINE_UNUSED void gf_add_RAW (gf out, const gf a, const gf b);
static INLINE_UNUSED void gf_sub_RAW (gf out, const gf a, const gf b);
static INLINE_UNUSED void gf_bias (gf inout, int amount);
static INLINE_UNUSED void gf_weak_reduce (gf inout);

void gf_strong_reduce (gf inout);   
void gf_add (gf out, const gf a, const gf b);
void gf_sub (gf out, const gf a, const gf b);
void gf_mul (gf_s *__restrict__ out, const gf a, const gf b);
void gf_mulw_unsigned (gf_s *__restrict__ out, const gf a, uint32_t b);
void gf_sqr (gf_s *__restrict__ out, const gf a);
mask_t gf_isr(gf a, const gf x); /** a^2 x = 1, QNR, or 0 if x=0.  Return true if successful */
mask_t gf_eq (const gf x, const gf y);
mask_t gf_lobit (const gf x);
mask_t gf_hibit (const gf x);

void gf_serialize (uint8_t *serial, const gf x,int with_highbit);
mask_t gf_deserialize (gf x, const uint8_t serial[SER_BYTES],int with_hibit,uint8_t hi_nmask);


#ifdef __cplusplus
} /* extern "C" */
#endif

#include "f_impl.h" /* Bring in the inline implementations */

#define P_MOD_8 5
#if P_MOD_8 == 5
    extern const gf SQRT_MINUS_ONE;
#endif

#ifndef LIMBPERM
  #define LIMBPERM(i) (i)
#endif
#define LIMB_MASK(i) (((1ull)<<LIMB_PLACE_VALUE(i))-1)

static const gf ZERO = {{{0}}}, ONE = {{{ [LIMBPERM(0)] = 1 }}};

#endif /* __P25519_F_FIELD_H__ */
