/** @brief Field-specific code for $(gf_desc). */

#include "constant_time.h"
#include <string.h>
#include <assert.h>

#include "word.h"

#define __DECAF_$(gf_shortname)_GF_DEFINED__ 1
#define NLIMBS ($(gf_impl_bits//8)/sizeof(word_t))
#define X_SER_BYTES $(((gf_bits-1)//8 + 1))
#define SER_BYTES $(((gf_bits-2)//8 + 1))
typedef struct gf_$(gf_shortname)_s {
    word_t limb[NLIMBS];
} __attribute__((aligned(32))) gf_$(gf_shortname)_s, gf_$(gf_shortname)_t[1];

#define GF_LIT_LIMB_BITS  $(gf_lit_limb_bits)
#define GF_BITS           $(gf_bits)
#define ZERO              gf_$(gf_shortname)_ZERO
#define ONE               gf_$(gf_shortname)_ONE
#define MODULUS           gf_$(gf_shortname)_MODULUS
#define gf                gf_$(gf_shortname)_t
#define gf_s              gf_$(gf_shortname)_s
#define gf_eq             gf_$(gf_shortname)_eq
#define gf_hibit          gf_$(gf_shortname)_hibit
#define gf_lobit          gf_$(gf_shortname)_lobit
#define gf_copy           gf_$(gf_shortname)_copy
#define gf_add            gf_$(gf_shortname)_add
#define gf_sub            gf_$(gf_shortname)_sub
#define gf_add_RAW        gf_$(gf_shortname)_add_RAW
#define gf_sub_RAW        gf_$(gf_shortname)_sub_RAW
#define gf_bias           gf_$(gf_shortname)_bias
#define gf_weak_reduce    gf_$(gf_shortname)_weak_reduce
#define gf_strong_reduce  gf_$(gf_shortname)_strong_reduce
#define gf_mul            gf_$(gf_shortname)_mul
#define gf_sqr            gf_$(gf_shortname)_sqr
#define gf_mulw_unsigned  gf_$(gf_shortname)_mulw_unsigned
#define gf_isr            gf_$(gf_shortname)_isr
#define gf_serialize      gf_$(gf_shortname)_serialize
#define gf_deserialize    gf_$(gf_shortname)_deserialize

/* RFC 7748 support */
#define X_PUBLIC_BYTES  X_SER_BYTES
#define X_PRIVATE_BYTES X_PUBLIC_BYTES
#define X_PRIVATE_BITS  $(gf_bits)

#define SQRT_MINUS_ONE    P$(gf_shortname)_SQRT_MINUS_ONE /* might not be defined */

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

#define P_MOD_8 $(modulus % 8)
#if P_MOD_8 == 5
    extern const gf SQRT_MINUS_ONE;
#endif

#ifndef LIMBPERM
  #define LIMBPERM(i) (i)
#endif
#define LIMB_MASK(i) (((1ull)<<LIMB_PLACE_VALUE(i))-1)

static const gf ZERO = {{{0}}}, ONE = {{{ [LIMBPERM(0)] = 1 }}};
