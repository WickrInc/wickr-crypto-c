/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "f_field.h"

typedef struct {
  uint64x3_t lo, hi, hier;
} nonad_t;

static inline __uint128_t widemulu(uint64_t a, uint64_t b) {
    return ((__uint128_t)(a)) * b;
}

static inline __int128_t widemuls(int64_t a, int64_t b) {
    return ((__int128_t)(a)) * b;
}
 
/* This is a trick to prevent terrible register allocation by hiding things from clang's optimizer */
static inline uint64_t opacify(uint64_t x) {
    __asm__ volatile("" : "+r"(x));
    return x;
}

/* These used to be hexads, leading to 10% better performance, but there were overflow issues */
static inline void nonad_mul (
  nonad_t *hex,
  const uint64_t *a,
  const uint64_t *b
) {
    __uint128_t xu, xv, xw;

    uint64_t tmp = opacify(a[2]);
    xw = widemulu(tmp, b[0]);
    tmp <<= 1;
    xu = widemulu(tmp, b[1]);
    xv = widemulu(tmp, b[2]);

    tmp = opacify(a[1]);
    xw += widemulu(tmp, b[1]);
    xv += widemulu(tmp, b[0]);
    tmp <<= 1;
    xu += widemulu(tmp, b[2]);

    tmp = opacify(a[0]);
    xu += widemulu(tmp, b[0]);
    xv += widemulu(tmp, b[1]);
    xw += widemulu(tmp, b[2]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };

    hex->hier = hi>>52;
    hex->hi = (hi<<12)>>6 | lo>>58;
    hex->lo = lo & mask58;
}

static inline void hexad_mul_signed (
  nonad_t *hex,
  const int64_t *a,
  const int64_t *b
) {
    __int128_t xu, xv, xw;

    int64_t tmp = opacify(a[2]);
    xw = widemuls(tmp, b[0]);
    tmp <<= 1;
    xu = widemuls(tmp, b[1]);
    xv = widemuls(tmp, b[2]);

    tmp = opacify(a[1]);
    xw += widemuls(tmp, b[1]);
    xv += widemuls(tmp, b[0]);
    tmp <<= 1;
    xu += widemuls(tmp, b[2]);

    tmp = opacify(a[0]);
    xu += widemuls(tmp, b[0]);
    xv += widemuls(tmp, b[1]);
    xw += widemuls(tmp, b[2]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };

    /*
    hex->hier = (uint64x4_t)((int64x4_t)hi>>52);
    hex->hi = (hi<<12)>>6 | lo>>58;
    hex->lo = lo & mask58;
    */
    
    hex->hi = hi<<6 | lo>>58;
    hex->lo = lo & mask58;
}

static inline void nonad_sqr (
  nonad_t *hex,
  const uint64_t *a
) {
    __uint128_t xu, xv, xw;

    int64_t tmp = a[2];
    tmp <<= 1;
    xw = widemulu(tmp, a[0]);
    xv = widemulu(tmp, a[2]);
    tmp <<= 1;
    xu = widemulu(tmp, a[1]);

    tmp = a[1];
    xw += widemulu(tmp, a[1]);
    tmp <<= 1;
    xv += widemulu(tmp, a[0]);

    tmp = a[0];
    xu += widemulu(tmp, a[0]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };

    hex->hier = hi>>52;
    hex->hi = (hi<<12)>>6 | lo>>58;
    hex->lo = lo & mask58;
}

static inline void hexad_sqr_signed (
  nonad_t *hex,
  const int64_t *a
) {
    __uint128_t xu, xv, xw;

    int64_t tmp = a[2];
    tmp <<= 1;
    xw = widemuls(tmp, a[0]);
    xv = widemuls(tmp, a[2]);
    tmp <<= 1;
    xu = widemuls(tmp, a[1]);

    tmp = a[1];
    xw += widemuls(tmp, a[1]);
    tmp <<= 1;
    xv += widemuls(tmp, a[0]);

    tmp = a[0];
    xu += widemuls(tmp, a[0]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };


    /*
    hex->hier = (uint64x4_t)((int64x4_t)hi>>52);
    hex->hi = (hi<<12)>>6 | lo>>58;
    hex->lo = lo & mask58;
    */
    
    hex->hi = hi<<6 | lo>>58;
    hex->lo = lo & mask58;
}



void gf_mul (gf *__restrict__ cs, const gf *as, const gf *bs) {
    int i;
    
#if 0
    assert(as->limb[3] == 0 && as->limb[7] == 0 && as->limb[11] == 0);
    assert(bs->limb[3] == 0 && bs->limb[7] == 0 && bs->limb[11] == 0);
    for (i=0; i<12; i++) {
        assert(as->limb[i] < 5ull<<57);
        assert(bs->limb[i] < 5ull<<57);
    }
#endif
    
    /* Bounds on the hexads and nonads.
     *
     * Limbs < 2<<58 + ep.
     * Nonad mul < 1<<58, 1<<58, tiny
     * -> t0 < (3,2,2)<<58 + tiny
     * t1,t2 < 2<<58 + tiny
     *   * w < (4,2,2)
     * Hexad mul < +- (5,4,3) * 4<<116 -> 2^58 lo, +- (5,4,3) * 4<<58+ep
     * TimesW < (2,1,1)<<58, (6,5,4)*4<<58 + ep
    
     * ot2 = t0 + timesW(t2 + t1 - acdf.hi - bcef.lo);
         == (3,2,2) + (4,2,2) + (4,2,2) +- (6,5,4)*4 - (1) << 58
         in (-25, +35) << 58

    uint64x3_t ot0 = t0 + timesW(t2 + t1 - acdf.hi - bcef.lo);
    uint64x3_t ot1 = t0 + t1 - abde.lo + timesW(t2 - bcef.hi);
    uint64x3_t ot2 = t0 + t1 + t2 - abde.hi - acdf.lo + vhi2;
     
     */
    
    
    uint64_t *c = cs->limb;
    const uint64_t *a = as->limb, *b = bs->limb;

    nonad_t ad, be, cf, abde, bcef, acdf;
    nonad_mul(&ad, &a[0], &b[0]);
    nonad_mul(&be, &a[4], &b[4]);
    nonad_mul(&cf, &a[8], &b[8]);

    uint64_t amt = 26;
    uint64x3_t vhi = { amt*((1ull<<58)-1), amt*((1ull<<58)-1), amt*((1ull<<58)-1), 0 },
    vhi2 = { 0, 0, -amt<<57, 0 };

    uint64x3_t t2 = cf.lo + be.hi + ad.hier, t0 = ad.lo + timesW(cf.hi + be.hier) + vhi, t1 = ad.hi + be.lo + timesW(cf.hier);

    int64_t ta[4] VECTOR_ALIGNED, tb[4] VECTOR_ALIGNED;
    // it seems to be faster not to vectorize these loops
    for (i=0; i<3; i++) {
        ta[i] = a[i]-a[i+4];
        tb[i] = b[i]-b[i+4];
    }
    hexad_mul_signed(&abde,ta,tb);

    for (i=0; i<3; i++) {
        ta[i] = a[i+4]-a[i+8];
        tb[i] = b[i+4]-b[i+8];
    }
    hexad_mul_signed(&bcef,ta,tb);

    for (i=0; i<3; i++) {
        ta[i] = a[i]-a[i+8];
        tb[i] = b[i]-b[i+8];
    }
    hexad_mul_signed(&acdf,ta,tb);

    uint64x3_t ot0 = t0 + timesW(t2 + t1 - acdf.hi - bcef.lo);
    uint64x3_t ot1 = t0 + t1 - abde.lo + timesW(t2 - bcef.hi);
    uint64x3_t ot2 = t0 + t1 + t2 - abde.hi - acdf.lo + vhi2;

    uint64x3_t out0 = (ot0 & mask58) + timesW(ot2>>58);
    uint64x3_t out1 = (ot1 & mask58) + (ot0>>58);
    uint64x3_t out2 = (ot2 & mask58) + (ot1>>58);

    *(uint64x4_t *)&c[0] = out0;
    *(uint64x4_t *)&c[4] = out1;
    *(uint64x4_t *)&c[8] = out2;
}


void gf_sqr (gf *__restrict__ cs, const gf *as) {
    int i;
#if 0
    assert(as->limb[3] == 0 && as->limb[7] == 0 && as->limb[11] == 0);
    for (i=0; i<12; i++) {
        assert(as->limb[i] < 5ull<<57);
    }
#endif

    uint64_t *c = cs->limb;
    const uint64_t *a = as->limb;

    nonad_t ad, be, cf, abde, bcef, acdf;
    nonad_sqr(&ad, &a[0]);
    nonad_sqr(&be, &a[4]);
    nonad_sqr(&cf, &a[8]);

    uint64_t amt = 26;
    uint64x3_t vhi = { amt*((1ull<<58)-1), amt*((1ull<<58)-1), amt*((1ull<<58)-1), 0 },
    vhi2 = { 0, 0, -amt<<57, 0 };
    
    uint64x3_t t2 = cf.lo + be.hi + ad.hier, t0 = ad.lo + timesW(cf.hi + be.hier) + vhi, t1 = ad.hi + be.lo + timesW(cf.hier);

    int64_t ta[4] VECTOR_ALIGNED;
    // it seems to be faster not to vectorize these loops
    for (i=0; i<3; i++) {
        ta[i] = a[i]-a[i+4];
    }
    hexad_sqr_signed(&abde,ta);

    for (i=0; i<3; i++) {
        ta[i] = a[i+4]-a[i+8];
    }
    hexad_sqr_signed(&bcef,ta);

    for (i=0; i<3; i++) {
        ta[i] = a[i]-a[i+8];
    }
    hexad_sqr_signed(&acdf,ta);

    uint64x3_t ot0 = t0 + timesW(t2 + t1 - acdf.hi - bcef.lo);
    uint64x3_t ot1 = t0 + t1 - abde.lo + timesW(t2 - bcef.hi);
    uint64x3_t ot2 = t0 + t1 + t2 - abde.hi - acdf.lo + vhi2;

    uint64x3_t out0 = (ot0 & mask58) + timesW(ot2>>58);
    uint64x3_t out1 = (ot1 & mask58) + (ot0>>58);
    uint64x3_t out2 = (ot2 & mask58) + (ot1>>58);

    *(uint64x4_t *)&c[0] = out0;
    *(uint64x4_t *)&c[4] = out1;
    *(uint64x4_t *)&c[8] = out2;
}

void gf_mulw (gf *__restrict__ cs, const gf *as, uint64_t b) {
#if 0
    int i;
    assert(as->limb[3] == 0 && as->limb[7] == 0 && as->limb[11] == 0);
    for (i=0; i<12; i++) {
        assert(as->limb[i] < 1ull<<61);
    }
    assert(b < 1ull<<61);
#endif
    
    
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum3 = 0, accum6 = 0;
    uint64_t mask = (1ull<<58) - 1;

    accum0 += widemulu(b, a[0]);
    accum3 += widemulu(b, a[1]);
    accum6 += widemulu(b, a[2]);
    c[0] = accum0 & mask; accum0 >>= 58;
    c[1] = accum3 & mask; accum3 >>= 58;
    c[2] = accum6 & mask; accum6 >>= 58;

    accum0 += widemulu(b, a[4]);
    accum3 += widemulu(b, a[5]);
    accum6 += widemulu(b, a[6]);
    c[4] = accum0 & mask; accum0 >>= 58;
    c[5] = accum3 & mask; accum3 >>= 58;
    c[6] = accum6 & mask; accum6 >>= 58;

    accum0 += widemulu(b, a[8]);
    accum3 += widemulu(b, a[9]);
    accum6 += widemulu(b, a[10]);
    c[8] = accum0 & mask; accum0 >>= 58;
    c[9] = accum3 & mask; accum3 >>= 58;
    c[10] = accum6 & (mask>>1); accum6 >>= 57;
    
    accum0 += c[1];
    c[1] = accum0 & mask;
    c[5] += accum0 >> 58;

    accum3 += c[2];
    c[2] = accum3 & mask;
    c[6] += accum3 >> 58;

    accum6 += c[0];
    c[0] = accum6 & mask;
    c[4] += accum6 >> 58;
    
    c[3] = c[7] = c[11] = 0;
}
