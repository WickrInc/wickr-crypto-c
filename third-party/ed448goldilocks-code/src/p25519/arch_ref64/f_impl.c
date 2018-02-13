/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "f_field.h"

void gf_mul (gf_s *__restrict__ cs, const gf as, const gf bs) {
    const uint64_t *a = as->limb, *b = bs->limb, mask = ((1ull<<51)-1);
    
    uint64_t bh[4];
    int i,j;
    for (i=0; i<4; i++) bh[i] = b[i+1] * 19;
    
    uint64_t *c = cs->limb;

    __uint128_t accum = 0;
    for (i=0; i<5; i++) {
        for (j=0; j<=i; j++) {
            accum += widemul(b[i-j], a[j]);
        }
        for (; j<5; j++) {
            accum += widemul(bh[i-j+4], a[j]);
        }
        c[i] = accum & mask;
        accum >>= 51;
    }
    
    accum *= 19;
    accum += c[0];
    c[0] = accum & mask;
    accum >>= 51;
    
    assert(accum < mask);
    c[1] += accum;
}

void gf_mulw_unsigned (gf_s *__restrict__ cs, const gf as, uint32_t b) {
    const uint64_t *a = as->limb, mask = ((1ull<<51)-1);
    int i;
    
    uint64_t *c = cs->limb;

    __uint128_t accum = 0;
    for (i=0; i<5; i++) {
        accum += widemul(b, a[i]);
        c[i] = accum & mask;
        accum >>= 51;
    }
    
    accum *= 19;
    accum += c[0];
    c[0] = accum & mask;
    accum >>= 51;
    
    assert(accum < mask);
    c[1] += accum;
}

void gf_sqr (gf_s *__restrict__ cs, const gf as) {
    gf_mul(cs,as,as); /* Performs better with dedicated square */
}
