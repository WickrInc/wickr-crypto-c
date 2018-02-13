/* Copyright (c) 2016 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "f_field.h"

void gf_mul (gf_s *__restrict__ cs, const gf as, const gf bs) {
    const uint32_t *a = as->limb, *b = bs->limb, maske = ((1<<26)-1), masko = ((1<<25)-1);
    
    uint32_t bh[9];
    int i,j;
    for (i=0; i<9; i++) bh[i] = b[i+1] * 19;
    
    uint32_t *c = cs->limb;

    uint64_t accum = 0;
    for (i=0; i<10; /*i+=2*/) {
        /* Even case. */
        for (j=0; j<i; /*j+=2*/) {
            accum += widemul(b[i-j], a[j]); j++;
            accum += widemul(b[i-j], 2*a[j]); j++;
        }
        accum += widemul(b[0], a[j]); j++;
        accum += widemul(bh[8], 2*a[j]); j++;
        for (; j<10; /* j+=2*/) {
            accum += widemul(bh[i-j+9], a[j]); j++;
            accum += widemul(bh[i-j+9], 2*a[j]); j++;
        }
        c[i] = accum & maske;
        accum >>= 26;
        i++;

        /* Odd case is easier: all place values are exact. */
        for (j=0; j<=i; j++) {
            accum += widemul(b[i-j], a[j]);
        }
        for (; j<10; j++) {
            accum += widemul(bh[i-j+9], a[j]);
        }
        c[i] = accum & masko;
        accum >>= 25;
        i++;
    }
    
    accum *= 19;
    accum += c[0];
    c[0] = accum & maske;
    accum >>= 26;
    
    assert(accum < masko);
    c[1] += accum;
}

void gf_mulw_unsigned (gf_s *__restrict__ cs, const gf as, uint32_t b) {
    const uint32_t *a = as->limb, maske = ((1<<26)-1), masko = ((1<<25)-1);
    uint32_t *c = cs->limb;
    uint64_t accum = widemul(b, a[0]);
    c[0] = accum & maske;
    accum >>= 26;

    accum += widemul(b, a[1]);
    c[1] = accum & masko;
    accum >>= 25;

    for (int i=2; i<10; /*i+=2*/) {
        accum += widemul(b, a[i]);
        c[i] = accum & maske;
        accum >>= 26;
        i++;

        accum += widemul(b, a[i]);
        c[i] = accum & masko;
        accum >>= 25;
        i++;
    }
    
    accum *= 19;
    accum += c[0];
    c[0] = accum & maske;
    accum >>= 26;
    
    assert(accum < masko);
    c[1] += accum;
}

void gf_sqr (gf_s *__restrict__ cs, const gf as) {
    gf_mul(cs,as,as); /* Performs better with dedicated square */
}


