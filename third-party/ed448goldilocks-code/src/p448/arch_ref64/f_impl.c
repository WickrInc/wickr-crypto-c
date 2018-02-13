/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "f_field.h"

void gf_mul (gf_s *__restrict__ cs, const gf as, const gf bs) {
    const uint64_t *a = as->limb, *b = bs->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum1 = 0, accum2;
    uint64_t mask = (1ull<<56) - 1;  

    uint64_t aa[4], bb[4], bbb[4];

    unsigned int i;
    for (i=0; i<4; i++) {
        aa[i]  = a[i] + a[i+4];
        bb[i]  = b[i] + b[i+4];
        bbb[i] = bb[i] + b[i+4];
    }

    int I_HATE_UNROLLED_LOOPS = 0;

    if (I_HATE_UNROLLED_LOOPS) {
        /* The compiler probably won't unroll this,
         * so it's like 80% slower.
         */
        for (i=0; i<4; i++) {
            accum2 = 0;

            unsigned int j;
            for (j=0; j<=i; j++) {
                accum2 += widemul(a[j],   b[i-j]);
                accum1 += widemul(aa[j], bb[i-j]);
                accum0 += widemul(a[j+4], b[i-j+4]);
            }
            for (; j<4; j++) {
                accum2 += widemul(a[j],   b[i-j+8]);
                accum1 += widemul(aa[j], bbb[i-j+4]);
                accum0 += widemul(a[j+4], bb[i-j+4]);
            }

            accum1 -= accum2;
            accum0 += accum2;

            c[i]   = ((uint64_t)(accum0)) & mask;
            c[i+4] = ((uint64_t)(accum1)) & mask;

            accum0 >>= 56;
            accum1 >>= 56;
        }
    } else {
        accum2  = widemul(a[0],  b[0]);
        accum1 += widemul(aa[0], bb[0]);
        accum0 += widemul(a[4],  b[4]);

        accum2 += widemul(a[1],  b[7]);
        accum1 += widemul(aa[1], bbb[3]);
        accum0 += widemul(a[5],  bb[3]);

        accum2 += widemul(a[2],  b[6]);
        accum1 += widemul(aa[2], bbb[2]);
        accum0 += widemul(a[6],  bb[2]);

        accum2 += widemul(a[3],  b[5]);
        accum1 += widemul(aa[3], bbb[1]);
        accum0 += widemul(a[7],  bb[1]);

        accum1 -= accum2;
        accum0 += accum2;

        c[0] = ((uint64_t)(accum0)) & mask;
        c[4] = ((uint64_t)(accum1)) & mask;

        accum0 >>= 56;
        accum1 >>= 56;

        accum2  = widemul(a[0],  b[1]);
        accum1 += widemul(aa[0], bb[1]);
        accum0 += widemul(a[4],  b[5]);

        accum2 += widemul(a[1],  b[0]);
        accum1 += widemul(aa[1], bb[0]);
        accum0 += widemul(a[5],  b[4]);

        accum2 += widemul(a[2],  b[7]);
        accum1 += widemul(aa[2], bbb[3]);
        accum0 += widemul(a[6],  bb[3]);

        accum2 += widemul(a[3],  b[6]);
        accum1 += widemul(aa[3], bbb[2]);
        accum0 += widemul(a[7],  bb[2]);

        accum1 -= accum2;
        accum0 += accum2;

        c[1] = ((uint64_t)(accum0)) & mask;
        c[5] = ((uint64_t)(accum1)) & mask;

        accum0 >>= 56;
        accum1 >>= 56;

        accum2  = widemul(a[0],  b[2]);
        accum1 += widemul(aa[0], bb[2]);
        accum0 += widemul(a[4],  b[6]);

        accum2 += widemul(a[1],  b[1]);
        accum1 += widemul(aa[1], bb[1]);
        accum0 += widemul(a[5],  b[5]);

        accum2 += widemul(a[2],  b[0]);
        accum1 += widemul(aa[2], bb[0]);
        accum0 += widemul(a[6],  b[4]);

        accum2 += widemul(a[3],  b[7]);
        accum1 += widemul(aa[3], bbb[3]);
        accum0 += widemul(a[7],  bb[3]);

        accum1 -= accum2;
        accum0 += accum2;

        c[2] = ((uint64_t)(accum0)) & mask;
        c[6] = ((uint64_t)(accum1)) & mask;

        accum0 >>= 56;
        accum1 >>= 56;

        accum2  = widemul(a[0],  b[3]);
        accum1 += widemul(aa[0], bb[3]);
        accum0 += widemul(a[4],  b[7]);

        accum2 += widemul(a[1],  b[2]);
        accum1 += widemul(aa[1], bb[2]);
        accum0 += widemul(a[5],  b[6]);

        accum2 += widemul(a[2],  b[1]);
        accum1 += widemul(aa[2], bb[1]);
        accum0 += widemul(a[6],  b[5]);

        accum2 += widemul(a[3],  b[0]);
        accum1 += widemul(aa[3], bb[0]);
        accum0 += widemul(a[7],  b[4]);

        accum1 -= accum2;
        accum0 += accum2;

        c[3] = ((uint64_t)(accum0)) & mask;
        c[7] = ((uint64_t)(accum1)) & mask;

        accum0 >>= 56;
        accum1 >>= 56;
    } /* !I_HATE_UNROLLED_LOOPS */

    accum0 += accum1;
    accum0 += c[4];
    accum1 += c[0];
    c[4] = ((uint64_t)(accum0)) & mask;
    c[0] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    c[5] += ((uint64_t)(accum0));
    c[1] += ((uint64_t)(accum1));
}

void gf_mulw_unsigned (gf_s *__restrict__ cs, const gf as, uint32_t b) {
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum4 = 0;
    uint64_t mask = (1ull<<56) - 1;  

    int i;
    for (i=0; i<4; i++) {
        accum0 += widemul(b, a[i]);
        accum4 += widemul(b, a[i+4]);
        c[i]   = accum0 & mask; accum0 >>= 56;
        c[i+4] = accum4 & mask; accum4 >>= 56;
    }
    
    accum0 += accum4 + c[4];
    c[4] = accum0 & mask;
    c[5] += accum0 >> 56;

    accum4 += c[0];
    c[0] = accum4 & mask;
    c[1] += accum4 >> 56;
}

void gf_sqr (gf_s *__restrict__ cs, const gf as) {
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum1 = 0, accum2;
    uint64_t mask = (1ull<<56) - 1;  

    uint64_t aa[4];

    /* For some reason clang doesn't vectorize this without prompting? */
    unsigned int i;
    for (i=0; i<4; i++) {
        aa[i] = a[i] + a[i+4];
    }

    accum2  = widemul(a[0],a[3]);
    accum0  = widemul(aa[0],aa[3]);
    accum1  = widemul(a[4],a[7]);

    accum2 += widemul(a[1], a[2]);
    accum0 += widemul(aa[1], aa[2]);
    accum1 += widemul(a[5], a[6]);

    accum0 -= accum2;
    accum1 += accum2;

    c[3] = ((uint64_t)(accum1))<<1 & mask;
    c[7] = ((uint64_t)(accum0))<<1 & mask;

    accum0 >>= 55;
    accum1 >>= 55;

    accum0 += widemul(2*aa[1],aa[3]);
    accum1 += widemul(2*a[5], a[7]);
    accum0 += widemul(aa[2], aa[2]);
    accum1 += accum0;

    accum0 -= widemul(2*a[1], a[3]);
    accum1 += widemul(a[6], a[6]);
    
    accum2 = widemul(a[0],a[0]);
    accum1 -= accum2;
    accum0 += accum2;

    accum0 -= widemul(a[2], a[2]);
    accum1 += widemul(aa[0], aa[0]);
    accum0 += widemul(a[4], a[4]);

    c[0] = ((uint64_t)(accum0)) & mask;
    c[4] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul(2*aa[2],aa[3]);
    accum0 -= widemul(2*a[2], a[3]);
    accum1 += widemul(2*a[6], a[7]);

    accum1 += accum2;
    accum0 += accum2;

    accum2  = widemul(2*a[0],a[1]);
    accum1 += widemul(2*aa[0], aa[1]);
    accum0 += widemul(2*a[4], a[5]);

    accum1 -= accum2;
    accum0 += accum2;

    c[1] = ((uint64_t)(accum0)) & mask;
    c[5] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul(aa[3],aa[3]);
    accum0 -= widemul(a[3], a[3]);
    accum1 += widemul(a[7], a[7]);

    accum1 += accum2;
    accum0 += accum2;

    accum2  = widemul(2*a[0],a[2]);
    accum1 += widemul(2*aa[0], aa[2]);
    accum0 += widemul(2*a[4], a[6]);

    accum2 += widemul(a[1], a[1]);
    accum1 += widemul(aa[1], aa[1]);
    accum0 += widemul(a[5], a[5]);

    accum1 -= accum2;
    accum0 += accum2;

    c[2] = ((uint64_t)(accum0)) & mask;
    c[6] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum0 += c[3];
    accum1 += c[7];
    c[3] = ((uint64_t)(accum0)) & mask;
    c[7] = ((uint64_t)(accum1)) & mask;

    /* we could almost stop here, but it wouldn't be stable, so... */

    accum0 >>= 56;
    accum1 >>= 56;
    c[4] += ((uint64_t)(accum0)) + ((uint64_t)(accum1));
    c[0] += ((uint64_t)(accum1));
}

