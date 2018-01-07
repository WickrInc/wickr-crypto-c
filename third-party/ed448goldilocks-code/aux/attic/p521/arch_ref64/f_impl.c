/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "f_field.h"

void gf_mul (gf_s *__restrict__ cs, const gf as, const gf bs) {
    uint64_t *c = cs->limb;
    const uint64_t *a = as->limb, *b = bs->limb;
    __uint128_t accum0, accum1;

    accum0  = widemul(2*a[8], b[8]);
    accum1  = widemul(a[0], b[7]);
    accum0 += widemul(a[1], b[6]);
    accum1 += widemul(a[2], b[5]);
    accum0 += widemul(a[3], b[4]);
    accum1 += widemul(a[4], b[3]);
    accum0 += widemul(a[5], b[2]);
    accum1 += widemul(a[6], b[1]);
    accum0 += widemul(a[7], b[0]);
    accum1 += accum0;
    c[7] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;
  
    accum0 = 0;
    accum1 += widemul(a[0], b[8-0]);
    accum0 += widemul(a[1], b[8-1]);
    accum1 += widemul(a[2], b[8-2]);
    accum0 += widemul(a[3], b[8-3]);
    accum1 += widemul(a[4], b[8-4]);
    accum0 += widemul(a[5], b[8-5]);
    accum1 += widemul(a[6], b[8-6]);
    accum0 += widemul(a[7], b[8-7]);
    accum1 += widemul(a[8], b[8-8]);
    accum1 += accum0;
    c[8] = accum1 & ((1ull<<57)-1);
    accum1 >>= 57;

    accum0 = 0;
    accum0 += widemul(a[1], b[0+9-1]);
    accum0 += widemul(a[2], b[0+9-2]);
    accum0 += widemul(a[3], b[0+9-3]);
    accum0 += widemul(a[4], b[0+9-4]);
    accum1 += widemul(a[0], b[0-0]);
    accum0 += widemul(a[5], b[0+9-5]);
    accum0 += widemul(a[6], b[0+9-6]);
    accum0 += widemul(a[7], b[0+9-7]);
    accum0 += widemul(a[8], b[0+9-8]);
    accum1 += accum0 << 1;
    c[0] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum0 += widemul(a[2], b[1+9-2]);
    accum0 += widemul(a[3], b[1+9-3]);
    accum1 += widemul(a[0], b[1-0]);
    accum0 += widemul(a[4], b[1+9-4]);
    accum0 += widemul(a[5], b[1+9-5]);
    accum1 += widemul(a[1], b[1-1]);
    accum0 += widemul(a[6], b[1+9-6]);
    accum0 += widemul(a[7], b[1+9-7]);
    accum0 += widemul(a[8], b[1+9-8]);
    accum1 += accum0 << 1;
    c[1] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum0 += widemul(a[3], b[2+9-3]);
    accum1 += widemul(a[0], b[2-0]);
    accum0 += widemul(a[4], b[2+9-4]);
    accum0 += widemul(a[5], b[2+9-5]);
    accum1 += widemul(a[1], b[2-1]);
    accum0 += widemul(a[6], b[2+9-6]);
    accum0 += widemul(a[7], b[2+9-7]);
    accum1 += widemul(a[2], b[2-2]);
    accum0 += widemul(a[8], b[2+9-8]);
    accum1 += accum0 << 1;
    c[2] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum0 += widemul(a[4], b[3+9-4]);
    accum1 += widemul(a[0], b[3-0]);
    accum0 += widemul(a[5], b[3+9-5]);
    accum1 += widemul(a[1], b[3-1]);
    accum0 += widemul(a[6], b[3+9-6]);
    accum1 += widemul(a[2], b[3-2]);
    accum0 += widemul(a[7], b[3+9-7]);
    accum1 += widemul(a[3], b[3-3]);
    accum0 += widemul(a[8], b[3+9-8]);
    accum1 += accum0 << 1;
    c[3] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum1 += widemul(a[0], b[4-0]);
    accum0 += widemul(a[5], b[4+9-5]);
    accum1 += widemul(a[1], b[4-1]);
    accum0 += widemul(a[6], b[4+9-6]);
    accum1 += widemul(a[2], b[4-2]);
    accum0 += widemul(a[7], b[4+9-7]);
    accum1 += widemul(a[3], b[4-3]);
    accum0 += widemul(a[8], b[4+9-8]);
    accum1 += widemul(a[4], b[4-4]);
    accum1 += accum0 << 1;
    c[4] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum1 += widemul(a[0], b[5-0]);
    accum0 += widemul(a[6], b[5+9-6]);
    accum1 += widemul(a[1], b[5-1]);
    accum1 += widemul(a[2], b[5-2]);
    accum0 += widemul(a[7], b[5+9-7]);
    accum1 += widemul(a[3], b[5-3]);
    accum1 += widemul(a[4], b[5-4]);
    accum0 += widemul(a[8], b[5+9-8]);
    accum1 += widemul(a[5], b[5-5]);
    accum1 += accum0 << 1;
    c[5] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum1 += widemul(a[0], b[6-0]);
    accum1 += widemul(a[1], b[6-1]);
    accum0 += widemul(a[7], b[6+9-7]);
    accum1 += widemul(a[2], b[6-2]);
    accum1 += widemul(a[3], b[6-3]);
    accum1 += widemul(a[4], b[6-4]);
    accum0 += widemul(a[8], b[6+9-8]);
    accum1 += widemul(a[5], b[6-5]);
    accum1 += widemul(a[6], b[6-6]);
    accum1 += accum0 << 1;
    c[6] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;
  
    accum1 += c[7];
    c[7] = accum1 & ((1ull<<58)-1);
  
    c[8] += accum1 >> 58;
}

void gf_mulw (
    gf_s *__restrict__ cs,
    const gf as,
    uint64_t b
) {
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum3 = 0, accum6 = 0;
    uint64_t mask = (1ull<<58) - 1;  

    int i;
    for (i=0; i<3; i++) {
        accum0 += widemul(b, a[i]);
        accum3 += widemul(b, a[i+3]);
        accum6 += widemul(b, a[i+6]);
        c[i]   = accum0 & mask; accum0 >>= 58;
        c[i+3] = accum3 & mask; accum3 >>= 58;
        if (i==2) { 
            c[i+6] = accum6 & (mask>>1); accum6 >>= 57;
        } else {
            c[i+6] = accum6 & mask; accum6 >>= 58;
        }
    }
    
    accum0 += c[3];
    c[3] = accum0 & mask;
    c[4] += accum0 >> 58;

    accum3 += c[6];
    c[6] = accum3 & mask;
    c[7] += accum3 >> 58;

    accum6 += c[0];
    c[0] = accum6 & mask;
    c[1] += accum6 >> 58;
}

void gf_sqr (gf_s *__restrict__ cs, const gf as) {
    uint64_t *c = cs->limb;
    const uint64_t *a = as->limb;
    __uint128_t accum0, accum1;

    accum0  = widemul(a[8], a[8]);
    accum1  = widemul(a[0], a[7]);
    accum0 += widemul(a[1], a[6]);
    accum1 += widemul(a[2], a[5]);
    accum0 += widemul(a[3], a[4]);
    accum1 += accum0;
    c[7] = 2 * (accum1 & ((1ull<<57)-1));
    accum1 >>= 57;
  
    accum0 = 0;
    accum0 = 0;
    accum1 += widemul(a[4], a[4]);
    accum0 += widemul(a[1], a[7]);
    accum1 += widemul(2*a[2], a[6]);
    accum0 += widemul(a[3], a[5]);
    accum1 += widemul(2*a[0], a[8]);
    accum1 += 2*accum0;
    c[8] = accum1 & ((1ull<<57)-1);
    accum1 >>= 57;

    accum0 = 0;
    accum1 += widemul(a[0], a[0]);
    accum0 += widemul(a[1], a[8]);
    accum0 += widemul(a[2], a[7]);
    accum0 += widemul(a[3], a[6]);
    accum0 += widemul(a[4], a[5]);
    accum1 += accum0 << 2;
    c[0] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum0 += widemul(a[2], a[8]);
    accum0 += widemul(a[3], a[7]);
    accum0 += widemul(a[4], a[6]);
    accum0 <<= 1;
    accum0 += widemul(a[5], a[5]);
    accum0 += widemul(a[0], a[1]);
    accum1 += accum0 << 1;
    c[1] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum1 += widemul(a[1], a[1]);

    accum0 += widemul(a[3], a[8]);
    accum0 += widemul(a[4], a[7]);
    accum0 += widemul(a[5], a[6]);
    accum0 <<= 1;
    accum0 += widemul(a[0], a[2]);
    accum1 += accum0 << 1;
    c[2] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum0 += widemul(a[6], a[6]);
    accum0 += widemul(2*a[5], a[7]);
    accum0 += widemul(2*a[4], a[8]);
    accum0 += widemul(a[0], a[3]);
    accum0 += widemul(a[1], a[2]);
    accum1 += accum0 << 1;
    c[3] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum0 += widemul(a[6], a[7]);
    accum0 += widemul(a[5], a[8]);
    accum0 <<= 1;
    accum1 += widemul(a[2], a[2]);
    accum0 += widemul(a[0], a[4]);
    accum0 += widemul(a[1], a[3]);
    accum1 += accum0 << 1;
    c[4] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum0 += widemul(2*a[6], a[8]);
    accum0 += widemul(a[7], a[7]);
    accum0 += widemul(a[0], a[5]);
    accum0 += widemul(a[1], a[4]);
    accum0 += widemul(a[2], a[3]);
    accum1 += accum0 << 1;
    c[5] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;

    accum0 = 0;
    accum1 += widemul(a[3], a[3]);
    accum0 += widemul(a[0], a[6]);
    accum0 += widemul(a[1], a[5]);
    accum0 += widemul(2*a[7], a[8]);
    accum0 += widemul(a[2], a[4]);
    accum1 += accum0 << 1;
    c[6] = accum1 & ((1ull<<58)-1);
    accum1 >>= 58;
  
    accum1 += c[7];
    c[7] = accum1 & ((1ull<<58)-1);
  
    c[8] += accum1 >> 58;
}
