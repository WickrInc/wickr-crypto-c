/**
 * @cond internal
 * @file f_arithmetic.c
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Field-specific arithmetic.
 */

#include "field.h"
#include "constant_time.h"

/* Guarantee: a^2 x = 0 if x = 0; else a^2 x = 1 or SQRT_MINUS_ONE; */
mask_t gf_isr (gf a, const gf x) {
    gf L0, L1, L2, L3;
    
    gf_sqr (L0, x);
    gf_mul (L1, L0, x);
    gf_sqr (L0, L1);
    gf_mul (L1, L0, x);
    gf_sqrn(L0, L1, 3);
    gf_mul (L2, L0, L1);
    gf_sqrn(L0, L2, 6);
    gf_mul (L1, L2, L0);
    gf_sqr (L2, L1);
    gf_mul (L0, L2, x);
    gf_sqrn(L2, L0, 12);
    gf_mul (L0, L2, L1);
    gf_sqrn(L2, L0, 25);
    gf_mul (L3, L2, L0);
    gf_sqrn(L2, L3, 25);
    gf_mul (L1, L2, L0);    
    gf_sqrn(L2, L1, 50);
    gf_mul (L0, L2, L3);
    gf_sqrn(L2, L0, 125);
    gf_mul (L3, L2, L0);
    gf_sqrn(L2, L3, 2);
    gf_mul (L0, L2, x);

    gf_sqr (L2, L0);
    gf_mul (L3, L2, x);
    gf_add(L1,L3,ONE);
    mask_t one = gf_eq(L3,ONE);
    mask_t succ = one | gf_eq(L1,ZERO);
    mask_t qr   = one | gf_eq(L3,SQRT_MINUS_ONE);
    
    constant_time_select(L2, SQRT_MINUS_ONE, ONE, sizeof(L2), qr, 0);
    gf_mul (a,L2,L0);
    return succ;
}
