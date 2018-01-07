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


const gf MODULUS = {FIELD_LITERAL(
    0xfffffffffffffff, 0xfffffffffffffff, 0xfffffffffffffff, 0xfffffffffffffff, 
    0xffffffffffffffe, 0xfffffffffffffff, 0xfffffffffffffff, 0xfffffffffffffff
)};

void 
gf_isr (
    gf_a_t a,
    const gf_a_t x
) {
    gf_a_t L0, L1, L2, L3;
    gf_sqr  (   L2,     x );
    gf_mul  (   L1,     x,   L2 );
    gf_sqrn (   L0,   L1,     2 );
    gf_mul  (   L2,   L1,   L0 );
    gf_sqrn (   L0,   L2,     4 );
    gf_mul  (   L1,   L2,   L0 );
    gf_sqr  (   L0,   L1 );
    gf_mul  (   L2,     x,   L0 );
    gf_sqrn (   L0,   L2,     8 );
    gf_mul  (   L2,   L1,   L0 );
    gf_sqrn (   L0,   L2,    17 );
    gf_mul  (   L1,   L2,   L0 );
    gf_sqrn (   L0,   L1,    17 );
    gf_mul  (   L1,   L2,   L0 );
    gf_sqrn (   L3,   L1,    17 );
    gf_mul  (   L0,   L2,   L3 );
    gf_sqrn (   L2,   L0,    51 );
    gf_mul  (   L0,   L1,   L2 );
    gf_sqrn (   L1,   L0,   119 );
    gf_mul  (   L2,   L0,   L1 );
    gf_sqr  (   L0,   L2 );
    gf_mul  (   L1,     x,   L0 );
    gf_sqrn (   L0,   L1,   239 );
    gf_mul  (     a,   L2,   L0 );
}
