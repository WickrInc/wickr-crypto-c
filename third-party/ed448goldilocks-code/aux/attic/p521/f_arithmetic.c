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
    0x3ffffffffffffff, 0x3ffffffffffffff, 0x3ffffffffffffff,
    0x3ffffffffffffff, 0x3ffffffffffffff, 0x3ffffffffffffff,
    0x3ffffffffffffff, 0x3ffffffffffffff, 0x1ffffffffffffff
)};

void 
gf_isr (
    gf_a_t a,
    const gf_a_t x
) {
    gf_a_t L0, L1, L2;
    gf_sqr  (   L1,     x );
    gf_mul  (   L0,     x,   L1 );
    gf_sqrn (   L2,   L0,     2 );
    gf_mul  (   L1,   L0,   L2 );
    gf_sqrn (   L2,   L1,     4 );
    gf_mul  (   L0,   L1,   L2 );
    gf_sqrn (   L2,   L0,     8 );
    gf_mul  (   L1,   L0,   L2 );
    gf_sqrn (   L2,   L1,    16 );
    gf_mul  (   L0,   L1,   L2 );
    gf_sqrn (   L2,   L0,    32 );
    gf_mul  (   L1,   L0,   L2 );
    gf_sqr  (   L2,   L1 );
    gf_mul  (   L0,     x,   L2 );
    gf_sqrn (   L2,   L0,    64 );
    gf_mul  (   L0,   L1,   L2 );
    gf_sqrn (   L2,   L0,   129 );
    gf_mul  (   L1,   L0,   L2 );
    gf_sqr  (   L2,   L1 );
    gf_mul  (   L0,     x,   L2 );
    gf_sqrn (   L2,   L0,   259 );
    gf_mul  (   L1,   L0,   L2 );
    gf_sqr  (   L0,   L1 );
    gf_mul  (     a,     x,   L0 );
}
