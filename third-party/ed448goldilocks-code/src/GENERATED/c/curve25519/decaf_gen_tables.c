/**
 * @file curve25519/decaf_gen_tables.c
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Decaf global constant table precomputation.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */
#define _XOPEN_SOURCE 600 /* for posix_memalign */
#include <stdio.h>
#include <stdlib.h>

#include "field.h"
#include "f_field.h"
#include "decaf.h"

#define API_NS(_id) decaf_255_##_id
static const unsigned char base_point_ser_for_pregen[SER_BYTES] = {
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76
};

 /* To satisfy linker. */
const gf API_NS(precomputed_base_as_fe)[1];
const API_NS(point_t) API_NS(point_base);

struct niels_s;
const gf_s *API_NS(precomputed_wnaf_as_fe);
extern const size_t API_NS(sizeof_precomputed_wnafs);

void API_NS(precompute_wnafs) (
    struct niels_s *out,
    const API_NS(point_t) base
);
static void field_print(const gf f) {
    unsigned char ser[X_SER_BYTES];
    gf_serialize(ser,f,1);
    int b=0, i, comma=0;
    unsigned long long limb = 0;
    printf("{FIELD_LITERAL(");
    for (i=0; i<X_SER_BYTES; i++) {
        limb |= ((uint64_t)ser[i])<<b;
        b += 8;
        if (b >= GF_LIT_LIMB_BITS || i == SER_BYTES-1) {
            limb &= (1ull<<GF_LIT_LIMB_BITS) -1;
            b -= GF_LIT_LIMB_BITS;
            if (comma) printf(",");
            comma = 1;
            printf("0x%016llx", limb);
            limb = ((uint64_t)ser[i])>>(8-b);
        }
    }
    printf(")}");
    assert(b<8);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    
    API_NS(point_t) real_point_base;
    int ret = API_NS(point_decode)(real_point_base,base_point_ser_for_pregen,0);
    if (ret != DECAF_SUCCESS) {
        fprintf(stderr, "Can't decode base point!\n");
        return 1;
    }
    
    API_NS(precomputed_s) *pre;
    ret = posix_memalign((void**)&pre, API_NS(alignof_precomputed_s), API_NS(sizeof_precomputed_s));
    if (ret || !pre) {
        fprintf(stderr, "Can't allocate space for precomputed table\n");
        return 1;
    }
    API_NS(precompute)(pre, real_point_base);
    
    struct niels_s *pre_wnaf;
    ret = posix_memalign((void**)&pre_wnaf, API_NS(alignof_precomputed_s), API_NS(sizeof_precomputed_wnafs));
    if (ret || !pre_wnaf) {
        fprintf(stderr, "Can't allocate space for precomputed WNAF table\n");
        return 1;
    }
    API_NS(precompute_wnafs)(pre_wnaf, real_point_base);

    const gf_s *output;
    unsigned i;
    
    printf("/** @warning: this file was automatically generated. */\n");
    printf("#include \"field.h\"\n\n");
    printf("#include <decaf.h>\n\n");
    printf("#define API_NS(_id) decaf_255_##_id\n");
    
    output = (const gf_s *)real_point_base;
    printf("const API_NS(point_t) API_NS(point_base) = {{\n");
    for (i=0; i < sizeof(API_NS(point_t)); i+=sizeof(gf)) {
        if (i) printf(",\n  ");
        field_print(output++);
    }
    printf("\n}};\n");
    
    output = (const gf_s *)pre;
    printf("const gf API_NS(precomputed_base_as_fe)[%d]\n", 
        (int)(API_NS(sizeof_precomputed_s) / sizeof(gf)));
    printf("VECTOR_ALIGNED __attribute__((visibility(\"hidden\"))) = {\n  ");
    
    for (i=0; i < API_NS(sizeof_precomputed_s); i+=sizeof(gf)) {
        if (i) printf(",\n  ");
        field_print(output++);
    }
    printf("\n};\n");
    
    output = (const gf_s *)pre_wnaf;
    printf("const gf API_NS(precomputed_wnaf_as_fe)[%d]\n", 
        (int)(API_NS(sizeof_precomputed_wnafs) / sizeof(gf)));
    printf("VECTOR_ALIGNED __attribute__((visibility(\"hidden\"))) = {\n  ");
    for (i=0; i < API_NS(sizeof_precomputed_wnafs); i+=sizeof(gf)) {
        if (i) printf(",\n  ");
        field_print(output++);
    }
    printf("\n};\n");
    
    return 0;
}
