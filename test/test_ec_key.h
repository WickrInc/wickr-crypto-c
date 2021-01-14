#ifndef test_ec_key_h
#define test_ec_key_h

#include <stdio.h>
#include "cspec.h"
#include "eckey.h"

bool ec_key_is_equal(const wickr_ec_key_t *key_a, const wickr_ec_key_t *key_b);

DEFINE_DESCRIPTION(wickr_ec_key)

#endif /* test_ec_key_h */
