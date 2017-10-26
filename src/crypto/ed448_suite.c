// Include

#include "ed448_suite.h"
#include <stdio.h>
#include <decaf/ed448.h>

int test_function(int a, int b)
{
    uint8_t pubkey[DECAF_EDDSA_448_PUBLIC_BYTES] = { 0 };
    uint8_t privkey[DECAF_EDDSA_448_PRIVATE_BYTES] = {a % 255, b % 255};
    decaf_ed448_derive_public_key(pubkey, privkey);
    return pubkey[0];
}