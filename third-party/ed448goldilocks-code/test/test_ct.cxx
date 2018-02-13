/**
 * @file test_decaf.cxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief C++ tests, because that's easier.
 */

#include <decaf.hxx>
#include <decaf/spongerng.hxx>
#include <decaf/crypto.h>
#include <decaf/crypto.hxx>
#include <stdio.h>
#include <valgrind/memcheck.h>

using namespace decaf;
using namespace decaf::TOY;

static const long NTESTS = 10;

const char *undef_str = "Valgrind thinks this string is undefined.";
const Block undef_block(undef_str);

static inline void ignore_result(decaf_error_t x) {
    (void)x;
}

template<typename Group> struct Tests {

typedef typename Group::Scalar Scalar;
typedef typename Group::Point Point;
typedef typename Group::Precomputed Precomputed;

static void test_arithmetic() {
    SpongeRng rng(Block("test_arithmetic"),SpongeRng::DETERMINISTIC);
    rng.stir(undef_block);
    
    Scalar x(rng),y(rng),z;
    uint8_t ser[Group::Scalar::SER_BYTES];
        
    for (int i=0; i<NTESTS; i++) {
        (void)(x+y);
        (void)(x-y);
        (void)(x*y);
        ignore_result(x.inverse_noexcept(y));
        (void)(x==y);
        (void)(z=y);
        x.serialize_into(ser);
        x = y;
    }
}

static void test_elligator() {
    SpongeRng rng(Block("test_elligator"),SpongeRng::DETERMINISTIC);
    rng.stir(undef_block);
    
    FixedArrayBuffer<Group::Point::HASH_BYTES> inv;
        
    for (int i=0; i<NTESTS; i++) {
        Point x(rng), y(rng,false);
        
        ignore_result((x+y).invert_elligator(inv,i));
    }
}

static void test_ec() {
    SpongeRng rng(Block("test_ec"),SpongeRng::DETERMINISTIC);
    rng.stir(undef_block);

    uint8_t ser[Group::Point::SER_BYTES];

    for (int i=0; i<NTESTS; i++) {
        Scalar y(rng),z(rng);
        Point p(rng),q(rng),r;

        p.serialize_into(ser);
        ignore_result(p.decode(FixedBlock<Group::Point::SER_BYTES>(ser)));
        (void)(p*y);
        (void)(p+q);
        (void)(p-q);
        (void)(-p);
        (void)(p.times_two());
        (void)(p==q);
        (void)(p.debugging_torque());
        /* (void)(p.non_secret_combo_with_base(y,z)); */ /* Should fail */
        (void)(Precomputed(p)*y);
        p.dual_scalarmul(q,r,y,z);
        Group::Point::double_scalarmul(p,y,q,z);
        
    }
}

static void test_cfrg() {
    SpongeRng rng(Block("test_cfrg"),SpongeRng::DETERMINISTIC);
    rng.stir(undef_block);
    
    for (int i=0; i<NTESTS; i++) {
        FixedArrayBuffer<Group::DhLadder::PUBLIC_BYTES> pub(rng);
        FixedArrayBuffer<Group::DhLadder::PRIVATE_BYTES> priv(rng);
        
        Group::DhLadder::derive_public_key(priv);
        ignore_result(Group::DhLadder::shared_secret_noexcept(pub,pub,priv));
    }
}

/* Specify the same value as you did when compiling decaf_crypto.c */
#ifndef DECAF_CRYPTO_SHARED_SECRET_SHORT_CIRUIT
#define DECAF_CRYPTO_SHARED_SECRET_SHORT_CIRUIT DECAF_FALSE
#endif

static void test_crypto() {
    SpongeRng rng(Block("test_crypto"),SpongeRng::DETERMINISTIC);
    rng.stir(undef_block);

#if DECAF_CRYPTO_SHARED_SECRET_SHORT_CIRUIT
    SpongeRng defrng(Block("test_crypto_defined"));
#endif
    
    FixedArrayBuffer<Group::Point::SER_BYTES> shared;
    
    for (int i=0; i<NTESTS; i++) {
        PrivateKey<Group> sk1(rng);
        SecureBuffer sig = sk1.sign(undef_block);

#if DECAF_CRYPTO_SHARED_SECRET_SHORT_CIRUIT
        PrivateKey<Group> sk2(defrng);
        ignore_result(sk1.shared_secret_noexcept(shared,sk2.pub(),i&1));
#else
        PrivateKey<Group> sk3(rng);
        ignore_result(sk1.shared_secret_noexcept(shared,sk3.pub(),i&1));
#endif
    }
}

static void run() {
    printf("Testing %s:\n",Group::name());
    test_arithmetic();
    test_elligator();
    test_ec();
    test_cfrg();
    test_crypto();
    printf("\n");
}

}; /* template<GroupId GROUP> struct Tests */

int main(int argc, char **argv) {
    (void) argc; (void) argv;
    VALGRIND_MAKE_MEM_UNDEFINED(undef_str, strlen(undef_str));
    run_for_all_curves<Tests>();    
    return 0;
}
