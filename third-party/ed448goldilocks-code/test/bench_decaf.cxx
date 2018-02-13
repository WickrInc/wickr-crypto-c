/**
 * @file test_decaf.cxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief C++ benchmarks, because that's easier.
 */

#include <decaf.hxx>
#include <decaf/shake.hxx>
#include <decaf/sha512.hxx>
#include <decaf/spongerng.hxx>
#include <decaf/eddsa.hxx>
#include <stdio.h>
#include <sys/time.h>
#include <assert.h>
#include <stdint.h>
#include <vector>
#include <algorithm>

using namespace decaf;


static __inline__ void __attribute__((unused)) ignore_result ( int result ) { (void)result; }
static double now(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec/1000000.0;
}

// RDTSC from the chacha code
#ifndef __has_builtin
#define __has_builtin(X) 0
#endif
#if defined(__clang__) && __has_builtin(__builtin_readcyclecounter)
#define rdtsc __builtin_readcyclecounter
#else
static inline uint64_t rdtsc(void) {
# if defined(__x86_64__)
    uint32_t lobits, hibits;
    __asm__ __volatile__ ("rdtsc" : "=a"(lobits), "=d"(hibits));
    return (lobits | ((uint64_t)(hibits) << 32));
# elif defined(__i386__)
    uint64_t __value;
    __asm__ __volatile__ ("rdtsc" : "=A"(__value));
    return __value;
# else
    return 0;
# endif
}
#endif

static void printSI(double x, const char *unit, const char *spacer = " ") {
    const char *small[] = {" ","m","µ","n","p"};
    const char *big[] = {" ","k","M","G","T"};
    if (x < 1) {
        unsigned di=0;
        for (di=0; di<sizeof(small)/sizeof(*small)-1 && x && x < 1; di++) { 
            x *= 1000.0;
        }
        printf("%6.2f%s%s%s", x, spacer, small[di], unit);
    } else {
        unsigned di=0;
        for (di=0; di<sizeof(big)/sizeof(*big)-1 && x && x >= 1000; di++) { 
            x /= 1000.0;
        }
        printf("%6.2f%s%s%s", x, spacer, big[di], unit);
    }
}

class Benchmark {
    static const int NTESTS = 20, NSAMPLES=50, DISCARD=2;
    static double totalCy, totalS;
public:
    int i, j, ntests, nsamples;
    double begin;
    uint64_t tsc_begin;
    std::vector<double> times;
    std::vector<uint64_t> cycles;
    Benchmark(const char *s, double factor = 1) {
        printf("%s:", s);
        if (strlen(s) < 25) printf("%*s",int(25-strlen(s)),"");
        fflush(stdout);
        i = j = 0;
        ntests = NTESTS * factor;
        nsamples = NSAMPLES;
        begin = now();
        tsc_begin = rdtsc();
        times = std::vector<double>(NSAMPLES);
        cycles = std::vector<uint64_t>(NSAMPLES);
    }
    ~Benchmark() {
        double tsc = 0;
        double t = 0;
        
        std::sort(times.begin(), times.end());
        std::sort(cycles.begin(), cycles.end());
        
        for (int k=DISCARD; k<nsamples-DISCARD; k++) {
            tsc += cycles[k];
            t += times[k];
        }
        
        totalCy += tsc;
        totalS += t;
        
        t /= ntests*(nsamples-2*DISCARD);
        tsc /= ntests*(nsamples-2*DISCARD);
        
        printSI(t,"s");
        printf("    ");
        printSI(1/t,"/s");
        if (tsc) { printf("    "); printSI(tsc, "cy"); }
        printf("\n");
    }
    inline bool iter() {
        i++;
        if (i >= ntests) {
            uint64_t tsc = rdtsc() - tsc_begin;
            double t = now() - begin;
            begin += t;
            tsc_begin += tsc;
            assert(j >= 0 && j < nsamples);
            cycles[j] = tsc;
            times[j] = t;
            
            j++;
            i = 0;
        }
        return j < nsamples;
    }
    static void calib() {
        if (totalS && totalCy) {
            const char *s = "Cycle calibration";
            printf("%s:", s);
            if (strlen(s) < 25) printf("%*s",int(25-strlen(s)),"");
            printSI(totalCy / totalS, "Hz");
            printf("\n");
        }
    }
};

double Benchmark::totalCy = 0, Benchmark::totalS = 0;


template<typename Group> struct Benches {

typedef typename Group::Scalar Scalar;
typedef typename Group::Point Point;
typedef typename Group::Precomputed Precomputed;

static void cfrg() {
    SpongeRng rng(Block("bench_cfrg_crypto"),SpongeRng::DETERMINISTIC);
    FixedArrayBuffer<Group::DhLadder::PUBLIC_BYTES> base(rng);
    FixedArrayBuffer<Group::DhLadder::PRIVATE_BYTES> s1(rng);
    for (Benchmark b("RFC 7748 keygen"); b.iter(); ) { Group::DhLadder::derive_public_key(s1); }
    for (Benchmark b("RFC 7748 shared secret"); b.iter(); ) { Group::DhLadder::shared_secret(base,s1); }

    FixedArrayBuffer<EdDSA<Group>::PrivateKey::SER_BYTES> e1(rng);
    typename EdDSA<Group>::PublicKey pub((NOINIT()));
    typename EdDSA<Group>::PrivateKey priv((NOINIT()));
    SecureBuffer sig;
    for (Benchmark b("EdDSA keygen"); b.iter(); ) { priv = e1; }
    for (Benchmark b("EdDSA sign"); b.iter(); ) { sig = priv.sign(Block(NULL,0)); }
    pub = priv;
    for (Benchmark b("EdDSA verify"); b.iter(); ) { pub.verify(sig,Block(NULL,0)); }
}

static void macro() {
    printf("\nMacro-benchmarks for %s:\n", Group::name());
    printf("CFRG crypto benchmarks:\n");
    cfrg();
}

static void micro() {
    SpongeRng rng(Block("per-curve-benchmarks"),SpongeRng::DETERMINISTIC);
    Precomputed pBase;
    Point p,q;
    Scalar s(1),t(2);
    SecureBuffer ep, ep2(Point::SER_BYTES*2);
    
    printf("\nMicro-benchmarks for %s:\n", Group::name());
    for (Benchmark b("Scalar add", 1000); b.iter(); ) { s+=t; }
    for (Benchmark b("Scalar times", 100); b.iter(); ) { s*=t; }
    for (Benchmark b("Scalar inv", 1); b.iter(); ) { s.inverse(); }
    for (Benchmark b("Point add", 100); b.iter(); ) { p += q; }
    for (Benchmark b("Point double", 100); b.iter(); ) { p.double_in_place(); }
    for (Benchmark b("Point scalarmul"); b.iter(); ) { p * s; }
    for (Benchmark b("Point encode"); b.iter(); ) { ep = p.serialize(); }
    for (Benchmark b("Point decode"); b.iter(); ) { p = Point(ep); }
    for (Benchmark b("Point create/destroy"); b.iter(); ) { Point r; }
    for (Benchmark b("Point hash nonuniform"); b.iter(); ) { Point::from_hash(ep); }
    for (Benchmark b("Point hash uniform"); b.iter(); ) { Point::from_hash(ep2); }
    for (Benchmark b("Point unhash nonuniform"); b.iter(); ) { ignore_result(p.invert_elligator(ep,0)); }
    for (Benchmark b("Point unhash uniform"); b.iter(); ) { ignore_result(p.invert_elligator(ep2,0)); }
    for (Benchmark b("Point steg"); b.iter(); ) { p.steg_encode(rng); }
    for (Benchmark b("Point double scalarmul"); b.iter(); ) { Point::double_scalarmul(p,s,q,t); }
    for (Benchmark b("Point dual scalarmul"); b.iter(); ) { p.dual_scalarmul(p,q,s,t); }
    for (Benchmark b("Point precmp scalarmul"); b.iter(); ) { pBase * s; }
    for (Benchmark b("Point double scalarmul_v"); b.iter(); ) {
        s = Scalar(rng);
        t = Scalar(rng);
        p.non_secret_combo_with_base(s,t);
    }
}

}; /* template <typename group> struct Benches */

template <typename Group> struct Macro { static void run() { Benches<Group>::macro(); } };
template <typename Group> struct Micro { static void run() { Benches<Group>::micro(); } };

int main(int argc, char **argv) {
    
    bool micro = false;
    if (argc >= 2 && !strcmp(argv[1], "--micro"))
        micro = true;

    SpongeRng rng(Block("micro-benchmarks"),SpongeRng::DETERMINISTIC);
    if (micro) {
        printf("\nMicro-benchmarks:\n");
        SHAKE<128> shake1;
        SHAKE<256> shake2;
        SHA3<512> sha5;
        SHA512 sha2;
        unsigned char b1024[1024] = {1};
        for (Benchmark b("SHAKE128 1kiB", 30); b.iter(); ) { shake1 += Buffer(b1024,1024); }
        for (Benchmark b("SHAKE256 1kiB", 30); b.iter(); ) { shake2 += Buffer(b1024,1024); }
        for (Benchmark b("SHA3-512 1kiB", 30); b.iter(); ) { sha5 += Buffer(b1024,1024); }
        for (Benchmark b("SHA512 1kiB", 30); b.iter(); ) { sha2 += Buffer(b1024,1024); }
        
        run_for_all_curves<Micro>();
    }
    
    run_for_all_curves<Macro>();
    
    printf("\n");
    Benchmark::calib();
    printf("\n");
    
    return 0;
}
