

/* Based on DJB's crypto_hashblocks/ref implementation.
 * Public domain.
 */

#include <decaf/sha512.h>
#include <string.h>
#include <assert.h>

static uint64_t load_bigendian(const uint8_t *x)
{
  return
      (uint64_t) (x[7]) \
  | (((uint64_t) (x[6])) << 8) \
  | (((uint64_t) (x[5])) << 16) \
  | (((uint64_t) (x[4])) << 24) \
  | (((uint64_t) (x[3])) << 32) \
  | (((uint64_t) (x[2])) << 40) \
  | (((uint64_t) (x[1])) << 48) \
  | (((uint64_t) (x[0])) << 56)
  ;
}

#define SHR(x,c) ((x) >> (c))
#define ROTR(x,c) (((x) >> (c)) | ((x) << (64 - (c))))

#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define Sigma1(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
#define sigma0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x,7))
#define sigma1(x) (ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6))

#define M(w0,w14,w9,w1) w0 = sigma1(w14) + w9 + sigma0(w1) + w0;

#define EXPAND \
  M(w0 ,w14,w9 ,w1 ) \
  M(w1 ,w15,w10,w2 ) \
  M(w2 ,w0 ,w11,w3 ) \
  M(w3 ,w1 ,w12,w4 ) \
  M(w4 ,w2 ,w13,w5 ) \
  M(w5 ,w3 ,w14,w6 ) \
  M(w6 ,w4 ,w15,w7 ) \
  M(w7 ,w5 ,w0 ,w8 ) \
  M(w8 ,w6 ,w1 ,w9 ) \
  M(w9 ,w7 ,w2 ,w10) \
  M(w10,w8 ,w3 ,w11) \
  M(w11,w9 ,w4 ,w12) \
  M(w12,w10,w5 ,w13) \
  M(w13,w11,w6 ,w14) \
  M(w14,w12,w7 ,w15) \
  M(w15,w13,w8 ,w0 )

#define F(w,k) \
  T1 = h + Sigma1(e) + Ch(e,f,g) + k + w; \
  T2 = Sigma0(a) + Maj(a,b,c); \
  h = g; \
  g = f; \
  f = e; \
  e = d + T1; \
  d = c; \
  c = b; \
  b = a; \
  a = T1 + T2;

static DECAF_NOINLINE void hashblock(decaf_sha512_ctx_t ctx) {
    const uint8_t *in = ctx->block;
    uint64_t a = ctx->state[0];
    uint64_t b = ctx->state[1];
    uint64_t c = ctx->state[2];
    uint64_t d = ctx->state[3];
    uint64_t e = ctx->state[4];
    uint64_t f = ctx->state[5];
    uint64_t g = ctx->state[6];
    uint64_t h = ctx->state[7];
    uint64_t T1;
    uint64_t T2;
    
    uint64_t w0  = load_bigendian(in +   0);
    uint64_t w1  = load_bigendian(in +   8);
    uint64_t w2  = load_bigendian(in +  16);
    uint64_t w3  = load_bigendian(in +  24);
    uint64_t w4  = load_bigendian(in +  32);
    uint64_t w5  = load_bigendian(in +  40);
    uint64_t w6  = load_bigendian(in +  48);
    uint64_t w7  = load_bigendian(in +  56);
    uint64_t w8  = load_bigendian(in +  64);
    uint64_t w9  = load_bigendian(in +  72);
    uint64_t w10 = load_bigendian(in +  80);
    uint64_t w11 = load_bigendian(in +  88);
    uint64_t w12 = load_bigendian(in +  96);
    uint64_t w13 = load_bigendian(in + 104);
    uint64_t w14 = load_bigendian(in + 112);
    uint64_t w15 = load_bigendian(in + 120);

    F(w0 ,0x428a2f98d728ae22ULL)
    F(w1 ,0x7137449123ef65cdULL)
    F(w2 ,0xb5c0fbcfec4d3b2fULL)
    F(w3 ,0xe9b5dba58189dbbcULL)
    F(w4 ,0x3956c25bf348b538ULL)
    F(w5 ,0x59f111f1b605d019ULL)
    F(w6 ,0x923f82a4af194f9bULL)
    F(w7 ,0xab1c5ed5da6d8118ULL)
    F(w8 ,0xd807aa98a3030242ULL)
    F(w9 ,0x12835b0145706fbeULL)
    F(w10,0x243185be4ee4b28cULL)
    F(w11,0x550c7dc3d5ffb4e2ULL)
    F(w12,0x72be5d74f27b896fULL)
    F(w13,0x80deb1fe3b1696b1ULL)
    F(w14,0x9bdc06a725c71235ULL)
    F(w15,0xc19bf174cf692694ULL)

    EXPAND

    F(w0 ,0xe49b69c19ef14ad2ULL)
    F(w1 ,0xefbe4786384f25e3ULL)
    F(w2 ,0x0fc19dc68b8cd5b5ULL)
    F(w3 ,0x240ca1cc77ac9c65ULL)
    F(w4 ,0x2de92c6f592b0275ULL)
    F(w5 ,0x4a7484aa6ea6e483ULL)
    F(w6 ,0x5cb0a9dcbd41fbd4ULL)
    F(w7 ,0x76f988da831153b5ULL)
    F(w8 ,0x983e5152ee66dfabULL)
    F(w9 ,0xa831c66d2db43210ULL)
    F(w10,0xb00327c898fb213fULL)
    F(w11,0xbf597fc7beef0ee4ULL)
    F(w12,0xc6e00bf33da88fc2ULL)
    F(w13,0xd5a79147930aa725ULL)
    F(w14,0x06ca6351e003826fULL)
    F(w15,0x142929670a0e6e70ULL)

    EXPAND

    F(w0 ,0x27b70a8546d22ffcULL)
    F(w1 ,0x2e1b21385c26c926ULL)
    F(w2 ,0x4d2c6dfc5ac42aedULL)
    F(w3 ,0x53380d139d95b3dfULL)
    F(w4 ,0x650a73548baf63deULL)
    F(w5 ,0x766a0abb3c77b2a8ULL)
    F(w6 ,0x81c2c92e47edaee6ULL)
    F(w7 ,0x92722c851482353bULL)
    F(w8 ,0xa2bfe8a14cf10364ULL)
    F(w9 ,0xa81a664bbc423001ULL)
    F(w10,0xc24b8b70d0f89791ULL)
    F(w11,0xc76c51a30654be30ULL)
    F(w12,0xd192e819d6ef5218ULL)
    F(w13,0xd69906245565a910ULL)
    F(w14,0xf40e35855771202aULL)
    F(w15,0x106aa07032bbd1b8ULL)

    EXPAND

    F(w0 ,0x19a4c116b8d2d0c8ULL)
    F(w1 ,0x1e376c085141ab53ULL)
    F(w2 ,0x2748774cdf8eeb99ULL)
    F(w3 ,0x34b0bcb5e19b48a8ULL)
    F(w4 ,0x391c0cb3c5c95a63ULL)
    F(w5 ,0x4ed8aa4ae3418acbULL)
    F(w6 ,0x5b9cca4f7763e373ULL)
    F(w7 ,0x682e6ff3d6b2b8a3ULL)
    F(w8 ,0x748f82ee5defb2fcULL)
    F(w9 ,0x78a5636f43172f60ULL)
    F(w10,0x84c87814a1f0ab72ULL)
    F(w11,0x8cc702081a6439ecULL)
    F(w12,0x90befffa23631e28ULL)
    F(w13,0xa4506cebde82bde9ULL)
    F(w14,0xbef9a3f7b2c67915ULL)
    F(w15,0xc67178f2e372532bULL)

    EXPAND

    F(w0 ,0xca273eceea26619cULL)
    F(w1 ,0xd186b8c721c0c207ULL)
    F(w2 ,0xeada7dd6cde0eb1eULL)
    F(w3 ,0xf57d4f7fee6ed178ULL)
    F(w4 ,0x06f067aa72176fbaULL)
    F(w5 ,0x0a637dc5a2c898a6ULL)
    F(w6 ,0x113f9804bef90daeULL)
    F(w7 ,0x1b710b35131c471bULL)
    F(w8 ,0x28db77f523047d84ULL)
    F(w9 ,0x32caab7b40c72493ULL)
    F(w10,0x3c9ebe0a15c9bebcULL)
    F(w11,0x431d67c49c100d4cULL)
    F(w12,0x4cc5d4becb3e42b6ULL)
    F(w13,0x597f299cfc657e2aULL)
    F(w14,0x5fcb6fab3ad6faecULL)
    F(w15,0x6c44198c4a475817ULL)
  
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void decaf_sha512_init(decaf_sha512_ctx_t ctx) {
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179
    };
    memcpy(ctx->state,iv,sizeof(iv));
    memset(ctx->block,0,sizeof(ctx->block));
    ctx->bytes_processed = 0;
}

void decaf_sha512_update(decaf_sha512_ctx_t ctx, const uint8_t *message, size_t length) {
    while (length > 0) {
        size_t grab = length, off = ctx->bytes_processed % 128;
        if (grab > 128-off) grab = 128-off;
        memcpy(&ctx->block[off], message, grab);
        
        ctx->bytes_processed += grab;
        length -= grab;
        message += grab;
        
        if (grab == 128 - off) {
            hashblock(ctx);
        }
    }
}

void decaf_sha512_final(decaf_sha512_ctx_t ctx, uint8_t *out, size_t length) {
    assert(length <= 512/8);
    
    size_t off = ctx->bytes_processed % 128;
    uint64_t bp = ctx->bytes_processed * 8;
    ctx->block[off] = 0x80;
    memset(&ctx->block[off+1], 0, 128-off-1);
    
    if (off >= 112) {
        hashblock(ctx);
        memset(&ctx->block,0,128);
    }
    
    for (size_t i=0; i<8; i++)
        ctx->block[120 + i] = bp >> (56 - 8*i);
    hashblock(ctx);
    
    for (size_t i=0; i<length; i++) {
        out[i] = ctx->state[i/8] >> (56 - 8*(i%8));
    }
    
    decaf_sha512_init(ctx);
}
