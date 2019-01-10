
#include "b32.h"
#include <string.h>

/* Base32 alphabet (Crockford's Base32) */
const char alphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/* Calculates the encoded output buffer length for given buffer size (bytes) */
static size_t __base32_encode_length(size_t bytes)
{
    if (bytes >= SIZE_MAX / 8) {
        return 0;
    }
    
    size_t bits = bytes * 8;
    size_t length = bits / 5;
    
    if ((bits % 5) > 0) {
        length++;
    }
    
    return length;
}

/* Calculates the decoded output buffer length for given encode base32 buffer size (bytes) */
static size_t __base32_decode_length(size_t bytes)
{
    if (bytes >= SIZE_MAX / 5) {
        return 0;
    }
    
    size_t bits = bytes * 5;
    size_t length = bits / 8;
    
    return length;
}

/* Maps a base32 encoded buffer TO a specified alphabet (i.e. "0123456789ABCDEFGHJKMNPQRSTVWXYZ").
 Performs in place mapping. */
static bool __base32_encode_map(unsigned char *inout32, size_t inout32_len, const char *alpha32)
{
    // Validate
    if ((inout32 == 0) || (alpha32 == 0)) {
        return false;
    }
    
    for (int i = 0; i < inout32_len; i++) {
        
        if (inout32[i] >= 32) {
            return false;
        }
        
        inout32[i] = alpha32[inout32[i]];
    }
    
    return true;
}

static void __base32_decode_reverse_map(const char* in_alpha32, unsigned char* out_map)
{
    /* Set 255 as an out of range marker to easily detect mapping failures */
    memset(out_map, 255, sizeof(unsigned char) * 256);
    
    for (int i = 0; i < 32; i++) {
        out_map[(int)in_alpha32[i]] = i;
    }
}

/* Maps a base32 encoded buffer FROM a specified alphabet (i.e. "0123456789ABCDEFGHJKMNPQRSTVWXYZ").
   Performs in place mapping. */
static bool __base32_decode_unmap(unsigned char* inout32, size_t inout32_len, const char* alpha32)
{
    if ((inout32 == 0) || (alpha32 == 0)) {
        return false;
    }
    
    unsigned char rmap[256];
    __base32_decode_reverse_map(alpha32, rmap);
    
    for (size_t i = 0; i < inout32_len; i++) {
        /* Fail if the character can't be mapped to the proper alphabet */
        unsigned char mapped_char = rmap[(int)inout32[i]];
        if ((int)mapped_char == 255) {
            return NULL;
        }
        inout32[i] = mapped_char;
    }
    
    return true;
}

static bool __base32_encode_block(const unsigned char* in5, unsigned char* out8)
{
    // pack 5 bytes
    uint64_t buffer = 0;
    
    for (int i = 0; i < 5; i++) {
        
        if (i != 0) {
            buffer = (buffer << 8);
        }
        
        buffer = buffer | in5[i];
    }
    
    // output 8 bytes
    for (int j = 7; j >= 0; j--) {
        
        buffer = buffer << (24 + (7 - j) * 5);
        buffer = buffer >> (24 + (7 - j) * 5);
        
        unsigned char c = (unsigned char)(buffer >> (j * 5));
        
        // self check
        if (c >= 32) {
            return false;
        }
        
        out8[7 - j] = c;
    }
    
    return true;
}

static bool __base32_decode_block(const unsigned char* in8, unsigned char* out5)
{
    // pack 8 bytes
    uint64_t buffer = 0;
    
    for (int i = 0; i < 8; i++) {
        
        // input check
        if (in8[i] >= 32) {
            return false;
        }
        
        if (i != 0) {
            buffer = (buffer << 5);
        }
        
        buffer = buffer | in8[i];
    }
    
    // output 5 bytes
    for (int j = 4; j >= 0; j--) {
        out5[4 - j] = (unsigned char)(buffer >> (j * 8));
    }
    
    return true;
}

/* Encode given input buffer, and outputs it into given output buffer */
static bool __base32_encode_base32(const unsigned char *in, size_t in_len, unsigned char *out)
{
    if ((in == 0) || (out == 0)) {
        return false;
    }
    
    size_t d = in_len / 5;
    size_t r = in_len % 5;
    
    unsigned char out_buff[8];
    
    for (size_t j = 0; j < d; j++)
    {
        if(!__base32_encode_block(&in[j * 5], &out_buff[0])) {
            return false;
        }
        
        memmove(&out[j * 8], &out_buff[0], sizeof(unsigned char) * 8);
    }
    
    unsigned char padd[5];
    memset(padd, 0, sizeof(unsigned char) * 5);
    
    for (size_t i = 0; i < r; i++) {
        padd[i] = in[in_len - r + i];
    }
    
    if (!__base32_encode_block(&padd[0], &out_buff[0])) {
        return false;
    }
    
    memmove(&out[d * 8], &out_buff[0], sizeof(unsigned char) * __base32_encode_length(r));
    
    return true;
}

static bool __base32_decode_base32(const unsigned char* in, size_t in_len, unsigned char* out)
{
    if ((in == 0) || (out == 0)) {
        return false;
    }
    
    size_t d = in_len / 8;
    size_t r = in_len % 8;
    
    unsigned char out_buff[5];
    
    for (size_t j = 0; j < d; j++) {
        if (!__base32_decode_block(&in[j * 8], &out_buff[0])) {
            return false;
        }
        memmove(&out[j * 5], &out_buff[0], sizeof(unsigned char) * 5);
    }
    
    unsigned char padd[8];
    memset(padd, 0, sizeof(unsigned char) * 8);
    
    for (size_t i = 0; i < r; i++) {
        padd[i] = in[in_len - r + i];
    }
    
    if(!__base32_decode_block(&padd[0], &out_buff[0])) {
        return false;
    }
    
    memmove(&out[d * 5], &out_buff[0], sizeof(unsigned char) * __base32_decode_length(r));
    
    return true;
}

wickr_buffer_t *base32_encode(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    wickr_buffer_t *return_buffer = wickr_buffer_create_empty_zero(__base32_encode_length(buffer->length));
    
    if (!return_buffer) {
        return NULL;
    }
    
    if (!__base32_encode_base32(buffer->bytes, buffer->length, return_buffer->bytes)) {
        wickr_buffer_destroy(&return_buffer);
        return NULL;
    }
    
    if (!__base32_encode_map(return_buffer->bytes, return_buffer->length, alphabet)) {
        wickr_buffer_destroy(&return_buffer);
        return NULL;
    }
    
    return return_buffer;
    
}

wickr_buffer_t *base32_decode(const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    wickr_buffer_t *unmapped = wickr_buffer_copy(buffer);
    
    if (!unmapped) {
        return NULL;
    }
    
    if (!__base32_decode_unmap(unmapped->bytes, unmapped->length, alphabet)) {
        wickr_buffer_destroy(&unmapped);
        return NULL;
    }
    
    wickr_buffer_t *decoded = wickr_buffer_create_empty_zero(__base32_decode_length(unmapped->length) + 1);
    decoded->length = decoded->length - 1;
    
    if (!decoded) {
        return NULL;
    }
    
    if (!__base32_decode_base32(unmapped->bytes, unmapped->length, decoded->bytes)) {
        wickr_buffer_destroy(&decoded);
        wickr_buffer_destroy(&unmapped);
        return NULL;
    }
    
    wickr_buffer_destroy(&unmapped);
    
    return decoded;
}
