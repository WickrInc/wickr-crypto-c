
#ifndef test_stream_cipher_h
#define test_stream_cipher_h

#include "cspec.h"
#include "stream_key.h"

bool wickr_stream_key_is_equal(const wickr_stream_key_t *k1, const wickr_stream_key_t *k2);

DEFINE_DESCRIPTION(wickr_stream_key)
DEFINE_DESCRIPTION(wickr_stream_cipher)
DEFINE_DESCRIPTION(wickr_stream_iv);

#endif /* test_stream_cipher_h */
