
#include "digest.h"

const wickr_digest_t *wickr_digest_find_with_id(uint8_t digest_id)
{
    switch (digest_id) {
        case DIGEST_ID_SHA256:
            return &DIGEST_SHA_256;
        case DIGEST_ID_SHA384:
            return &DIGEST_SHA_384;
        case DIGEST_ID_SHA512:
            return &DIGEST_SHA_512;
        case DIGEST_ID_SHAKE256:
            return &DIGEST_SHAKE_256_ED448;
        case DIGEST_ID_NONE:
            return &DIGEST_NONE_ED448;
        default:
            return NULL;
    }
}
