
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
        default:
            return NULL;
    }
}
