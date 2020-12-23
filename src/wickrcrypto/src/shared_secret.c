
#include "shared_secret.h"
#include "memory.h"

wickr_shared_secret_t *wickr_shared_secret_create(wickr_buffer_t *secret, wickr_buffer_t *ctx)
{
    if (!secret) {
        return NULL;
    }
    
    wickr_shared_secret_t *shared_secret = wickr_alloc_zero(sizeof(wickr_shared_secret_t));
    
    if (!shared_secret) {
        return NULL;
    }
    
    shared_secret->secret = secret;
    shared_secret->ctx = ctx;
    
    return shared_secret;
}

wickr_shared_secret_t *wickr_shared_secret_copy(const wickr_shared_secret_t *secret)
{
    if (!secret) {
        return NULL;
    }
    
    wickr_buffer_t *secret_copy = wickr_buffer_copy(secret->secret);
    
    if (!secret_copy) {
        return NULL;
    }
    
    wickr_buffer_t *ctx_copy = wickr_buffer_copy(secret->ctx);
    
    if (secret->ctx && !ctx_copy) {
        wickr_buffer_destroy(&secret_copy);
        return NULL;
    }
    
    wickr_shared_secret_t *shared_secret = wickr_shared_secret_create(secret_copy, ctx_copy);
    
    if (!shared_secret) {
        wickr_buffer_destroy(&secret_copy);
        wickr_buffer_destroy(&ctx_copy);
    }
    
    return shared_secret;
}

void wickr_shared_secret_destroy(wickr_shared_secret_t **secret)
{
    if (!secret || !*secret) {
        return;
    }
    
    wickr_buffer_destroy_zero(&(*secret)->secret);
    wickr_buffer_destroy_zero(&(*secret)->ctx);
    wickr_free(*secret);
    *secret = NULL;
}

wickr_shared_secret_t *wickr_shared_secret_merge(const wickr_shared_secret_t *secret_a, const wickr_shared_secret_t *secret_b)
{
    if (!secret_a || !secret_b) {
        return NULL;
    }
    
    wickr_buffer_t *secret_merge = wickr_buffer_concat(secret_a->secret, secret_b->secret);
    
    if (!secret_merge) {
        return NULL;
    }
    
    wickr_buffer_t *ctx_merge = NULL;
    bool has_ctx = false;
    
    if (secret_a->ctx && secret_b->ctx) {
        ctx_merge = wickr_buffer_concat(secret_a->ctx, secret_b->ctx);
        has_ctx = true;
    } else if (secret_a->ctx) {
        ctx_merge = wickr_buffer_copy(secret_a->ctx);
        has_ctx = true;
    } else if (secret_b->ctx) {
        ctx_merge = wickr_buffer_copy(secret_b->ctx);
        has_ctx = true;
    }
    
    if (has_ctx && !ctx_merge) {
        wickr_buffer_destroy(&secret_merge);
        return NULL;
    }
    
    wickr_shared_secret_t *merged = wickr_shared_secret_create(secret_merge, ctx_merge);
    
    if (!merged) {
        wickr_buffer_destroy(&secret_merge);
        wickr_buffer_destroy(&ctx_merge);
    }
    
    return merged;
}
