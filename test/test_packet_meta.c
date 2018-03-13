
#include "test_packet_meta.h"
#include "protocol.h"

DESCRIBE(packet_meta, "wickr_packet_meta")
{
    wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    wickr_buffer_t *test_tag = engine.wickr_crypto_engine_crypto_random(32);
    wickr_ephemeral_info_t test_settings = { .ttl = 1000, .bor = 1001 };
    uint16_t test_content = 128;
    
    wickr_packet_meta_t *test_meta = NULL;
    
    IT("can be created from it's components")
    {
        SHOULD_BE_NULL(wickr_packet_meta_create(test_settings, NULL, test_content));
        
        test_meta = wickr_packet_meta_create(test_settings, test_tag, test_content);
        SHOULD_NOT_BE_NULL(test_meta);
        SHOULD_EQUAL(test_tag, test_meta->channel_tag);
        SHOULD_EQUAL(test_settings.bor, test_meta->ephemerality_settings.bor);
        SHOULD_EQUAL(test_settings.ttl, test_meta->ephemerality_settings.ttl);
        SHOULD_EQUAL(test_content, test_meta->content_type);
    }
    END_IT
    
    IT("can be copied")
    {
        SHOULD_BE_NULL(wickr_packet_meta_copy(NULL));
        
        wickr_packet_meta_t *copy = wickr_packet_meta_copy(test_meta);
        SHOULD_NOT_BE_NULL(copy);
        SHOULD_BE_TRUE(wickr_buffer_is_equal(copy->channel_tag, test_meta->channel_tag, NULL));
        SHOULD_EQUAL(copy->ephemerality_settings.bor, test_meta->ephemerality_settings.bor);
        SHOULD_EQUAL(copy->ephemerality_settings.ttl, test_meta->ephemerality_settings.ttl);
        SHOULD_EQUAL(copy->content_type, test_meta->content_type);
        
        wickr_packet_meta_destroy(&copy);
    }
    END_IT
    
    wickr_packet_meta_destroy(&test_meta);
    SHOULD_BE_NULL(test_meta);
}
END_DESCRIBE
