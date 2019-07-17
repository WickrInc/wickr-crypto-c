
#include "packet_meta.h"
#include "memory.h"

wickr_packet_meta_t *wickr_packet_meta_create(wickr_ephemeral_info_t ephemerality_settings, wickr_buffer_t *channel_tag, uint16_t content_type)
{
    if (!channel_tag) {
        return NULL;
    }
    
    wickr_packet_meta_t *new_packet_meta = wickr_alloc_zero(sizeof(wickr_packet_meta_t));
    new_packet_meta->channel_tag = channel_tag;
    new_packet_meta->content_type = content_type;
    new_packet_meta->ephemerality_settings = ephemerality_settings;
    
    return new_packet_meta;
}

wickr_packet_meta_t *wickr_packet_meta_copy(const wickr_packet_meta_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_buffer_t *channel_tag = wickr_buffer_copy(source->channel_tag);
    
    if (!channel_tag) {
        return NULL;
    }
    
    wickr_packet_meta_t *copy = wickr_packet_meta_create(source->ephemerality_settings, channel_tag, source->content_type);
    
    if (!copy) {
        wickr_buffer_destroy(&channel_tag);
    }
    
    return copy;
}

void wickr_packet_meta_destroy(wickr_packet_meta_t **meta)
{
    if (!meta || !*meta) {
        return;
    }
    
    wickr_buffer_destroy(&(*meta)->channel_tag);
    wickr_free(*meta);
    *meta = NULL;
}
