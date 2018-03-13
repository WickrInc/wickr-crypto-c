
#include "key_exchange.h"
#include "memory.h"
#include "key_exchange.pb-c.h"

#define EXCHANGE_ARRAY_TYPE_ID 2

wickr_key_exchange_t *wickr_key_exchange_create(wickr_buffer_t *exchange_id,
                                                uint64_t key_id,
                                                wickr_buffer_t *exchange_data)
{
    if (!exchange_id || !exchange_data) {
        return NULL;
    }
    
    wickr_key_exchange_t *new_exchange = wickr_alloc_zero(sizeof(wickr_key_exchange_t));
    new_exchange->exchange_id = exchange_id;
    new_exchange->key_id = key_id;
    new_exchange->exchange_data = exchange_data;
    
    return new_exchange;
}

wickr_key_exchange_t *wickr_key_exchange_copy(const wickr_key_exchange_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_buffer_t *exchange_data_copy = wickr_buffer_copy(source->exchange_data);
    
    if (!exchange_data_copy) {
        return NULL;
    }
    
    wickr_buffer_t *exchange_id_copy = wickr_buffer_copy(source->exchange_id);
    
    if (!exchange_id_copy) {
        wickr_buffer_destroy(&exchange_data_copy);
        return NULL;
    }
    
    wickr_key_exchange_t *copy = wickr_key_exchange_create(exchange_id_copy, source->key_id, exchange_data_copy);
    
    if (!copy) {
        wickr_buffer_destroy(&exchange_data_copy);
        wickr_buffer_destroy(&exchange_id_copy);
    }
    
    return copy;
}

void wickr_key_exchange_destroy(wickr_key_exchange_t **exchange)
{
    if (!exchange || !*exchange) {
        return;
    }
    
    wickr_buffer_destroy(&(*exchange)->exchange_data);
    wickr_buffer_destroy(&(*exchange)->exchange_id);
    wickr_free(*exchange);
    *exchange = NULL;
}

wickr_exchange_array_t *wickr_exchange_array_new(uint32_t exchange_count)
{
    return wickr_array_new(exchange_count, EXCHANGE_ARRAY_TYPE_ID, (wickr_array_copy_func)wickr_key_exchange_copy,
                           (wickr_array_destroy_func)wickr_key_exchange_destroy);
}

bool wickr_exchange_array_set_item(wickr_exchange_array_t *array,
                                   uint32_t index,
                                   wickr_key_exchange_t *exchange)
{
    return wickr_array_set_item(array, index, exchange, false);
}

wickr_key_exchange_t *wickr_exchange_array_fetch_item(wickr_exchange_array_t *array, uint32_t index)
{
    return wickr_array_fetch_item(array, index, false);
}

wickr_array_t *wickr_exchange_array_copy(wickr_exchange_array_t *array)
{
    return wickr_array_copy(array, true);
}

void wickr_exchange_array_destroy(wickr_exchange_array_t **array)
{
    if (!array || !*array) {
        return;
    }
    
    wickr_array_destroy(array, true);
}

wickr_key_exchange_set_t *wickr_key_exchange_set_create(wickr_ec_key_t *sender_pub, wickr_exchange_array_t *exchanges)
{
    if (!sender_pub || !exchanges) {
        return NULL;
    }
    
    wickr_key_exchange_set_t *new_set = wickr_alloc_zero(sizeof(wickr_key_exchange_set_t));
    
    if (!new_set) {
        return NULL;
    }
    
    new_set->sender_pub = sender_pub;
    new_set->exchanges = exchanges;
    
    return new_set;
}

wickr_key_exchange_t *wickr_key_exchange_set_find(const wickr_key_exchange_set_t *exchange_set,
                                                  const wickr_buffer_t *identifier)
{
    if (!exchange_set || !identifier) {
        return NULL;
    }
    
    for (uint32_t i = 0; i < wickr_array_get_item_count(exchange_set->exchanges); i++) {
        wickr_key_exchange_t *one_exchange = wickr_exchange_array_fetch_item(exchange_set->exchanges, i);
        if (wickr_buffer_is_equal(identifier, one_exchange->exchange_id, NULL)) {
            return wickr_key_exchange_copy(one_exchange);
        }
    }
    
    return NULL;
}

wickr_key_exchange_set_t *wickr_key_exchange_set_copy(const wickr_key_exchange_set_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_ec_key_t *sender_pub = wickr_ec_key_copy(source->sender_pub);
    
    if (!sender_pub) {
        return NULL;
    }
    
    wickr_exchange_array_t *exchanges = wickr_exchange_array_copy(source->exchanges);
    
    if (!exchanges) {
        wickr_ec_key_destroy(&sender_pub);
        return NULL;
    }
    
    wickr_key_exchange_set_t *copy = wickr_key_exchange_set_create(sender_pub, exchanges);
    
    if (!copy) {
        wickr_ec_key_destroy(&sender_pub);
        wickr_array_destroy(&exchanges, true);
    }
    
    return copy;
}

void wickr_key_exchange_set_destroy(wickr_key_exchange_set_t **header)
{
    if (!header || !*header) {
        return;
    }
    
    wickr_ec_key_destroy(&(*header)->sender_pub);
    wickr_array_destroy(&(*header)->exchanges, true);
    wickr_free(*header);
    *header = NULL;
}

wickr_buffer_t *wickr_key_exchange_set_serialize(const wickr_key_exchange_set_t *exchange_set)
{
    if (!exchange_set) {
        return NULL;
    }
    
    uint32_t num_exchanges = wickr_array_get_item_count(exchange_set->exchanges);
    
    Wickr__Proto__KeyExchangeSet__Exchange **exchanges;
    exchanges = wickr_alloc_zero(sizeof(Wickr__Proto__KeyExchangeSet__Exchange *) * num_exchanges);
    
    Wickr__Proto__KeyExchangeSet proto_exchange_set = WICKR__PROTO__KEY_EXCHANGE_SET__INIT;
    proto_exchange_set.sender_pub.data = exchange_set->sender_pub->pub_data->bytes;
    proto_exchange_set.sender_pub.len = exchange_set->sender_pub->pub_data->length;
    
    
    for (int i = 0; i < num_exchanges; i++) {
        wickr_key_exchange_t *one_exchange = wickr_array_fetch_item(exchange_set->exchanges, i, false);
        
        exchanges[i] = wickr_alloc_zero(sizeof(Wickr__Proto__KeyExchangeSet__Exchange));
        wickr__proto__key_exchange_set__exchange__init(exchanges[i]);
        
        exchanges[i]->exchange_data.data = one_exchange->exchange_data->bytes;
        exchanges[i]->exchange_data.len = one_exchange->exchange_data->length;
        exchanges[i]->key_id = one_exchange->key_id;
        exchanges[i]->identifier.data = one_exchange->exchange_id->bytes;
        exchanges[i]->identifier.len = one_exchange->exchange_id->length;
    }
    
    proto_exchange_set.n_exchanges = num_exchanges;
    proto_exchange_set.exchanges = exchanges;
    size_t required_size = wickr__proto__key_exchange_set__get_packed_size(&proto_exchange_set);
    
    wickr_buffer_t *serialized_buffer = wickr_buffer_create_empty(required_size);
    if (!serialized_buffer) {
        for (int i = 0; i < num_exchanges; i++) {
            wickr_free(exchanges[i]);
        }
        wickr_free(proto_exchange_set.exchanges);
        return NULL;
    }
    
    wickr__proto__key_exchange_set__pack(&proto_exchange_set, serialized_buffer->bytes);
    
    for (int i = 0; i < num_exchanges; i++) {
        wickr_free(exchanges[i]);
    }
    
    wickr_free(proto_exchange_set.exchanges);
    
    return serialized_buffer;
}

wickr_key_exchange_set_t *wickr_key_exchange_set_create_from_buffer(const wickr_crypto_engine_t *engine,
                                                                    const wickr_buffer_t *buffer)
{
    if (!buffer) {
        return NULL;
    }
    
    Wickr__Proto__KeyExchangeSet *proto_exchange_set = wickr__proto__key_exchange_set__unpack(NULL,
                                                                                              buffer->length,
                                                                                              buffer->bytes);
    
    if (!proto_exchange_set ||
        proto_exchange_set->n_exchanges == 0 ||
        proto_exchange_set->n_exchanges > INT32_MAX) {
        return NULL;
    }
    
    wickr_exchange_array_t *exchanges = wickr_exchange_array_new((uint32_t)proto_exchange_set->n_exchanges);
    
    if (!exchanges) {
        wickr__proto__key_exchange_set__free_unpacked(proto_exchange_set, NULL);
        return NULL;
    }
    
    for (int i = 0; i < proto_exchange_set->n_exchanges; i++) {
        
        Wickr__Proto__KeyExchangeSet__Exchange *one_proto_exchange = proto_exchange_set->exchanges[i];
        
        wickr_buffer_t *one_exchange_data = wickr_buffer_create(one_proto_exchange->exchange_data.data,
                                                                one_proto_exchange->exchange_data.len);
        
        if (!one_exchange_data) {
            wickr__proto__key_exchange_set__free_unpacked(proto_exchange_set, NULL);
            wickr_exchange_array_destroy(&exchanges);
            return NULL;
        }
        
        wickr_buffer_t *one_id_data = wickr_buffer_create(one_proto_exchange->identifier.data,
                                                          one_proto_exchange->identifier.len);
        
        if (!one_id_data) {
            wickr_buffer_destroy(&one_exchange_data);
            wickr__proto__key_exchange_set__free_unpacked(proto_exchange_set, NULL);
            wickr_exchange_array_destroy(&exchanges);
            return NULL;
        }
        
        wickr_key_exchange_t *one_exchange = wickr_key_exchange_create(one_id_data,
                                                                       one_proto_exchange->key_id,
                                                                       one_exchange_data);
        
        if (!one_exchange) {
            wickr_buffer_destroy(&one_exchange_data);
            wickr_buffer_destroy(&one_id_data);
            wickr__proto__key_exchange_set__free_unpacked(proto_exchange_set, NULL);
            wickr_exchange_array_destroy(&exchanges);
            return NULL;
        }
        
        if (!wickr_exchange_array_set_item(exchanges, i, one_exchange)) {
            wickr_key_exchange_destroy(&one_exchange);
            wickr_exchange_array_destroy(&exchanges);
            wickr__proto__key_exchange_set__free_unpacked(proto_exchange_set, NULL);
            return NULL;
        }
        
    }
    
    wickr_buffer_t temp_ec_key_buffer;
    temp_ec_key_buffer.bytes = proto_exchange_set->sender_pub.data;
    temp_ec_key_buffer.length = proto_exchange_set->sender_pub.len;
    
    wickr_ec_key_t *sender_ec_key = engine->wickr_crypto_engine_ec_key_import(&temp_ec_key_buffer, false);
    wickr__proto__key_exchange_set__free_unpacked(proto_exchange_set, NULL);
    
    if (!sender_ec_key) {
        wickr_exchange_array_destroy(&exchanges);
        return NULL;
    }
    
    wickr_key_exchange_set_t *exchange_set = wickr_key_exchange_set_create(sender_ec_key, exchanges);
    
    if (!exchange_set) {
        wickr_ec_key_destroy(&sender_ec_key);
        wickr_exchange_array_destroy(&exchanges);
        return NULL;
    }
    
    return exchange_set;
}
