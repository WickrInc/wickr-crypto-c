
#include "key_exchange.h"
#include "memory.h"
#include "key_exchange.pb-c.h"
#include "private/buffer_priv.h"
#include "private/eckey_priv.h"

#define EXCHANGE_ARRAY_TYPE_ID 2

wickr_key_exchange_t *wickr_key_exchange_create(wickr_buffer_t *exchange_id,
                                                uint64_t key_id,
                                                wickr_cipher_result_t *exchange_ciphertext)
{
    if (!exchange_id || !exchange_ciphertext) {
        return NULL;
    }
    
    wickr_key_exchange_t *new_exchange = wickr_alloc_zero(sizeof(wickr_key_exchange_t));
    new_exchange->exchange_id = exchange_id;
    new_exchange->key_id = key_id;
    new_exchange->exchange_ciphertext = exchange_ciphertext;
    
    return new_exchange;
}

wickr_key_exchange_t *wickr_key_exchange_copy(const wickr_key_exchange_t *source)
{
    if (!source) {
        return NULL;
    }
    
    wickr_cipher_result_t *exchange_ciphertext_copy = wickr_cipher_result_copy(source->exchange_ciphertext);
    
    if (!exchange_ciphertext_copy) {
        return NULL;
    }
    
    wickr_buffer_t *exchange_id_copy = wickr_buffer_copy(source->exchange_id);
    
    if (!exchange_id_copy) {
        wickr_cipher_result_destroy(&exchange_ciphertext_copy);
        return NULL;
    }
    
    wickr_key_exchange_t *copy = wickr_key_exchange_create(exchange_id_copy, source->key_id, exchange_ciphertext_copy);
    
    if (!copy) {
        wickr_cipher_result_destroy(&exchange_ciphertext_copy);
        wickr_buffer_destroy(&exchange_id_copy);
    }
    
    return copy;
}

void wickr_key_exchange_destroy(wickr_key_exchange_t **exchange)
{
    if (!exchange || !*exchange) {
        return;
    }
    
    wickr_cipher_result_destroy(&(*exchange)->exchange_ciphertext);
    wickr_buffer_destroy(&(*exchange)->exchange_id);
    wickr_free(*exchange);
    *exchange = NULL;
}

static void __wickr_key_exchange_proto_free(Wickr__Proto__KeyExchangeSet__Exchange *exchange)
{
    if (!exchange) {
        return;
    }
    
    wickr_free(exchange->exchange_data.data);
    wickr_free(exchange);
}

static Wickr__Proto__KeyExchangeSet__Exchange *__wickr_key_exchange_to_proto(const wickr_key_exchange_t *exchange)
{
    if (!exchange) {
        return NULL;
    }
    
    Wickr__Proto__KeyExchangeSet__Exchange *proto_exchange = wickr_alloc_zero(sizeof(Wickr__Proto__KeyExchangeSet__Exchange));
    
    if (!proto_exchange) {
        return NULL;
    }
    
    wickr__proto__key_exchange_set__exchange__init(proto_exchange);
    proto_exchange->key_id = exchange->key_id;
    
    wickr_buffer_t *exchange_data = wickr_cipher_result_serialize(exchange->exchange_ciphertext);
    
    if (!exchange_data) {
        wickr_free(proto_exchange);
        return NULL;
    }
    
    if (!wickr_buffer_to_protobytes(&proto_exchange->exchange_data, exchange_data)) {
        wickr_free(proto_exchange);
        wickr_buffer_destroy(&exchange_data);
        return NULL;
    }
    
    wickr_buffer_destroy(&exchange_data);
    
    proto_exchange->identifier.data = exchange->exchange_id->bytes;
    proto_exchange->identifier.len = exchange->exchange_id->length;
    
    return proto_exchange;
}

static wickr_key_exchange_t *__wickr_key_exchange_create_with_proto(const Wickr__Proto__KeyExchangeSet__Exchange *exchange_proto)
{
    if (!exchange_proto || !exchange_proto->exchange_data.data || !exchange_proto->identifier.data) {
        return NULL;
    }
    
    wickr_buffer_t *exchange_bytes = wickr_buffer_from_protobytes(exchange_proto->exchange_data);
    wickr_cipher_result_t *cipher_result = wickr_cipher_result_from_buffer(exchange_bytes);
    wickr_buffer_destroy(&exchange_bytes);
    
    if (!cipher_result) {
        return NULL;
    }
    
    wickr_buffer_t *identifier_bytes = wickr_buffer_from_protobytes(exchange_proto->identifier);
    
    if (!identifier_bytes) {
        wickr_cipher_result_destroy(&cipher_result);
        return NULL;
    }
    
    
    wickr_key_exchange_t *exchange = wickr_key_exchange_create(identifier_bytes, exchange_proto->key_id, cipher_result);
    
    if (!exchange) {
        wickr_buffer_destroy(&identifier_bytes);
        wickr_cipher_result_destroy(&cipher_result);
        return NULL;
    }
    
    return exchange;
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

static void __wickr_key_exchange_proto_array_destroy(Wickr__Proto__KeyExchangeSet__Exchange **exchanges,
                                                     size_t num_exchanges)
{
    if (!exchanges) {
        return;
    }
    
    for (size_t i = 0; i < num_exchanges; i++) {
        __wickr_key_exchange_proto_free(exchanges[i]);
    }
    
    wickr_free(exchanges);
}

static void __wickr_key_exchange_set_proto_free(Wickr__Proto__KeyExchangeSet *proto_exchange_set)
{
    if (!proto_exchange_set) {
        return;
    }
    
    __wickr_key_exchange_proto_array_destroy(proto_exchange_set->exchanges, proto_exchange_set->n_exchanges);
    wickr_free(proto_exchange_set);
}

static wickr_key_exchange_set_t *__wickr_key_exchange_set_create_with_proto(const Wickr__Proto__KeyExchangeSet *exchange_set_proto,
                                                                            const wickr_crypto_engine_t *engine)
{
    if (!exchange_set_proto ||
        !exchange_set_proto->exchanges ||
        exchange_set_proto->n_exchanges == 0 ||
        exchange_set_proto->n_exchanges > INT32_MAX ||
        !exchange_set_proto->sender_pub.data) {
        return NULL;
    }
    
    wickr_exchange_array_t *exchanges = wickr_exchange_array_new((uint32_t)exchange_set_proto->n_exchanges);
    
    if (!exchanges) {
        return NULL;
    }
    
    for (uint32_t i = 0; i < exchange_set_proto->n_exchanges; i++) {
        
        Wickr__Proto__KeyExchangeSet__Exchange *one_proto_exchange = exchange_set_proto->exchanges[i];
        wickr_key_exchange_t *one_exchange = __wickr_key_exchange_create_with_proto(one_proto_exchange);
        
        if (!one_exchange) {
            wickr_exchange_array_destroy(&exchanges);
            return NULL;
        }
        
        if (!wickr_exchange_array_set_item(exchanges, i, one_exchange)) {
            wickr_key_exchange_destroy(&one_exchange);
            wickr_exchange_array_destroy(&exchanges);
            return NULL;
        }
        
    }
    
    wickr_ec_key_t *pubkey = wickr_ec_key_from_protobytes(exchange_set_proto->sender_pub, engine, false);
    
    if (!pubkey) {
        wickr_exchange_array_destroy(&exchanges);
        return NULL;
    }
    
    wickr_key_exchange_set_t *exchange_set = wickr_key_exchange_set_create(pubkey, exchanges);
    
    if (!exchange_set) {
        wickr_exchange_array_destroy(&exchanges);
        wickr_ec_key_destroy(&pubkey);
    }
    
    return exchange_set;
}

static Wickr__Proto__KeyExchangeSet *__wickr_key_exchange_set_to_proto(const wickr_key_exchange_set_t *exchange_set)
{
    if (!exchange_set) {
        return NULL;
    }
    
    uint32_t num_exchanges = wickr_array_get_item_count(exchange_set->exchanges);
    
    Wickr__Proto__KeyExchangeSet__Exchange **exchanges;
    exchanges = wickr_alloc_zero(sizeof(Wickr__Proto__KeyExchangeSet__Exchange *) * num_exchanges);
    
    if (!exchanges) {
        return NULL;
    }
    
    for (uint32_t i = 0; i < num_exchanges; i++) {
        wickr_key_exchange_t *one_exchange = wickr_array_fetch_item(exchange_set->exchanges, i, false);
        
        if (!one_exchange) {
            __wickr_key_exchange_proto_array_destroy(exchanges, num_exchanges);
            return NULL;
        }
        
        exchanges[i] = __wickr_key_exchange_to_proto(one_exchange);
        
        if (!exchanges[i]) {
            __wickr_key_exchange_proto_array_destroy(exchanges, num_exchanges);
            return NULL;
        }
    }
    
    Wickr__Proto__KeyExchangeSet *exchange_set_proto = wickr_alloc_zero(sizeof(Wickr__Proto__KeyExchangeSet));
    
    if (!exchange_set_proto) {
        __wickr_key_exchange_proto_array_destroy(exchanges, num_exchanges);
        return NULL;
    }
    
    wickr__proto__key_exchange_set__init(exchange_set_proto);
    
    exchange_set_proto->n_exchanges = num_exchanges;
    exchange_set_proto->exchanges = exchanges;
    exchange_set_proto->sender_pub.data = exchange_set->sender_pub->pub_data->bytes;
    exchange_set_proto->sender_pub.len = exchange_set->sender_pub->pub_data->length;
    
    return exchange_set_proto;
}

wickr_buffer_t *wickr_key_exchange_set_serialize(const wickr_key_exchange_set_t *exchange_set)
{
    if (!exchange_set) {
        return NULL;
    }
    
    Wickr__Proto__KeyExchangeSet *proto_exchange_set = __wickr_key_exchange_set_to_proto(exchange_set);
    
    if (!proto_exchange_set) {
        return NULL;
    }
    
    size_t required_size = wickr__proto__key_exchange_set__get_packed_size(proto_exchange_set);
    
    wickr_buffer_t *serialized_buffer = wickr_buffer_create_empty(required_size);
    
    if (!serialized_buffer) {
        __wickr_key_exchange_set_proto_free(proto_exchange_set);
        return NULL;
    }
    
    wickr__proto__key_exchange_set__pack(proto_exchange_set, serialized_buffer->bytes);
    __wickr_key_exchange_set_proto_free(proto_exchange_set);
    
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
    
    if (!proto_exchange_set) {
        return NULL;
    }
    
    wickr_key_exchange_set_t *exchange_set = __wickr_key_exchange_set_create_with_proto(proto_exchange_set, engine);
    wickr__proto__key_exchange_set__free_unpacked(proto_exchange_set, NULL);
    
    return exchange_set;
}

wickr_cipher_result_t *wickr_key_exchange_set_encrypt(const wickr_key_exchange_set_t *exchange_set,
                                                      const wickr_crypto_engine_t *engine,
                                                      const wickr_cipher_key_t *header_key)
{
    if (!exchange_set || !engine || !header_key) {
        return NULL;
    }
    
    wickr_buffer_t *serialized_exchange = wickr_key_exchange_set_serialize(exchange_set);
    
    if (!serialized_exchange) {
        return NULL;
    }
    
    wickr_cipher_result_t *cipher_result = engine->wickr_crypto_engine_cipher_encrypt(serialized_exchange, NULL, header_key, NULL);
    wickr_buffer_destroy_zero(&serialized_exchange);
    
    return cipher_result;
}

wickr_key_exchange_set_t *wickr_key_exchange_set_create_from_cipher(const wickr_crypto_engine_t *engine,
                                                                    const wickr_cipher_result_t *cipher_result,
                                                                    const wickr_cipher_key_t *header_key)
{
    if (!engine || !cipher_result || !header_key) {
        return NULL;
    }
    
    wickr_buffer_t *decrypted_exchange = engine->wickr_crypto_engine_cipher_decrypt(cipher_result, NULL, header_key, true);
    
    if (!decrypted_exchange) {
        return NULL;
    }
    
    wickr_key_exchange_set_t *deserialized_exchange = wickr_key_exchange_set_create_from_buffer(engine, decrypted_exchange);
    wickr_buffer_destroy(&decrypted_exchange);
    
    return deserialized_exchange;
}
