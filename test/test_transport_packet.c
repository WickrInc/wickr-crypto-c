
#include "test_transport_packet.h"
#include "transport_packet.h"
#include "externs.h"

bool wickr_transport_packet_meta_is_equal(wickr_transport_packet_meta_t a, wickr_transport_packet_meta_t b)
{
    if (a.body_type != b.body_type || a.mac_type != b.mac_type) {
        return false;
    }
    
    switch (a.body_type) {
        case TRANSPORT_PAYLOAD_TYPE_HANDSHAKE:
            return a.body_meta.handshake.flags == a.body_meta.handshake.flags ||
                a.body_meta.handshake.protocol_version == b.body_meta.handshake.protocol_version;
        case TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT:
            return a.body_meta.data.sequence_number == b.body_meta.data.sequence_number;
    }
}

bool wickr_transport_packet_is_equal(wickr_transport_packet_t *a, wickr_transport_packet_t *b)
{
    if (!a || !b) {
        return false;
    }
    
    if (!wickr_buffer_is_equal(a->body, b->body, NULL)) {
        return false;
    }
    
    if ((a->mac || b->mac) && !wickr_buffer_is_equal(a->mac, b->mac, NULL)) {
        return false;
    }
    
    return wickr_transport_packet_meta_is_equal(a->meta, b->meta);
}

void test_serialization(wickr_transport_packet_t *packet)
{
    /* Test serialization */
    wickr_buffer_t *serialized = wickr_transport_packet_serialize(packet);
    SHOULD_NOT_BE_NULL(serialized);
    
    wickr_transport_packet_t *deserialized = wickr_transport_packet_create_from_buffer(serialized);
    SHOULD_BE_TRUE(wickr_transport_packet_is_equal(deserialized, packet));
    SHOULD_BE_TRUE(wickr_buffer_is_equal(serialized, deserialized->network_buffer, NULL));
    
    /* Set up for verification */
    wickr_buffer_destroy(&packet->network_buffer);
    
    /* Cleanup */
    wickr_transport_packet_destroy(&deserialized);
    wickr_buffer_destroy(&serialized);
}

DESCRIBE(wickr_transport_packet_meta, "Wickr Transport Packet Metadata")
{
    
    wickr_transport_packet_meta_t test_handshake_meta;
    wickr_transport_packet_meta_t test_data_meta;
    
    IT("can be created for a handshake")
    {
        wickr_transport_packet_meta_initialize_handshake(&test_handshake_meta, 42, TRANSPORT_MAC_TYPE_EC_P521);
        SHOULD_EQUAL(test_handshake_meta.body_type, TRANSPORT_PAYLOAD_TYPE_HANDSHAKE);
        SHOULD_EQUAL(test_handshake_meta.mac_type, TRANSPORT_MAC_TYPE_EC_P521);
        SHOULD_EQUAL(test_handshake_meta.body_meta.handshake.flags, 0);
        SHOULD_EQUAL(test_handshake_meta.body_meta.handshake.protocol_version, 42);
    }
    END_IT
    
    IT("can be created for a data packet")
    {
        wickr_transport_packet_meta_initialize_data(&test_data_meta, 42, TRANSPORT_MAC_TYPE_AUTH_CIPHER);
        SHOULD_EQUAL(test_data_meta.body_type, TRANSPORT_PAYLOAD_TYPE_CIPHERTEXT);
        SHOULD_EQUAL(test_data_meta.mac_type, TRANSPORT_MAC_TYPE_AUTH_CIPHER);
        SHOULD_EQUAL(test_data_meta.body_meta.data.sequence_number, 42);
    }
    END_IT
    
    IT("can be serialized and restored")
    {
        /* Verify that null inputs are propertly handled */
        SHOULD_BE_NULL(wickr_transport_packet_meta_serialize(NULL));
        
        /* Serialize the metadata objects */
        wickr_buffer_t *serialized_test_handshake_meta = wickr_transport_packet_meta_serialize(&test_handshake_meta);
        SHOULD_NOT_BE_NULL(serialized_test_handshake_meta);
        
        wickr_buffer_t *serialized_test_data_meta = wickr_transport_packet_meta_serialize(&test_data_meta);
        SHOULD_NOT_BE_NULL(serialized_test_data_meta);
        
        /* Reconstruct the metadata objects and verify they are equal to the originals */
        
        wickr_transport_packet_meta_t restored_handshake_meta;
        int processed_length = wickr_transport_packet_meta_initialize_buffer(&restored_handshake_meta, serialized_test_handshake_meta);
        SHOULD_EQUAL(processed_length, serialized_test_handshake_meta->length);
        SHOULD_BE_TRUE(wickr_transport_packet_meta_is_equal(restored_handshake_meta, test_handshake_meta));
        
        wickr_transport_packet_meta_t restored_data_meta;
        processed_length = wickr_transport_packet_meta_initialize_buffer(&restored_data_meta, serialized_test_data_meta);
        SHOULD_EQUAL(processed_length, serialized_test_data_meta->length);
        SHOULD_BE_TRUE(wickr_transport_packet_meta_is_equal(restored_data_meta, test_data_meta));
        
        /* Verify that a corrupt buffer will fail gracefully */
        wickr_buffer_t *bad_data = wickr_buffer_create((uint8_t *)"baddata", 3);
        processed_length = wickr_transport_packet_meta_initialize_buffer(&restored_data_meta, bad_data);
        SHOULD_BE_TRUE(processed_length < 0);
        SHOULD_BE_TRUE(wickr_transport_packet_meta_initialize_buffer(&restored_data_meta, NULL) < 0);
        
        /* Cleanup */
        wickr_buffer_destroy(&bad_data);
        wickr_buffer_destroy(&serialized_test_handshake_meta);
        wickr_buffer_destroy(&serialized_test_data_meta);
    }
    END_IT
}
END_DESCRIBE

DESCRIBE(wickr_transport_packet, "Wickr Transport Packet")
{
    const wickr_crypto_engine_t test_engine = wickr_crypto_engine_get_default();
    wickr_transport_packet_meta_t test_meta;
    wickr_transport_packet_meta_initialize_data(&test_meta, 42, TRANSPORT_MAC_TYPE_NONE);
    
    wickr_identity_chain_t *test_id_chain = createIdentityChain("alice");
    wickr_buffer_t *test_buffer = test_engine.wickr_crypto_engine_crypto_random(32);
    wickr_transport_packet_t *test_packet = NULL;
    
    IT("can be created with a buffer and metadata")
    {
        /* Test missing dependencies */
        SHOULD_BE_NULL(wickr_transport_packet_create(test_meta, NULL));
        
        /* Test creation */
        test_packet = wickr_transport_packet_create(test_meta, test_buffer);
        SHOULD_NOT_BE_NULL(test_packet);
        SHOULD_EQUAL(test_buffer, test_packet->body);
        SHOULD_BE_NULL(test_packet->network_buffer);
        SHOULD_BE_TRUE(wickr_transport_packet_meta_is_equal(test_meta, test_packet->meta));
    }
    END_IT
    
    IT("can be copied (base case)")
    {
        SHOULD_BE_NULL(wickr_transport_packet_copy(NULL));
        wickr_transport_packet_t *copy = wickr_transport_packet_copy(test_packet);
        SHOULD_BE_TRUE(wickr_transport_packet_is_equal(copy, test_packet));
        SHOULD_NOT_EQUAL(copy->body, test_packet->body);
        wickr_transport_packet_destroy(&copy);
    }
    END_IT
    
    IT("can be serialized (base case)")
    {
        /* Test bad inputs */
        SHOULD_BE_NULL(wickr_transport_packet_serialize(NULL));
        
        /* Test serialization */
        test_serialization(test_packet);
    }
    END_IT
    
    IT("can be signed")
    {
        /* Test bad inputs */
        SHOULD_BE_FALSE(wickr_transport_packet_sign(NULL, &test_engine, test_id_chain));
        SHOULD_BE_FALSE(wickr_transport_packet_sign(test_packet, NULL, test_id_chain));
        SHOULD_BE_FALSE(wickr_transport_packet_sign(test_packet, &test_engine, NULL));
        
        /* Test signature */
        SHOULD_BE_TRUE(wickr_transport_packet_sign(test_packet, &test_engine, test_id_chain));
        SHOULD_NOT_BE_NULL(test_packet->mac);
        SHOULD_EQUAL(TRANSPORT_MAC_TYPE_EC_P521, test_packet->meta.mac_type);
    }
    END_IT
    
    IT("can be copied (signed case)")
    {
        wickr_transport_packet_t *copy = wickr_transport_packet_copy(test_packet);
        SHOULD_BE_TRUE(wickr_transport_packet_is_equal(copy, test_packet));
        SHOULD_NOT_EQUAL(copy->mac, test_packet->mac);
        SHOULD_NOT_EQUAL(copy->body, test_packet->body);
        wickr_transport_packet_destroy(&copy);
    }
    END_IT
    
    IT("can be serialized / deserialized (signed case)")
    {
        test_serialization(test_packet);
    }
    END_IT
    
    IT("can be verified")
    {
        /* Test bad inputs */
        SHOULD_BE_FALSE(wickr_transport_packet_verify(NULL, &test_engine, test_id_chain));
        SHOULD_BE_FALSE(wickr_transport_packet_verify(test_packet, NULL, test_id_chain));
        SHOULD_BE_FALSE(wickr_transport_packet_verify(test_packet, &test_engine, NULL));
        
        /* Test verification with proper key */
        SHOULD_BE_TRUE(wickr_transport_packet_verify(test_packet, &test_engine, test_id_chain));
        
        /* Test verification with incorrect key */
        wickr_identity_chain_t *bad_identity = createIdentityChain("bob");
        SHOULD_NOT_BE_NULL(bad_identity);
        SHOULD_BE_FALSE(wickr_transport_packet_verify(test_packet, &test_engine, bad_identity));
        
        /* Test verification with modified data */
        SHOULD_BE_TRUE(wickr_buffer_modify_section(test_packet->network_buffer, (uint8_t *)"bad", 0, 3));
        SHOULD_BE_FALSE(wickr_transport_packet_verify(test_packet, &test_engine, test_id_chain));
        
        /* Test verification with invalid chain */
        wickr_identity_destroy(&test_id_chain->root);
        test_id_chain->root = wickr_identity_copy(bad_identity->root);
        SHOULD_NOT_BE_NULL(bad_identity->root);
        SHOULD_BE_FALSE(wickr_transport_packet_verify(test_packet, &test_engine, test_id_chain));
        
        /* Cleanup */
        wickr_identity_chain_destroy(&bad_identity);
    }
    END_IT
    
    IT("can be cleaned up")
    {
        wickr_transport_packet_destroy(&test_packet);
        SHOULD_BE_NULL(test_packet);
    }
    END_IT
    
    wickr_identity_chain_destroy(&test_id_chain);
    
}
END_DESCRIBE
