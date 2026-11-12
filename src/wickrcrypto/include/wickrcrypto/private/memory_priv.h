#ifndef memory_priv_h
#define memory_priv_h

#include <protobuf-c/protobuf-c.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Allocator for protobuf-c unpack/free_unpacked, so deserialized messages (which can hold raw
   key bytes) are freed through wickr_free and zeroed with WICKR_SECURE_MEMORY */
extern ProtobufCAllocator wickr_protobuf_allocator;

#ifdef __cplusplus
}
#endif

#endif /* memory_priv_h */
