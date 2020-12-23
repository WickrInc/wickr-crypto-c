/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: stream.proto */

#ifndef PROTOBUF_C_stream_2eproto__INCLUDED
#define PROTOBUF_C_stream_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "identity.pb-c.h"

typedef struct _Wickr__Proto__HandshakeV1 Wickr__Proto__HandshakeV1;
typedef struct _Wickr__Proto__HandshakeV1__Seed Wickr__Proto__HandshakeV1__Seed;
typedef struct _Wickr__Proto__HandshakeV1__Response Wickr__Proto__HandshakeV1__Response;
typedef struct _Wickr__Proto__HandshakeV1ResponseData Wickr__Proto__HandshakeV1ResponseData;
typedef struct _Wickr__Proto__TransportRootKey Wickr__Proto__TransportRootKey;
typedef struct _Wickr__Proto__StreamKey Wickr__Proto__StreamKey;


/* --- enums --- */


/* --- messages --- */

struct  _Wickr__Proto__HandshakeV1__Seed
{
  ProtobufCMessage base;
  Wickr__Proto__IdentityChain *id_chain;
  protobuf_c_boolean has_ephemeral_pubkey;
  ProtobufCBinaryData ephemeral_pubkey;
  protobuf_c_boolean has_identity_required;
  protobuf_c_boolean identity_required;
};
#define WICKR__PROTO__HANDSHAKE_V1__SEED__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wickr__proto__handshake_v1__seed__descriptor) \
    , NULL, 0, {0,NULL}, 0, 0 }


struct  _Wickr__Proto__HandshakeV1__Response
{
  ProtobufCMessage base;
  protobuf_c_boolean has_ephemeral_pubkey;
  ProtobufCBinaryData ephemeral_pubkey;
  protobuf_c_boolean has_encrypted_response_data;
  ProtobufCBinaryData encrypted_response_data;
  Wickr__Proto__IdentityChain *id_chain;
  protobuf_c_boolean has_kem_ctx;
  ProtobufCBinaryData kem_ctx;
};
#define WICKR__PROTO__HANDSHAKE_V1__RESPONSE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wickr__proto__handshake_v1__response__descriptor) \
    , 0, {0,NULL}, 0, {0,NULL}, NULL, 0, {0,NULL} }


typedef enum {
  WICKR__PROTO__HANDSHAKE_V1__PAYLOAD__NOT_SET = 0,
  WICKR__PROTO__HANDSHAKE_V1__PAYLOAD_SEED = 2,
  WICKR__PROTO__HANDSHAKE_V1__PAYLOAD_RESPONSE = 3
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(WICKR__PROTO__HANDSHAKE_V1__PAYLOAD)
} Wickr__Proto__HandshakeV1__PayloadCase;

struct  _Wickr__Proto__HandshakeV1
{
  ProtobufCMessage base;
  Wickr__Proto__HandshakeV1__PayloadCase payload_case;
  union {
    Wickr__Proto__HandshakeV1__Seed *seed;
    Wickr__Proto__HandshakeV1__Response *response;
  };
};
#define WICKR__PROTO__HANDSHAKE_V1__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wickr__proto__handshake_v1__descriptor) \
    , WICKR__PROTO__HANDSHAKE_V1__PAYLOAD__NOT_SET, {0} }


struct  _Wickr__Proto__HandshakeV1ResponseData
{
  ProtobufCMessage base;
  Wickr__Proto__TransportRootKey *root_key;
};
#define WICKR__PROTO__HANDSHAKE_V1_RESPONSE_DATA__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wickr__proto__handshake_v1_response_data__descriptor) \
    , NULL }


struct  _Wickr__Proto__TransportRootKey
{
  ProtobufCMessage base;
  protobuf_c_boolean has_secret;
  ProtobufCBinaryData secret;
  protobuf_c_boolean has_cipher_id;
  uint32_t cipher_id;
  protobuf_c_boolean has_packets_per_evo_send;
  uint32_t packets_per_evo_send;
  protobuf_c_boolean has_packets_per_evo_recv;
  uint32_t packets_per_evo_recv;
};
#define WICKR__PROTO__TRANSPORT_ROOT_KEY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wickr__proto__transport_root_key__descriptor) \
    , 0, {0,NULL}, 0, 0, 0, 0, 0, 0 }


struct  _Wickr__Proto__StreamKey
{
  ProtobufCMessage base;
  protobuf_c_boolean has_cipher_key;
  ProtobufCBinaryData cipher_key;
  protobuf_c_boolean has_evolution_key;
  ProtobufCBinaryData evolution_key;
  protobuf_c_boolean has_packets_per_evo;
  uint32_t packets_per_evo;
  protobuf_c_boolean has_user_data;
  ProtobufCBinaryData user_data;
};
#define WICKR__PROTO__STREAM_KEY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wickr__proto__stream_key__descriptor) \
    , 0, {0,NULL}, 0, {0,NULL}, 0, 0, 0, {0,NULL} }


/* Wickr__Proto__HandshakeV1__Seed methods */
void   wickr__proto__handshake_v1__seed__init
                     (Wickr__Proto__HandshakeV1__Seed         *message);
/* Wickr__Proto__HandshakeV1__Response methods */
void   wickr__proto__handshake_v1__response__init
                     (Wickr__Proto__HandshakeV1__Response         *message);
/* Wickr__Proto__HandshakeV1 methods */
void   wickr__proto__handshake_v1__init
                     (Wickr__Proto__HandshakeV1         *message);
size_t wickr__proto__handshake_v1__get_packed_size
                     (const Wickr__Proto__HandshakeV1   *message);
size_t wickr__proto__handshake_v1__pack
                     (const Wickr__Proto__HandshakeV1   *message,
                      uint8_t             *out);
size_t wickr__proto__handshake_v1__pack_to_buffer
                     (const Wickr__Proto__HandshakeV1   *message,
                      ProtobufCBuffer     *buffer);
Wickr__Proto__HandshakeV1 *
       wickr__proto__handshake_v1__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wickr__proto__handshake_v1__free_unpacked
                     (Wickr__Proto__HandshakeV1 *message,
                      ProtobufCAllocator *allocator);
/* Wickr__Proto__HandshakeV1ResponseData methods */
void   wickr__proto__handshake_v1_response_data__init
                     (Wickr__Proto__HandshakeV1ResponseData         *message);
size_t wickr__proto__handshake_v1_response_data__get_packed_size
                     (const Wickr__Proto__HandshakeV1ResponseData   *message);
size_t wickr__proto__handshake_v1_response_data__pack
                     (const Wickr__Proto__HandshakeV1ResponseData   *message,
                      uint8_t             *out);
size_t wickr__proto__handshake_v1_response_data__pack_to_buffer
                     (const Wickr__Proto__HandshakeV1ResponseData   *message,
                      ProtobufCBuffer     *buffer);
Wickr__Proto__HandshakeV1ResponseData *
       wickr__proto__handshake_v1_response_data__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wickr__proto__handshake_v1_response_data__free_unpacked
                     (Wickr__Proto__HandshakeV1ResponseData *message,
                      ProtobufCAllocator *allocator);
/* Wickr__Proto__TransportRootKey methods */
void   wickr__proto__transport_root_key__init
                     (Wickr__Proto__TransportRootKey         *message);
size_t wickr__proto__transport_root_key__get_packed_size
                     (const Wickr__Proto__TransportRootKey   *message);
size_t wickr__proto__transport_root_key__pack
                     (const Wickr__Proto__TransportRootKey   *message,
                      uint8_t             *out);
size_t wickr__proto__transport_root_key__pack_to_buffer
                     (const Wickr__Proto__TransportRootKey   *message,
                      ProtobufCBuffer     *buffer);
Wickr__Proto__TransportRootKey *
       wickr__proto__transport_root_key__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wickr__proto__transport_root_key__free_unpacked
                     (Wickr__Proto__TransportRootKey *message,
                      ProtobufCAllocator *allocator);
/* Wickr__Proto__StreamKey methods */
void   wickr__proto__stream_key__init
                     (Wickr__Proto__StreamKey         *message);
size_t wickr__proto__stream_key__get_packed_size
                     (const Wickr__Proto__StreamKey   *message);
size_t wickr__proto__stream_key__pack
                     (const Wickr__Proto__StreamKey   *message,
                      uint8_t             *out);
size_t wickr__proto__stream_key__pack_to_buffer
                     (const Wickr__Proto__StreamKey   *message,
                      ProtobufCBuffer     *buffer);
Wickr__Proto__StreamKey *
       wickr__proto__stream_key__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wickr__proto__stream_key__free_unpacked
                     (Wickr__Proto__StreamKey *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Wickr__Proto__HandshakeV1__Seed_Closure)
                 (const Wickr__Proto__HandshakeV1__Seed *message,
                  void *closure_data);
typedef void (*Wickr__Proto__HandshakeV1__Response_Closure)
                 (const Wickr__Proto__HandshakeV1__Response *message,
                  void *closure_data);
typedef void (*Wickr__Proto__HandshakeV1_Closure)
                 (const Wickr__Proto__HandshakeV1 *message,
                  void *closure_data);
typedef void (*Wickr__Proto__HandshakeV1ResponseData_Closure)
                 (const Wickr__Proto__HandshakeV1ResponseData *message,
                  void *closure_data);
typedef void (*Wickr__Proto__TransportRootKey_Closure)
                 (const Wickr__Proto__TransportRootKey *message,
                  void *closure_data);
typedef void (*Wickr__Proto__StreamKey_Closure)
                 (const Wickr__Proto__StreamKey *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor wickr__proto__handshake_v1__descriptor;
extern const ProtobufCMessageDescriptor wickr__proto__handshake_v1__seed__descriptor;
extern const ProtobufCMessageDescriptor wickr__proto__handshake_v1__response__descriptor;
extern const ProtobufCMessageDescriptor wickr__proto__handshake_v1_response_data__descriptor;
extern const ProtobufCMessageDescriptor wickr__proto__transport_root_key__descriptor;
extern const ProtobufCMessageDescriptor wickr__proto__stream_key__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_stream_2eproto__INCLUDED */
