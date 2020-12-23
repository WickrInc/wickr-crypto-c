/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: identity.proto */

#ifndef PROTOBUF_C_identity_2eproto__INCLUDED
#define PROTOBUF_C_identity_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _Wickr__Proto__Identity Wickr__Proto__Identity;
typedef struct _Wickr__Proto__IdentityChain Wickr__Proto__IdentityChain;


/* --- enums --- */

typedef enum _Wickr__Proto__Identity__Type {
  WICKR__PROTO__IDENTITY__TYPE__IDENTITY_TYPE_ROOT = 0,
  WICKR__PROTO__IDENTITY__TYPE__IDENTITY_TYPE_NODE = 1
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(WICKR__PROTO__IDENTITY__TYPE)
} Wickr__Proto__Identity__Type;

/* --- messages --- */

struct  _Wickr__Proto__Identity
{
  ProtobufCMessage base;
  protobuf_c_boolean has_identifier;
  ProtobufCBinaryData identifier;
  protobuf_c_boolean has_sig_key;
  ProtobufCBinaryData sig_key;
  protobuf_c_boolean has_signature;
  ProtobufCBinaryData signature;
  protobuf_c_boolean has_type;
  Wickr__Proto__Identity__Type type;
  protobuf_c_boolean has_is_private;
  protobuf_c_boolean is_private;
};
#define WICKR__PROTO__IDENTITY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wickr__proto__identity__descriptor) \
    , 0, {0,NULL}, 0, {0,NULL}, 0, {0,NULL}, 0, WICKR__PROTO__IDENTITY__TYPE__IDENTITY_TYPE_ROOT, 0, 0 }


struct  _Wickr__Proto__IdentityChain
{
  ProtobufCMessage base;
  Wickr__Proto__Identity *root;
  Wickr__Proto__Identity *node;
};
#define WICKR__PROTO__IDENTITY_CHAIN__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wickr__proto__identity_chain__descriptor) \
    , NULL, NULL }


/* Wickr__Proto__Identity methods */
void   wickr__proto__identity__init
                     (Wickr__Proto__Identity         *message);
size_t wickr__proto__identity__get_packed_size
                     (const Wickr__Proto__Identity   *message);
size_t wickr__proto__identity__pack
                     (const Wickr__Proto__Identity   *message,
                      uint8_t             *out);
size_t wickr__proto__identity__pack_to_buffer
                     (const Wickr__Proto__Identity   *message,
                      ProtobufCBuffer     *buffer);
Wickr__Proto__Identity *
       wickr__proto__identity__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wickr__proto__identity__free_unpacked
                     (Wickr__Proto__Identity *message,
                      ProtobufCAllocator *allocator);
/* Wickr__Proto__IdentityChain methods */
void   wickr__proto__identity_chain__init
                     (Wickr__Proto__IdentityChain         *message);
size_t wickr__proto__identity_chain__get_packed_size
                     (const Wickr__Proto__IdentityChain   *message);
size_t wickr__proto__identity_chain__pack
                     (const Wickr__Proto__IdentityChain   *message,
                      uint8_t             *out);
size_t wickr__proto__identity_chain__pack_to_buffer
                     (const Wickr__Proto__IdentityChain   *message,
                      ProtobufCBuffer     *buffer);
Wickr__Proto__IdentityChain *
       wickr__proto__identity_chain__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wickr__proto__identity_chain__free_unpacked
                     (Wickr__Proto__IdentityChain *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Wickr__Proto__Identity_Closure)
                 (const Wickr__Proto__Identity *message,
                  void *closure_data);
typedef void (*Wickr__Proto__IdentityChain_Closure)
                 (const Wickr__Proto__IdentityChain *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor wickr__proto__identity__descriptor;
extern const ProtobufCEnumDescriptor    wickr__proto__identity__type__descriptor;
extern const ProtobufCMessageDescriptor wickr__proto__identity_chain__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_identity_2eproto__INCLUDED */
