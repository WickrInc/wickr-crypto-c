/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: node.proto */

#ifndef PROTOBUF_C_node_2eproto__INCLUDED
#define PROTOBUF_C_node_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "identity.pb-c.h"
#include "ephemeral_keypair.pb-c.h"

typedef struct _Wickr__Proto__Node Wickr__Proto__Node;


/* --- enums --- */


/* --- messages --- */

struct  _Wickr__Proto__Node
{
  ProtobufCMessage base;
  protobuf_c_boolean has_devid;
  ProtobufCBinaryData devid;
  Wickr__Proto__IdentityChain *id_chain;
  Wickr__Proto__EphemeralKeypair *ephemeral_keypair;
};
#define WICKR__PROTO__NODE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wickr__proto__node__descriptor) \
    , 0, {0,NULL}, NULL, NULL }


/* Wickr__Proto__Node methods */
void   wickr__proto__node__init
                     (Wickr__Proto__Node         *message);
size_t wickr__proto__node__get_packed_size
                     (const Wickr__Proto__Node   *message);
size_t wickr__proto__node__pack
                     (const Wickr__Proto__Node   *message,
                      uint8_t             *out);
size_t wickr__proto__node__pack_to_buffer
                     (const Wickr__Proto__Node   *message,
                      ProtobufCBuffer     *buffer);
Wickr__Proto__Node *
       wickr__proto__node__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wickr__proto__node__free_unpacked
                     (Wickr__Proto__Node *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Wickr__Proto__Node_Closure)
                 (const Wickr__Proto__Node *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor wickr__proto__node__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_node_2eproto__INCLUDED */
