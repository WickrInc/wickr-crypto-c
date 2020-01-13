
#if defined(SWIGJAVASCRIPT)

%module transport

%include engine.i
%include node.i
%include engine.i

%{
#include <wickrcrypto/transport_ctx.h>
%}

%include transport_callbacks.i

%immutable;

%ignore wickr_transport_ctx_create;
%ignore wickr_transport_ctx_copy;
%ignore wickr_transport_ctx_destroy;
%ignore wickr_transport_ctx_start;
%ignore wickr_transport_ctx_process_tx_buffer;
%ignore wickr_transport_ctx_process_rx_buffer;
%ignore wickr_transport_ctx_get_status;
%ignore wickr_transport_ctx_get_rxstream_user_data;
%ignore wickr_transport_ctx_get_local_node_ptr;
%ignore wickr_transport_ctx_get_remote_node_ptr;
%ignore wickr_transport_ctx_get_user_ctx;
%ignore wickr_transport_ctx_set_user_ctx;
%ignore wickr_transport_ctx_get_user_psk;
%ignore wickr_transport_ctx_get_data_flow_mode;
%ignore wickr_transport_ctx_set_data_flow_mode;
%ignore wickr_transport_ctx_get_callbacks;
%ignore wickr_transport_ctx_set_callbacks;
%ignore wickr_transport_ctx_force_tx_key_evo;

%nodefaultctor wickr_transport_ctx;
%nodefaultdtor wickr_transport_ctx;

struct wickr_transport_ctx { };

%include "wickrcrypto/transport_ctx.h"

%extend struct wickr_transport_ctx {

  ~wickr_transport_ctx() {
    #if defined(SWIGJAVASCRIPT)
      auto obj = (Persistent<Object> *)wickr_transport_ctx_get_user_ctx($self);
      obj->Reset();
      delete obj;
    #endif
    wickr_transport_ctx_destroy(&$self);
  }

  %newobject create_transport;
  %newobject process_tx_buffer;
  %newobject process_rx_buffer;

  static wickr_transport_ctx_t *create_transport(wickr_node_t *local_identity, wickr_node_t *remote_identity, wickr_transport_callbacks_t callbacks, void *user_data) {
   
    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    wickr_node_t *local_copy = wickr_node_copy(local_identity);
    wickr_node_t *remote_copy = wickr_node_copy(remote_identity);
    
    wickr_transport_ctx_t *transport = wickr_transport_ctx_create(engine, local_copy, remote_copy, 0, callbacks, user_data);

    if (!transport) {
      wickr_node_destroy(&local_copy);
      wickr_node_destroy(&remote_copy);
    }

    return transport;
  }

  void start();
  wickr_buffer_t *process_tx_buffer(const wickr_buffer_t *buffer);
  wickr_buffer_t *process_rx_buffer(const wickr_buffer_t *buffer);
  wickr_transport_status get_status();

};

#endif