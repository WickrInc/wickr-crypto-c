%module wickr_ctx

%include dev_info.i
%include identity.i

%{
#include <wickrcrypto/node.h> 
%}

#if defined(SWIGJAVA)
%typemap(javaout) SWIGTYPE *id_chain, SWIGTYPE *ephemeral_keypair {
  long cPtr = $jnicall;
    return (cPtr == 0) ? null : new $javaclassname(cPtr, $owner, this);
}
#elif defined(SWIGJAVASCRIPT)
%typemap(ret) SWIGTYPE *id_chain, SWIGTYPE *ephemeral_keypair {
  if (jsresult->IsObject() && jsresult->ToObject()->Set(SWIGV8_CURRENT_CONTEXT(), SWIGV8_SYMBOL_NEW("parent"), info.Holder()).IsNothing()) {
    SWIG_exception_fail(SWIG_ERROR, "Could not set parent object for getter");
  }
}
#endif

%immutable;

%ignore wickr_node_create;
%ignore wickr_node_rotate_keypair;
%ignore wickr_node_copy;
%ignore wickr_node_destroy;
%ignore wickr_node_verify_signature_chain;
%ignore wickr_node_array_new;
%ignore wickr_node_array_set_item;
%ignore wickr_node_array_fetch_item;
%ignore wickr_node_array_copy;
%ignore wickr_node_array_destroy;
%ignore wickr_node_serialize;
%ignore wickr_node_from_buffer;

%include "wickrcrypto/node.h"

%extend struct wickr_node {

	~wickr_node() {
		wickr_node_destroy(&$self);
	}

	%newobject from_values;
  %newobject serialize;

 	static wickr_node_t *from_values(wickr_buffer_t *dev_id, wickr_identity_chain_t *id_chain, wickr_ephemeral_keypair_t *ephemeral_keypair) {
 		wickr_identity_chain_t *id_chain_copy = wickr_identity_chain_copy(id_chain);
 		wickr_ephemeral_keypair_t *keypair_copy = wickr_ephemeral_keypair_copy(ephemeral_keypair);
 		wickr_node_t *node = wickr_node_create(dev_id, id_chain_copy, keypair_copy);

 		if (!node) {
 			wickr_identity_chain_destroy(&id_chain_copy);
 			wickr_ephemeral_keypair_destroy(&keypair_copy);
 		}

 		return node;
 	}

  static wickr_node_t *from_buffer(const wickr_buffer_t *buffer) {
    const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    return wickr_node_create_from_buffer(buffer, &engine);
  }

 	bool set_keypair(wickr_ephemeral_keypair_t *new_keypair) {
 		return wickr_node_rotate_keypair($self, new_keypair, true);
 	}

 	bool verify() {
 		wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
 		return wickr_node_verify_signature_chain($self, &engine);
 	}

  wickr_buffer_t *serialize();

};

%include wickr_array.i

%extend struct wickr_array {

  %newobject allocate_node;
  %newobject get_node;

  static wickr_array_t *allocate_node(uint32_t count) {
    return wickr_node_array_new(count);
  }

  wickr_node_t *get_node(uint32_t index) {
    return (wickr_node_t *)wickr_array_fetch_item($self, index, true);
  }

  bool set_node(uint32_t index, wickr_node_t *node) {
    return wickr_array_set_item($self, index, node, true);
  }

}