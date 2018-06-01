%module cipher

%{
#include <wickrcrypto/cipher.h>	
%}

%ignore CIPHER_AES256_GCM;
%ignore CIPHER_AES256_CTR;
%ignore wickr_cipher_find;
%ignore wickr_cipher_result_create;
%ignore wickr_cipher_result_copy;
%ignore wickr_cipher_result_destroy;
%ignore wickr_cipher_result_create;
%ignore wickr_cipher_key_copy;
%ignore wickr_cipher_key_destroy;
%ignore wickr_cipher_result_serialize;
%ignore wickr_cipher_result_from_buffer;
%ignore wickr_cipher_key_serialize;
%ignore wickr_cipher_key_from_buffer;
%ignore wickr_cipher_result_is_valid;

%nodefaultctor wickr_cipher;
%nodefaultdtor wickr_cipher;

%immutable;

%include "wickrcrypto/cipher.h"

%extend struct wickr_cipher {
  static const wickr_cipher_t *aes256_gcm() {
    return &CIPHER_AES256_GCM;
  }
  static const wickr_cipher_t *aes256_ctr() {
    return &CIPHER_AES256_CTR;
  }
}

%extend struct wickr_cipher_result{

 ~wickr_cipher_result() {
   wickr_cipher_result_destroy(&$self);
 }
 bool is_valid();

 %newobject from_buffer;
 %newobject serialize;

 wickr_buffer_t *serialize();
 static wickr_cipher_result_t *from_buffer(const wickr_buffer_t *buffer);
};

%extend struct wickr_cipher_key{

 ~wickr_cipher_key() {
  wickr_cipher_key_destroy(&$self);
 }
 
 %newobject serialize;
 %newobject from_buffer;
 %newobject from_components;

 wickr_buffer_t *serialize();

 static wickr_cipher_key_t *from_components(wickr_cipher_t cipher, wickr_buffer_t *key_data) {
   return wickr_cipher_key_create(cipher, key_data);
 }

 static wickr_cipher_key_t *from_buffer(const wickr_buffer_t *buffer);
};
