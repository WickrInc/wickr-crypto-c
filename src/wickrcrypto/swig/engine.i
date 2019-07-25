%module engine

%include "buffer.i"
%include "typemaps.i"
%include "cipher.i"
%include "eckey.i"
%include "ecdsa.i"
%include "digest.i"
%include "kdf.i"

%{
#include <wickrcrypto/crypto_engine.h>
%}

%immutable;

struct wickr_crypto_engine{
  
  %extend {

    %newobject random_bytes;
    %newobject random_key;
    %newobject cipher;
    %newobject decipher;
    %newobject rand_ec_key;
    %newobject import_ec_key;
    %newobject ec_sign;
    %newobject digest;
    %newobject ecdh_gen_key;
    %newobject kdf;
    %newobject kdf_salt;
    %newobject kdf_encrypt;
    %newobject kdf_decrypt; 


    static wickr_buffer_t *random_bytes(size_t len) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return engine.wickr_crypto_engine_crypto_random(len);
    }
    static wickr_cipher_key_t *random_key(wickr_cipher_t cipher) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return engine.wickr_crypto_engine_cipher_key_random(cipher);
    }
    static wickr_cipher_result_t *cipher(const wickr_buffer_t *plaintext, const wickr_buffer_t *aad, const wickr_cipher_key_t *key, const wickr_buffer_t *iv) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return engine.wickr_crypto_engine_cipher_encrypt(plaintext,aad,key,iv);
    }
    static wickr_buffer_t *decipher(const wickr_cipher_result_t *result, const wickr_buffer_t *aad, const wickr_cipher_key_t *key, bool onlyAuth) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return engine.wickr_crypto_engine_cipher_decrypt(result,aad,key,onlyAuth);
    }
    static wickr_ec_key_t *rand_ec_key(wickr_ec_curve_t curve) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return engine.wickr_crypto_engine_ec_rand_key(curve);
    }
    static wickr_ec_key_t *import_ec_key(const wickr_buffer_t *buffer, bool is_private) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return engine.wickr_crypto_engine_ec_key_import(buffer, is_private);
    }
    static wickr_ecdsa_result_t *ec_sign(const wickr_ec_key_t *ec_signing_key, const wickr_buffer_t *data_to_sign,const wickr_digest_t digest_mode) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return engine.wickr_crypto_engine_ec_sign(ec_signing_key, data_to_sign, digest_mode);
    }

    static bool ec_verify(const wickr_ecdsa_result_t *signature, const wickr_ec_key_t *ec_public_key, const wickr_buffer_t *data_to_verify) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return engine.wickr_crypto_engine_ec_verify(signature, ec_public_key, data_to_verify);
    }

    static wickr_buffer_t *digest(const wickr_buffer_t *buffer, const wickr_buffer_t *salt, wickr_digest_t digest_mode) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return engine.wickr_crypto_engine_digest(buffer,salt,digest_mode);
    }

    static wickr_buffer_t *ecdh_gen_shared_secret(const wickr_ec_key_t *local, wickr_ec_key_t *remote) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return engine.wickr_crypto_engine_gen_shared_secret(local, remote);
    }

    static wickr_buffer_t *kdf(wickr_kdf_algo_t algo, const wickr_buffer_t *passphrase) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      wickr_kdf_result_t *result = engine.wickr_crypto_kdf_gen(algo, passphrase);
      if (!result) {
        return NULL;
      }
      wickr_buffer_t *copy_out = wickr_buffer_copy(result->hash);
      wickr_kdf_result_destroy(&result);
      return copy_out;
    }

    static wickr_buffer_t *kdf_salt(const wickr_kdf_meta_t *existing_meta, const wickr_buffer_t *passphrase) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      wickr_kdf_result_t *result = engine.wickr_crypto_kdf_meta(existing_meta, passphrase);
      if (!result) {
        return NULL;
      }
      wickr_buffer_t *copy_out = wickr_buffer_copy(result->hash);
      wickr_kdf_result_destroy(&result);
      return copy_out;
    }

    static wickr_buffer_t *kdf_encrypt(wickr_kdf_algo_t algo, wickr_cipher_t cipher, const wickr_buffer_t *value, const wickr_buffer_t *passphrase) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return wickr_crypto_engine_kdf_cipher(&engine, algo, cipher, value, passphrase);
    }

    static wickr_buffer_t *kdf_decrypt(const wickr_buffer_t *input_buffer, const wickr_buffer_t *passphrase) {
      wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
      return wickr_crypto_engine_kdf_decipher(&engine, input_buffer, passphrase);
    }


  } 

};

%include "wickrcrypto/crypto_engine.h"