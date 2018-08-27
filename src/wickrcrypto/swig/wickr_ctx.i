%module wickr_ctx

%include dev_info.i
%include identity.i
%include storage_keys.i

%{
#include <wickrcrypto/wickr_ctx.h>
%}

#if defined(SWIGJAVA)
%typemap(javaout) SWIGTYPE *dev_info, SWIGTYPE *id_chain, SWIGTYPE *storage_keys, SWIGTYPE *packet_header_key, SWIGTYPE *recovery_key, SWIGTYPE *ctx, SWIGTYPE *root_keys, SWIGTYPE *recovery_key, SWIGTYPE *packet, SWIGTYPE *sender, SWIGTYPE *parse_result, SWIGTYPE *packet_key, SWIGTYPE *encoded_packet, SWIGTYPE *meta, SWIGTYPE *signature, SWIGTYPE *header, SWIGTYPE *key_exchange, SWIGTYPE *enc_payload, SWIGTYPE *payload_key, SWIGTYPE *decrypted_payload {
	long cPtr = $jnicall;
    return (cPtr == 0) ? null : new $javaclassname(cPtr, $owner, this);
}
#elif defined(SWIGJAVASCRIPT)
%typemap(ret) SWIGTYPE *dev_info, SWIGTYPE *id_chain, SWIGTYPE *storage_keys, SWIGTYPE *packet_header_key, SWIGTYPE *recovery_key, SWIGTYPE *ctx, SWIGTYPE *root_keys, SWIGTYPE *recovery_key, SWIGTYPE *packet, SWIGTYPE *sender, SWIGTYPE *parse_result, SWIGTYPE *packet_key, SWIGTYPE *encoded_packet, SWIGTYPE *meta, SWIGTYPE *signature, SWIGTYPE *header, SWIGTYPE *key_exchange, SWIGTYPE *enc_payload, SWIGTYPE *payload_key, SWIGTYPE *decrypted_payload {
    if (jsresult->IsObject() && jsresult->ToObject()->Set(SWIGV8_CURRENT_CONTEXT(), SWIGV8_SYMBOL_NEW("parent"), info.Holder()).IsNothing()) {
        SWIG_exception_fail(SWIG_ERROR, "Could not set parent object for getter");
    }
}
#endif

%immutable;

%ignore wickr_ctx_gen_new;
%ignore wickr_ctx_gen_new_with_sig_key;
%ignore wickr_ctx_gen_with_root_keys;
%ignore wickr_ctx_gen_with_passphrase;
%ignore wickr_ctx_gen_with_recovery;
%ignore wickr_ctx_gen_export_recovery_key_passphrase;
%ignore wickr_ctx_gen_import_recovery_key_passphrase;
%ignore wickr_ctx_gen_result_make_recovery;
%ignore wickr_ctx_gen_import_recovery;
%ignore wickr_ctx_gen_result_copy;
%ignore wickr_ctx_gen_result_destroy;
%ignore wickr_ctx_create;
%ignore wickr_ctx_copy;
%ignore wickr_ctx_destroy;
%ignore wickr_ctx_export_storage_keys;
%ignore wickr_ctx_import_storage_keys;
%ignore wickr_ctx_cipher_local;
%ignore wickr_ctx_decipher_local;
%ignore wickr_ctx_cipher_remote;
%ignore wickr_ctx_decipher_remote;
%ignore wickr_ctx_ephemeral_keypair_gen;
%ignore wickr_ctx_packet_create;
%ignore wickr_ctx_packet_destroy;
%ignore wickr_ctx_encode_create;
%ignore wickr_ctx_encode_destroy;
%ignore wickr_ctx_encode_packet;
%ignore wickr_ctx_parse_packet;
%ignore wickr_ctx_parse_packet_no_decode;
%ignore wickr_ctx_decode_packet;
%ignore wickr_ctx_serialize;
%ignore wickr_ctx_export;
%ignore wickr_ctx_import;
%ignore wickr_ctx_create_from_buffer;
%ignore wickr_packet_meta_create;
%ignore wickr_packet_meta_copy;
%ignore wickr_packet_meta_destroy;
%ignore wickr_key_exchange_create_with_packet_key;
%ignore wickr_key_exchange_create_with_data;
%ignore wickr_key_exchange_derive_packet_key;
%ignore wickr_key_exchange_derive_data;
%ignore wickr_packet_header_encrypt;
%ignore wickr_packet_header_create_from_cipher;
%ignore wickr_payload_create;
%ignore wickr_payload_copy;
%ignore wickr_payload_destroy;
%ignore wickr_key_exchange_set_encrypt;
%ignore wickr_key_exchange_set_create_from_cipher;
%ignore wickr_packet_create;
%ignore wickr_packet_create_from_buffer;
%ignore wickr_packet_serialize;
%ignore wickr_packet_copy;
%ignore wickr_packet_destroy;
%ignore wickr_parse_result_create_failure;
%ignore wickr_parse_result_create_success;
%ignore wickr_parse_result_copy;
%ignore wickr_parse_result_destroy;
%ignore wickr_decode_result_create_failure;
%ignore wickr_decode_result_create_success;
%ignore wickr_decode_result_copy;
%ignore wickr_decode_result_destroy;
%ignore wickr_packet_create_from_components;
%ignore wickr_parse_result_from_packet;
%ignore wickr_decode_result_from_parse_result;

%include "wickrcrypto/wickr_ctx.h"
%include "wickrcrypto/protocol.h"

%extend struct wickr_ephemeral_info {
	
	%newobject from_values;

	static wickr_ephemeral_info_t *from_values(uint64_t ttl, uint64_t bor) {
		wickr_ephemeral_info_t *info = (wickr_ephemeral_info_t *)malloc(sizeof(wickr_ephemeral_info_t));
		if (!info) {
			return NULL;
		}
		info->ttl = ttl;
		info->bor = bor;
		return info;
	}
	~wickr_ephemeral_info() {
		free($self);
	}
}

%extend struct wickr_packet {
	~wickr_packet() {
		wickr_packet_destroy(&$self);
	}

	%newobject serialize;
	%newobject create_from_buffer;

	wickr_buffer_t *serialize();
	static wickr_packet_t *create_from_buffer(const wickr_buffer_t *buffer);
}

%extend struct wickr_packet_meta {
	%newobject from_values;
	static wickr_packet_meta_t *from_values(wickr_ephemeral_info_t ephemerality_settings, wickr_buffer_t *channel_tag, uint16_t content_type) {
		return wickr_packet_meta_create(ephemerality_settings, channel_tag, content_type);
	}
	~wickr_packet_meta() {
		wickr_packet_meta_destroy(&$self);
	}
}

%extend struct wickr_payload {

	%newobject from_values;

	static wickr_payload_t *from_values(wickr_packet_meta_t *meta, wickr_buffer_t *body) {
		wickr_packet_meta_t *meta_copy = wickr_packet_meta_copy(meta);

		wickr_payload_t *payload = wickr_payload_create(meta_copy, body);

		if (!payload) {
			wickr_packet_meta_destroy(&meta_copy);
		}

		return payload;
	}

	~wickr_payload() {
		wickr_payload_destroy(&$self);
	}
}

%extend struct wickr_ctx {

	~wickr_ctx() {
		wickr_ctx_destroy(&$self);
	}

	%newobject export_storage_keys;
	%newobject import_storage;
 	%newobject from_values;
 	%newobject cipher_local;
 	%newobject decipher_local;
 	%newobject cipher_remote;
 	%newobject decipher_remote;
    %newobject ephemeral_keypair_gen;
    %newobject encode_packet;
    %newobject parse_packet_no_decode;
    %newobject parse_packet;
    %newobject decode_packet;
    %newobject from_buffer;
    %newobject export;
    %newobject import_from_buffer;

	wickr_buffer_t *export_storage_keys(const wickr_buffer_t *passphrase);

	static wickr_storage_keys_t *import_storage(const wickr_buffer_t *exported, const wickr_buffer_t *passphrase) {
		const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
		return wickr_ctx_import_storage_keys(engine, exported, passphrase);
	}

    static wickr_ctx_t *from_buffer(wickr_dev_info_t *dev_info, const wickr_buffer_t *buffer) {
        const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
        wickr_dev_info_t *dev_info_copy = wickr_dev_info_copy(dev_info);
        wickr_ctx_t *ctx = wickr_ctx_create_from_buffer(engine, dev_info_copy, buffer);
        if (!ctx) {
            wickr_dev_info_destroy(&dev_info_copy);
        }
        return ctx;
    }

    wickr_buffer_t *serialize();

#if defined(SWIGPHP)
	%newobject from_ctx;

	static wickr_ctx_t *from_ctx(wickr_ctx_t *ctx) {
		return wickr_ctx_copy(ctx);
	}
#endif

	static wickr_ctx_t *from_values(wickr_dev_info_t *dev_info, wickr_identity_chain_t *id_chain, wickr_storage_keys_t *storage_keys)
	{
		const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
		wickr_dev_info_t *dev_copy = wickr_dev_info_copy(dev_info);
		wickr_identity_chain_t *id_chain_copy = wickr_identity_chain_copy(id_chain);
		wickr_storage_keys_t *storage_keys_copy = wickr_storage_keys_copy(storage_keys);
		wickr_ctx_t *ctx = wickr_ctx_create(engine, dev_copy, id_chain_copy, storage_keys_copy);

		if (!ctx) {
			wickr_dev_info_destroy(&dev_copy);
			wickr_identity_chain_destroy(&id_chain_copy);
			wickr_storage_keys_destroy(&storage_keys_copy);
		}

		return ctx;
	}

    static wickr_ctx_t *import_from_buffer(wickr_dev_info_t *dev_info, const wickr_buffer_t *exported, const wickr_buffer_t *passphrase)
    {
        const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
        wickr_dev_info_t *dev_copy = wickr_dev_info_copy(dev_info);

        wickr_ctx_t *ctx = wickr_ctx_import(engine, dev_copy, exported, passphrase);

        if (!ctx) {
            wickr_dev_info_destroy(&dev_copy);
        }

        return ctx;
    }

    wickr_buffer_t *export_passphrase(const wickr_buffer_t *passphrase) {
        return wickr_ctx_export($self, passphrase);
    }

	wickr_cipher_result_t *cipher_local(const wickr_buffer_t *plaintext);
	wickr_buffer_t *decipher_local(const wickr_cipher_result_t *cipher_text);
	wickr_cipher_result_t *cipher_remote(const wickr_buffer_t *plaintext);
	wickr_buffer_t *decipher_remote(const wickr_cipher_result_t *cipher_text);
	wickr_ephemeral_keypair_t *ephemeral_keypair_gen(uint64_t key_id);
	wickr_ctx_encode_t *encode_packet(const wickr_payload_t *payload, const wickr_node_array_t *nodes);
    wickr_ctx_packet_t *parse_packet_no_decode(const wickr_buffer_t *packet_buffer, const wickr_identity_chain_t *sender);
    wickr_ctx_packet_t *parse_packet(const wickr_buffer_t *packet_buffer, const wickr_identity_chain_t *sender);
    wickr_decode_result_t *decode_packet(const wickr_ctx_packet_t *packet, wickr_ec_key_t *keypair);
 
};

%extend struct wickr_ctx_gen_result {
	
	~wickr_ctx_gen_result() {
		wickr_ctx_gen_result_destroy(&$self);
	}

	%newobject gen_new;
 	%newobject gen_new_with_sig_key;
 	%newobject gen_with_root_keys;
 	%newobject gen_with_passphrase;
 	%newobject gen_with_recovery;
 	%newobject export_recovery_key_passphrase;
 	%newobject make_recovery;
    %newobject import_recovery_key_passphrase;
    %newobject import_recovery;
    
	static wickr_ctx_gen_result_t *gen_new(wickr_dev_info_t *dev_info,wickr_buffer_t *identifier) {
		const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
		return wickr_ctx_gen_new(engine, dev_info, identifier);
	}

	static wickr_ctx_gen_result_t *gen_new_with_sig_key(wickr_dev_info_t *dev_info, wickr_ec_key_t *sig_key, wickr_buffer_t *identifier) {
		const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
		return wickr_ctx_gen_new_with_sig_key(engine, dev_info, sig_key, identifier);
	}

	static wickr_ctx_gen_result_t *gen_with_root_keys(wickr_dev_info_t *dev_info, wickr_root_keys_t *root_keys, wickr_buffer_t *identifier) {
		const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
		return wickr_ctx_gen_with_root_keys(engine, dev_info, root_keys, identifier);
    }

    static wickr_ctx_gen_result_t *gen_with_passphrase(wickr_dev_info_t *dev_info, wickr_buffer_t *exported_recovery_key, wickr_buffer_t *passphrase, wickr_buffer_t *recovery_data, wickr_buffer_t *identifier) {
		const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
		return wickr_ctx_gen_with_passphrase(engine, dev_info, exported_recovery_key, passphrase, recovery_data, identifier);
    }

    static wickr_ctx_gen_result_t *gen_with_recovery(wickr_dev_info_t *dev_info, wickr_buffer_t *recovery_data, wickr_cipher_key_t *recovery_key, wickr_buffer_t *identifier) {
		const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
		return wickr_ctx_gen_with_recovery(engine, dev_info, recovery_data, recovery_key, identifier);
    }

    wickr_buffer_t *export_recovery_key_passphrase(const wickr_buffer_t *passphrase) {
    	return wickr_ctx_gen_export_recovery_key_passphrase($self, passphrase);
    }

    static wickr_cipher_key_t *import_recovery_key_passphrase(const wickr_buffer_t *exported_recovery_key, const wickr_buffer_t *passphrase) {
    	const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    	return wickr_ctx_gen_import_recovery_key_passphrase(engine, exported_recovery_key, passphrase);
    }
    
    wickr_buffer_t *make_recovery();
    static wickr_root_keys_t *import_recovery(const wickr_buffer_t *recovery_data, const wickr_cipher_key_t *recovery_key) {
    	const wickr_crypto_engine_t engine = wickr_crypto_engine_get_default();
    	return wickr_ctx_gen_import_recovery(engine, recovery_data, recovery_key);
    }

};