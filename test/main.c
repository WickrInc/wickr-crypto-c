#include <stdio.h>
#include <string.h>
#include "cspec_output_verbose.h"
#include "test_util.h"
#include "test_cipher.h"
#include "test_openssl_suite.h"
#include "test_openssl_file_suite.h"
#include "test_array.h"
#include "test_protocol.h"
#include "test_kdf.h"
#include "test_context.h"
#include "test_node.h"
#include "test_buffer.h"
#include "test_stream_cipher.h"
#include "test_transport_ctx.h"
#include "test_identity.h"
#include "test_ephemeral_keypair.h"
#include "test_packet_meta.h"
#include "test_key_exchange.h"
#include "test_ecdh_cipher.h"
#include "test_protocol_version.h"
#include "test_storage_keys.h"
#include "test_b32.h"
#include "test_fingerprint.h"
#include "test_ec_key.h"
#include "test_encoder_result.h"
#include "test_payload.h"
#include "test_transport_packet.h"
#include "test_transport_handshake.h"
#include "test_transport_root_key.h"
#include "openssl_suite.h"

#ifdef FIPS
#include "private/openssl_threads.h"
#endif

#include "cspec_output_unit.h"

static const char *ci_flag = "--ci";

void run_primitive_tests(CSpecOutputStruct *output)
{
    CSpec_Run(DESCRIPTION(wickr_buffer_tests), output);
    CSpec_Run(DESCRIPTION(node_tests), output);
    CSpec_Run(DESCRIPTION(wickr_fingerprint), output);
    CSpec_Run(DESCRIPTION(wickr_fingerprint_generation), output);
    CSpec_Run(DESCRIPTION(wickr_fingerprint_bilateral_generation), output);
    CSpec_Run(DESCRIPTION(identity), output);
    CSpec_Run(DESCRIPTION(identity_chain), output);
    CSpec_Run(DESCRIPTION(ephemeral_keypair), output);
    CSpec_Run(DESCRIPTION(an_array_of_items), output);
    CSpec_Run(DESCRIPTION(a_zero_length_array), output);
    CSpec_Run(DESCRIPTION(wickr_ec_key), output);
    CSpec_Run(DESCRIPTION(cipher_result), output);
    CSpec_Run(DESCRIPTION(getBase64FromData), output);
    CSpec_Run(DESCRIPTION(getDataFromBase64), output);
    CSpec_Run(DESCRIPTION(getHexStringFromData), output);
    CSpec_Run(DESCRIPTION(getDataFromHexString), output);
    CSpec_Run(DESCRIPTION(base32_encode), output);
    CSpec_Run(DESCRIPTION(wickr_kdf_meta), output);
    CSpec_Run(DESCRIPTION(wickr_kdf_result), output);
    CSpec_Run(DESCRIPTION(packet_meta), output);
    CSpec_Run(DESCRIPTION(key_exchange), output);
    CSpec_Run(DESCRIPTION(key_exchange_set), output);
    CSpec_Run(DESCRIPTION(wickr_storage_keys), output);
}

void run_crypto_engine_tests(CSpecOutputStruct *output)
{
    CSpec_Run(DESCRIPTION(encodePlainFile), output);
    CSpec_Run(DESCRIPTION(decodeCipherFile), output);
    CSpec_Run(DESCRIPTION(openssl_crypto_random), output);
    CSpec_Run(DESCRIPTION(openssl_cipher_key_random), output);
    CSpec_Run(DESCRIPTION(openssl_cipher_ctr), output);
    CSpec_Run(DESCRIPTION(openssl_cipher_gcm), output);
    CSpec_Run(DESCRIPTION(openssl_ec_sign_verify), output);
    CSpec_Run(DESCRIPTION(openssl_ec_key_management), output);
    CSpec_Run(DESCRIPTION(openssl_digest_sha256), output);
    CSpec_Run(DESCRIPTION(openssl_digest_sha384), output);
    CSpec_Run(DESCRIPTION(openssl_digest_sha512), output);
    CSpec_Run(DESCRIPTION(openssl_ecdh), output);
    CSpec_Run(DESCRIPTION(openssl_hmac), output);
    CSpec_Run(DESCRIPTION(openssl_hkdf), output);
#ifdef FIPS
    CSpec_Run(DESCRIPTION(openssl_fips), output);
#endif
}

void run_stream_tests(CSpecOutputStruct *output)
{
    CSpec_Run(DESCRIPTION(wickr_stream_key), output);
    CSpec_Run(DESCRIPTION(wickr_stream_iv), output);
    CSpec_Run(DESCRIPTION(wickr_stream_cipher), output);
}

void run_ecdh_cipher_tests(CSpecOutputStruct *output)
{
    CSpec_Run(DESCRIPTION(wickr_ecdh_cipher), output);
    CSpec_Run(DESCRIPTION(wickr_ecdh_cipher_e2e_test), output);
}

void run_transport_tests(CSpecOutputStruct *output)
{
    CSpec_Run(DESCRIPTION(wickr_transport_root_key), output);
    CSpec_Run(DESCRIPTION(wickr_transport_packet_meta), output);
    CSpec_Run(DESCRIPTION(wickr_transport_packet), output);
    CSpec_Run(DESCRIPTION(wickr_transport_handshake), output);
    CSpec_Run(DESCRIPTION(wickr_transport_handshake_res), output);
    CSpec_Run(DESCRIPTION(wickr_transport_ctx), output);
}

void run_messaging_protocol_tests(CSpecOutputStruct *output)
{
    CSpec_Run(DESCRIPTION(wickr_protocol_key_exchanges), output);
    CSpec_Run(DESCRIPTION(wickr_packet_create_from_components), output);
    CSpec_Run(DESCRIPTION(wickr_encoder_result), output);
    CSpec_Run(DESCRIPTION(wickr_payload), output);
    CSpec_Run(DESCRIPTION(protocol_support_regression_tests), output);
}

void run_context_api_tests(CSpecOutputStruct *output)
{
    CSpec_Run(DESCRIPTION(wickr_ctx_generate), output);
    CSpec_Run(DESCRIPTION(wickr_ctx_send_pkt), output);
    CSpec_Run(DESCRIPTION(wickr_ctx_functions), output);
}

void run_kdf_tests(CSpecOutputStruct *output)
{
    CSpec_Run(DESCRIPTION(wickr_perform_kdf), output);
    CSpec_Run(DESCRIPTION(wickr_crypto_engine_kdf), output);
}

int main(int argc, char *argv[])
{
    bool CI_MODE = false;
    
    if (argc > 1) {
        if (strcmp(argv[1], ci_flag) == 0) {
            CI_MODE = true;
        }
    }
    
    CSpecOutputStruct* output = CI_MODE ? CSpec_NewOutputUnit() : CSpec_NewOutputVerbose();

    run_primitive_tests(output);
    run_crypto_engine_tests(output);
    run_ecdh_cipher_tests(output);
    run_stream_tests(output);
    run_transport_tests(output);
    run_messaging_protocol_tests(output);
    run_context_api_tests(output);
    run_kdf_tests(output);
    
#ifdef FIPS
    openssl_thread_cleanup();
#endif
    
    return output->failed;
}
