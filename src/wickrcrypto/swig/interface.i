#if defined(SWIGJAVASCRIPT)

%{
#include <node.h>
#include <node_buffer.h>	
%}

#endif

#if defined(SWIGJAVASCRIPT)
%module wickrcrypto
#else
%module WickrCrypto
#endif

%rename(Cipher) wickr_cipher;
%rename(CipherResult) wickr_cipher_result;
%rename(CipherKey) wickr_cipher_key;
%rename(DeviceInfo) wickr_dev_info;
%rename(KeyExchange) wickr_key_exchange;
%rename(KeyExchangeSet) wickr_key_exchange_set;
%rename(ECDSAResult) wickr_ecdsa_result;
%rename(ECKey) wickr_ec_key;
%rename(ECCurve) wickr_ec_curve;
%rename(Digest) wickr_digest;
%rename(CryptoEngine) wickr_crypto_engine;
%rename(Identity) wickr_identity;
%rename(IdentityChain) wickr_identity_chain;
%rename(KDFMeta) wickr_kdf_meta;
%rename(KDFAlgo) wickr_kdf_algo;
%rename(KDFResult) wickr_kdf_result;
%rename(KeyExchange) wickr_key_exchange;
%rename(PacketHeader) wickr_packet_header;
%rename(ParseResult) wickr_parse_result;
%rename(EphemeralKeypair) wickr_ephemeral_keypair;
%rename(Node) wickr_node;
%rename(WickrArray) wickr_array;
%rename(RootKeys) wickr_root_keys;
%rename(StorageKeys) wickr_storage_keys;
%rename(Packet) wickr_packet;
%rename(PacketMeta) wickr_packet_meta;
%rename(Payload) wickr_payload;
%rename(Context) wickr_ctx;
%rename(ContextEncodeResult) wickr_ctx_encode;
%rename(ContextParseResult) wickr_ctx_packet;
%rename(ContextDecodeResult) wickr_decode_result;
%rename(ContextGenResult) wickr_ctx_gen_result;
%rename(EphemeralInfo) wickr_ephemeral_info;
%rename(Fingerprint) wickr_fingerprint;

%rename(DigestType) wickr_digest_type;
%rename(IdentityChainStatus) wickr_identity_chain_status;
%rename(IdentityType) wickr_identity_type;
%rename(PacketSignatureStatus) wickr_packet_signature_status;
%rename(FingerprintOutputType) wickr_fingerprint_output;
%rename(FingerprintType) wickr_fingerprint_type;

%rename (DecodeError) wickr_decode_error;
%rename (CipherID) wickr_cipher_id;
%rename (DigestID) wickr_digest_id;
%rename (CurveID) wickr_ec_curve_id;
%rename (KDFAlgoID) wickr_kdf_algo_id;
%rename (KDFID) wickr_kdf_id;

%rename (ECDHCipherContext) wickr_ecdh_cipher_ctx;

%rename("%(lowercamelcase)s", %$isfunction) "";
%rename("%(lowercamelcase)s", %$ismember) "";

#if defined(SWIGJAVA)

%typemap(javabody,noblock=1) SWIGTYPE {

  private long swigCPtr;
  protected boolean swigCMemOwn;
  private Object swigCParent;
  
  public $javaclassname(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  public $javaclassname(long cPtr, boolean cMemoryOwn, Object cParent) {
    this(cPtr, cMemoryOwn);
    swigCParent = cParent;
  }

  public static long getCPtr($javaclassname obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  
}

#endif

%include engine.i

#if !defined(SWIGPHP)
%include dev_info.i
%include storage_keys.i
%include identity.i
%include root_keys.i
%include keypairs.i
%include node.i
%include key_exchange.i
%include ecdh_cipher.i
%include wickr_ctx.i
#endif