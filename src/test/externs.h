#ifndef externs_h
#define externs_h

#include "crypto_engine.h"
#include "wickr_ctx.h"

extern wickr_crypto_engine_t engine;
extern wickr_buffer_t *devSalt;

extern void initTest();

extern wickr_identity_chain_t *createIdentityChain(char *userName);
extern wickr_node_t *createUserNode(char *userName, wickr_buffer_t *devID);
extern wickr_dev_info_t *createDevInfo(wickr_buffer_t *systemID);
extern wickr_buffer_t *createDeviceIdentity(uint8_t *devStr, size_t devLen);
extern wickr_buffer_t *hex_char_to_buffer(const char *hex);
extern wickr_buffer_t *hex_char_to_buffer(const char *hex);
extern wickr_ctx_t *createContext(wickr_node_t *userNode);

#endif // externs_h
