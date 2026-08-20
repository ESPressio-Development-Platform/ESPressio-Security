#pragma once
#include <cstddef>
#define MBEDTLS_CIPHER_ID_AES 1
#define MBEDTLS_GCM_ENCRYPT 1
typedef struct { int dummy; } mbedtls_gcm_context;
inline void mbedtls_gcm_init(mbedtls_gcm_context*){}
inline void mbedtls_gcm_free(mbedtls_gcm_context*){}
inline int mbedtls_gcm_setkey(mbedtls_gcm_context*,int,const unsigned char*,unsigned int){return 0;}
inline int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context*,int,std::size_t len,const unsigned char*,std::size_t,const unsigned char*,std::size_t,const unsigned char* in,unsigned char* out,std::size_t tagLen,unsigned char* tag){for(std::size_t i=0;i<len;++i)out[i]=in[i];for(std::size_t i=0;i<tagLen;++i)tag[i]=0xA5;return 0;}
inline int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context*,std::size_t len,const unsigned char*,std::size_t,const unsigned char*,std::size_t,const unsigned char*,std::size_t,const unsigned char* in,unsigned char* out){for(std::size_t i=0;i<len;++i)out[i]=in[i];return 0;}
