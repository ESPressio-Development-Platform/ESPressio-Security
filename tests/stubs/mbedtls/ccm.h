#pragma once
#include <cstddef>
#define MBEDTLS_CCM_C 1
#ifndef MBEDTLS_CIPHER_ID_AES
#define MBEDTLS_CIPHER_ID_AES 1
#endif
typedef struct { int dummy; } mbedtls_ccm_context;
inline void mbedtls_ccm_init(mbedtls_ccm_context*){}
inline void mbedtls_ccm_free(mbedtls_ccm_context*){}
inline int mbedtls_ccm_setkey(mbedtls_ccm_context*,int,const unsigned char*,unsigned int){return 0;}
inline int mbedtls_ccm_encrypt_and_tag(mbedtls_ccm_context*,std::size_t len,const unsigned char*,std::size_t,const unsigned char*,std::size_t,const unsigned char* in,unsigned char* out,unsigned char* tag,std::size_t tagLen){for(std::size_t i=0;i<len;++i)out[i]=in[i];for(std::size_t i=0;i<tagLen;++i)tag[i]=0x5A;return 0;}
inline int mbedtls_ccm_auth_decrypt(mbedtls_ccm_context*,std::size_t len,const unsigned char*,std::size_t,const unsigned char*,std::size_t,const unsigned char* in,unsigned char* out,const unsigned char*,std::size_t){for(std::size_t i=0;i<len;++i)out[i]=in[i];return 0;}
