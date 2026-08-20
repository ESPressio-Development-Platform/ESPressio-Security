#pragma once
#include <cstddef>
#define MBEDTLS_CHACHAPOLY_C 1
typedef struct { int dummy; } mbedtls_chachapoly_context;
inline void mbedtls_chachapoly_init(mbedtls_chachapoly_context*){}
inline void mbedtls_chachapoly_free(mbedtls_chachapoly_context*){}
inline int mbedtls_chachapoly_setkey(mbedtls_chachapoly_context*,const unsigned char[32]){return 0;}
inline int mbedtls_chachapoly_encrypt_and_tag(mbedtls_chachapoly_context*,std::size_t len,const unsigned char[12],const unsigned char*,std::size_t,const unsigned char* in,unsigned char* out,unsigned char tag[16]){for(std::size_t i=0;i<len;++i)out[i]=in[i];for(std::size_t i=0;i<16;++i)tag[i]=0x3C;return 0;}
inline int mbedtls_chachapoly_auth_decrypt(mbedtls_chachapoly_context*,std::size_t len,const unsigned char[12],const unsigned char*,std::size_t,const unsigned char[16],const unsigned char* in,unsigned char* out){for(std::size_t i=0;i<len;++i)out[i]=in[i];return 0;}
