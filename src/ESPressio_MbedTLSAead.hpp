#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include "ESPressio_IAeadCipher.hpp"

#if __has_include(<mbedtls/gcm.h>)
#include <mbedtls/gcm.h>
#if defined(MBEDTLS_GCM_C)
#define ESPRESSIO_SECURITY_HAS_MBEDTLS_GCM 1
#else
#define ESPRESSIO_SECURITY_HAS_MBEDTLS_GCM 0
#endif
#else
#define ESPRESSIO_SECURITY_HAS_MBEDTLS_GCM 0
#endif

#if __has_include(<mbedtls/ccm.h>)
#include <mbedtls/ccm.h>
#if defined(MBEDTLS_CCM_C)
#define ESPRESSIO_SECURITY_HAS_MBEDTLS_CCM 1
#else
#define ESPRESSIO_SECURITY_HAS_MBEDTLS_CCM 0
#endif
#else
#define ESPRESSIO_SECURITY_HAS_MBEDTLS_CCM 0
#endif

#if __has_include(<mbedtls/chachapoly.h>)
#include <mbedtls/chachapoly.h>
#if defined(MBEDTLS_CHACHAPOLY_C)
#define ESPRESSIO_SECURITY_HAS_MBEDTLS_CHACHAPOLY 1
#else
#define ESPRESSIO_SECURITY_HAS_MBEDTLS_CHACHAPOLY 0
#endif
#else
#define ESPRESSIO_SECURITY_HAS_MBEDTLS_CHACHAPOLY 0
#endif

namespace ESPressio::Security {

#if ESPRESSIO_SECURITY_HAS_MBEDTLS_GCM
template<std::size_t KeyBytes, AeadAlgorithm AlgorithmValue>
class MbedTLSAesGcm final : public IAeadCipher {
public:
    AeadAlgorithm Algorithm() const noexcept override { return AlgorithmValue; }
    const char* Name() const noexcept override { return KeyBytes == 16 ? "AES-128-GCM" : "AES-256-GCM"; }
    std::size_t KeySize() const noexcept override { return KeyBytes; }
    std::size_t NonceSize() const noexcept override { return 12; }
    std::size_t TagSize() const noexcept override { return 16; }
    bool Seal(const uint8_t* key,std::size_t keySize,const uint8_t* nonce,std::size_t nonceSize,const uint8_t* aad,std::size_t aadSize,const uint8_t* plaintext,std::size_t plaintextSize,std::vector<uint8_t>& ciphertext,std::vector<uint8_t>& tag) override {
        if(keySize!=KeyBytes||nonceSize!=NonceSize())return false; mbedtls_gcm_context ctx;mbedtls_gcm_init(&ctx);
        bool ok=mbedtls_gcm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,key,static_cast<unsigned int>(KeyBytes*8))==0; ciphertext.resize(plaintextSize);tag.resize(TagSize());
        if(ok)ok=mbedtls_gcm_crypt_and_tag(&ctx,MBEDTLS_GCM_ENCRYPT,plaintextSize,nonce,nonceSize,aad,aadSize,plaintext,ciphertext.data(),tag.size(),tag.data())==0;
        mbedtls_gcm_free(&ctx); if(!ok){ciphertext.clear();tag.clear();} return ok;
    }
    bool Open(const uint8_t* key,std::size_t keySize,const uint8_t* nonce,std::size_t nonceSize,const uint8_t* aad,std::size_t aadSize,const uint8_t* ciphertext,std::size_t ciphertextSize,const uint8_t* tag,std::size_t tagSize,std::vector<uint8_t>& plaintext) override {
        if(keySize!=KeyBytes||nonceSize!=NonceSize()||tagSize!=TagSize())return false; mbedtls_gcm_context ctx;mbedtls_gcm_init(&ctx);
        bool ok=mbedtls_gcm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,key,static_cast<unsigned int>(KeyBytes*8))==0; plaintext.resize(ciphertextSize);
        if(ok)ok=mbedtls_gcm_auth_decrypt(&ctx,ciphertextSize,nonce,nonceSize,aad,aadSize,tag,tagSize,ciphertext,plaintext.data())==0;
        mbedtls_gcm_free(&ctx); if(!ok)plaintext.clear(); return ok;
    }
};
using AES128GCMCipher=MbedTLSAesGcm<16,AeadAlgorithm::AES128GCM>;
using AES256GCMCipher=MbedTLSAesGcm<32,AeadAlgorithm::AES256GCM>;
#endif

#if ESPRESSIO_SECURITY_HAS_MBEDTLS_CCM
template<std::size_t KeyBytes, AeadAlgorithm AlgorithmValue>
class MbedTLSAesCcm final : public IAeadCipher {
public:
    AeadAlgorithm Algorithm() const noexcept override { return AlgorithmValue; }
    const char* Name() const noexcept override { return KeyBytes == 16 ? "AES-128-CCM" : "AES-256-CCM"; }
    std::size_t KeySize() const noexcept override { return KeyBytes; }
    std::size_t NonceSize() const noexcept override { return 12; }
    std::size_t TagSize() const noexcept override { return 16; }
    bool Seal(const uint8_t* key,std::size_t keySize,const uint8_t* nonce,std::size_t nonceSize,const uint8_t* aad,std::size_t aadSize,const uint8_t* plaintext,std::size_t plaintextSize,std::vector<uint8_t>& ciphertext,std::vector<uint8_t>& tag) override {
        if(keySize!=KeyBytes||nonceSize!=NonceSize())return false; mbedtls_ccm_context ctx;mbedtls_ccm_init(&ctx);
        bool ok=mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,key,static_cast<unsigned int>(KeyBytes*8))==0; ciphertext.resize(plaintextSize);tag.resize(TagSize());
        if(ok)ok=mbedtls_ccm_encrypt_and_tag(&ctx,plaintextSize,nonce,nonceSize,aad,aadSize,plaintext,ciphertext.data(),tag.data(),tag.size())==0;
        mbedtls_ccm_free(&ctx); if(!ok){ciphertext.clear();tag.clear();} return ok;
    }
    bool Open(const uint8_t* key,std::size_t keySize,const uint8_t* nonce,std::size_t nonceSize,const uint8_t* aad,std::size_t aadSize,const uint8_t* ciphertext,std::size_t ciphertextSize,const uint8_t* tag,std::size_t tagSize,std::vector<uint8_t>& plaintext) override {
        if(keySize!=KeyBytes||nonceSize!=NonceSize()||tagSize!=TagSize())return false; mbedtls_ccm_context ctx;mbedtls_ccm_init(&ctx);
        bool ok=mbedtls_ccm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,key,static_cast<unsigned int>(KeyBytes*8))==0; plaintext.resize(ciphertextSize);
        if(ok)ok=mbedtls_ccm_auth_decrypt(&ctx,ciphertextSize,nonce,nonceSize,aad,aadSize,ciphertext,plaintext.data(),tag,tagSize)==0;
        mbedtls_ccm_free(&ctx); if(!ok)plaintext.clear(); return ok;
    }
};
using AES128CCMCipher=MbedTLSAesCcm<16,AeadAlgorithm::AES128CCM>;
using AES256CCMCipher=MbedTLSAesCcm<32,AeadAlgorithm::AES256CCM>;
#endif

#if ESPRESSIO_SECURITY_HAS_MBEDTLS_CHACHAPOLY
class ChaCha20Poly1305Cipher final : public IAeadCipher {
public:
    AeadAlgorithm Algorithm() const noexcept override{return AeadAlgorithm::ChaCha20Poly1305;} const char* Name() const noexcept override{return "ChaCha20-Poly1305";}
    std::size_t KeySize() const noexcept override{return 32;} std::size_t NonceSize() const noexcept override{return 12;} std::size_t TagSize() const noexcept override{return 16;}
    bool Seal(const uint8_t* key,std::size_t keySize,const uint8_t* nonce,std::size_t nonceSize,const uint8_t* aad,std::size_t aadSize,const uint8_t* plaintext,std::size_t plaintextSize,std::vector<uint8_t>& ciphertext,std::vector<uint8_t>& tag) override {
        if(keySize!=KeySize()||nonceSize!=NonceSize())return false;mbedtls_chachapoly_context ctx;mbedtls_chachapoly_init(&ctx);bool ok=mbedtls_chachapoly_setkey(&ctx,key)==0;ciphertext.resize(plaintextSize);tag.resize(TagSize());
        if(ok)ok=mbedtls_chachapoly_encrypt_and_tag(&ctx,plaintextSize,nonce,aad,aadSize,plaintext,ciphertext.data(),tag.data())==0;mbedtls_chachapoly_free(&ctx);if(!ok){ciphertext.clear();tag.clear();}return ok;
    }
    bool Open(const uint8_t* key,std::size_t keySize,const uint8_t* nonce,std::size_t nonceSize,const uint8_t* aad,std::size_t aadSize,const uint8_t* ciphertext,std::size_t ciphertextSize,const uint8_t* tag,std::size_t tagSize,std::vector<uint8_t>& plaintext) override {
        if(keySize!=KeySize()||nonceSize!=NonceSize()||tagSize!=TagSize())return false;mbedtls_chachapoly_context ctx;mbedtls_chachapoly_init(&ctx);bool ok=mbedtls_chachapoly_setkey(&ctx,key)==0;plaintext.resize(ciphertextSize);
        if(ok)ok=mbedtls_chachapoly_auth_decrypt(&ctx,ciphertextSize,nonce,aad,aadSize,tag,ciphertext,plaintext.data())==0;mbedtls_chachapoly_free(&ctx);if(!ok)plaintext.clear();return ok;
    }
};
#endif

}
