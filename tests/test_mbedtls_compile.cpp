#include <cassert>
#include <vector>
#include "ESPressio_MbedTLSAead.hpp"
using namespace ESPressio::Security;

template<typename T>
void Exercise(std::size_t keySize){
    T cipher;
    std::vector<uint8_t> key(keySize,1),nonce(cipher.NonceSize(),2),aad={3,4},plain={5,6,7},ct,tag,opened;
    assert(cipher.Seal(key.data(),key.size(),nonce.data(),nonce.size(),aad.data(),aad.size(),plain.data(),plain.size(),ct,tag));
    assert(cipher.Open(key.data(),key.size(),nonce.data(),nonce.size(),aad.data(),aad.size(),ct.data(),ct.size(),tag.data(),tag.size(),opened));
    assert(opened==plain);
}

int main(){
#if ESPRESSIO_SECURITY_HAS_MBEDTLS_GCM
    Exercise<AES128GCMCipher>(16); Exercise<AES256GCMCipher>(32);
#endif
#if ESPRESSIO_SECURITY_HAS_MBEDTLS_CCM
    Exercise<AES128CCMCipher>(16); Exercise<AES256CCMCipher>(32);
#endif
#if ESPRESSIO_SECURITY_HAS_MBEDTLS_CHACHAPOLY
    Exercise<ChaCha20Poly1305Cipher>(32);
#endif
}
