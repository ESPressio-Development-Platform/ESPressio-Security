#include <Arduino.h>
#include <ESPressio_Security.hpp>

using namespace ESPressio::Security;

void setup() {
    Serial.begin(115200);
    delay(500);

    AeadCipherRegistry registry;

#if ESPRESSIO_SECURITY_HAS_MBEDTLS_GCM
    static AES128GCMCipher aes128gcm;
    static AES256GCMCipher aes256gcm;
    registry.Register(aes128gcm);
    registry.Register(aes256gcm);
    Serial.println("AES-128-GCM: available");
    Serial.println("AES-256-GCM: available");
#endif

#if ESPRESSIO_SECURITY_HAS_MBEDTLS_CCM
    static AES128CCMCipher aes128ccm;
    static AES256CCMCipher aes256ccm;
    registry.Register(aes128ccm);
    registry.Register(aes256ccm);
    Serial.println("AES-128-CCM: available");
    Serial.println("AES-256-CCM: available");
#endif

#if ESPRESSIO_SECURITY_HAS_MBEDTLS_CHACHAPOLY
    static ChaCha20Poly1305Cipher chacha;
    registry.Register(chacha);
    Serial.println("ChaCha20-Poly1305: available");
#endif
}

void loop() {}
