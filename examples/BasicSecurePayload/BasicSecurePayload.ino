#include <Arduino.h>
#include <ESPressio_Security.hpp>

using namespace ESPressio::Security;

#if !ESPRESSIO_SECURITY_HAS_MBEDTLS_GCM
#error "This example requires mbedTLS GCM support."
#endif

AES256GCMCipher aes256gcm;
AeadCipherRegistry ciphers;
StaticKeyProvider keys;
ESP32RandomSource randomSource;
TransportSecurity* security = nullptr;

void setup() {
    Serial.begin(115200);
    delay(500);

    ciphers.Register(aes256gcm);

    // Example only. Provision keys securely in real applications; do not
    // hard-code production keys into firmware/source control.
    const uint8_t demoKey[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    keys.Add(1, AeadAlgorithm::AES256GCM, demoKey, sizeof(demoKey));

    static TransportSecurityConfig config;
    config.Policy = TransportSecurityPolicy::Required;
    config.OutboundAlgorithm = AeadAlgorithm::AES256GCM;
    config.OutboundKeyID = 1;
    config.SenderID = ESP.getEfuseMac();

    static TransportSecurity instance(ciphers, keys, randomSource, config);
    security = &instance;

    const char* message = "hello secure transport";
    std::vector<uint8_t> protectedPayload;
    SecurityResult protectedResult = security->Protect(
        42,
        reinterpret_cast<const uint8_t*>(message),
        strlen(message),
        protectedPayload
    );

    Serial.printf("protected=%s bytes=%u\n",
        protectedResult.Success ? "yes" : "no",
        static_cast<unsigned>(protectedPayload.size()));

    UnprotectedPayload opened;
    SecurityResult openedResult = security->Unprotect(
        42,
        protectedPayload.data(),
        protectedPayload.size(),
        opened
    );

    Serial.printf("authenticated=%s sender=%llu sequence=%llu plaintext=\"%.*s\"\n",
        openedResult.Success ? "yes" : "no",
        static_cast<unsigned long long>(opened.SenderID),
        static_cast<unsigned long long>(opened.Sequence),
        static_cast<int>(opened.Data.size()),
        opened.Data.empty() ? "" : reinterpret_cast<const char*>(opened.Data.data()));
}

void loop() {}
