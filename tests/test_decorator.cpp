#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
#include "ESPressio_Security.hpp"

using namespace ESPressio::Security;

class TinyCipher final : public IAeadCipher {
public:
    AeadAlgorithm Algorithm() const noexcept override { return AeadAlgorithm::TestOnly; }
    const char* Name() const noexcept override { return "TEST"; }
    std::size_t KeySize() const noexcept override { return 16; }
    std::size_t NonceSize() const noexcept override { return 12; }
    std::size_t TagSize() const noexcept override { return 16; }

    bool Seal(
        const uint8_t* key, std::size_t keySize,
        const uint8_t* nonce, std::size_t nonceSize,
        const uint8_t* aad, std::size_t aadSize,
        const uint8_t* plaintext, std::size_t plaintextSize,
        uint8_t* ciphertext, std::size_t ciphertextCapacity,
        uint8_t* tag, std::size_t tagCapacity
    ) override {
        if (keySize != 16 || nonceSize != 12 || ciphertextCapacity < plaintextSize || tagCapacity < 16) return false;
        uint8_t value = 0;
        for (std::size_t i = 0; i < plaintextSize; ++i) {
            ciphertext[i] = plaintext[i] ^ key[i % keySize] ^ nonce[i % nonceSize];
        }
        for (std::size_t i = 0; i < aadSize; ++i) value ^= aad[i];
        for (std::size_t i = 0; i < plaintextSize; ++i) value ^= ciphertext[i];
        for (std::size_t i = 0; i < keySize; ++i) value ^= key[i];
        for (std::size_t i = 0; i < 16; ++i) tag[i] = value;
        return true;
    }

    bool Open(
        const uint8_t* key, std::size_t keySize,
        const uint8_t* nonce, std::size_t nonceSize,
        const uint8_t* aad, std::size_t aadSize,
        const uint8_t* ciphertext, std::size_t ciphertextSize,
        const uint8_t* tag, std::size_t tagSize,
        uint8_t* plaintext, std::size_t plaintextCapacity
    ) override {
        if (keySize != 16 || nonceSize != 12 || tagSize != 16 || plaintextCapacity < ciphertextSize) return false;
        uint8_t value = 0;
        for (std::size_t i = 0; i < aadSize; ++i) value ^= aad[i];
        for (std::size_t i = 0; i < ciphertextSize; ++i) value ^= ciphertext[i];
        for (std::size_t i = 0; i < keySize; ++i) value ^= key[i];
        uint8_t difference = 0;
        for (std::size_t i = 0; i < tagSize; ++i) difference |= tag[i] ^ value;
        if (difference != 0) return false;
        for (std::size_t i = 0; i < ciphertextSize; ++i) {
            plaintext[i] = ciphertext[i] ^ key[i % keySize] ^ nonce[i % nonceSize];
        }
        return true;
    }
};

class Random final : public IRandomSource {
public:
    bool Fill(uint8_t* output, std::size_t size) override {
        for (std::size_t i = 0; i < size; ++i) output[i] = static_cast<uint8_t>(++next);
        return true;
    }
private:
    uint8_t next = 0;
};

class LoopbackCarrier final : public ITransportSecurityCarrier {
public:
    bool Send(uint8_t protocol, const uint8_t* data, std::size_t size) override {
        last.assign(data, data + size);
        if (receiver) receiver(protocol, last.data(), last.size());
        return true;
    }

    void SetReceiver(Receiver value) override { receiver = std::move(value); }

    Receiver receiver;
    std::vector<uint8_t> last;
};

int main() {
    TinyCipher cipher;
    AeadCipherRegistry registry;
    assert(registry.Register(cipher));

    StaticKeyProvider keys;
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    assert(keys.Add(1, AeadAlgorithm::TestOnly, key, 16));

    Random random;
    TransportSecurityConfig config;
    config.Policy = TransportSecurityPolicy::Required;
    config.OutboundAlgorithm = AeadAlgorithm::TestOnly;
    config.OutboundKeyID = 1;
    config.SenderID = 77;

    TransportSecurity security(registry, keys, random, config);
    LoopbackCarrier carrier;
    SecureTransportDecorator secure(carrier, security);

    bool received = false;
    secure.SetReceiver([&](uint8_t protocol, const UnprotectedPayload& payload) {
        received = true;
        assert(protocol == 9);
        assert(payload.Protected);
        assert(payload.SenderID == 77);
        assert(payload.SessionID != 0);
        assert(payload.Sequence == 1);
        assert(std::string(payload.Data.begin(), payload.Data.end()) == "hello");
    });

    SecurityResult result;
    assert(secure.Send(9, reinterpret_cast<const uint8_t*>("hello"), 5, &result));
    assert(result.Success && result.Protected && received);
    assert(TransportSecurity::LooksProtected(carrier.last.data(), carrier.last.size()));

    std::cout << "Secure transport decorator test passed\n";
}
