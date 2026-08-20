#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

class IAeadCipher {
public:
    virtual ~IAeadCipher() = default;
    virtual AeadAlgorithm Algorithm() const noexcept = 0;
    virtual const char* Name() const noexcept = 0;
    virtual std::size_t KeySize() const noexcept = 0;
    virtual std::size_t NonceSize() const noexcept = 0;
    virtual std::size_t TagSize() const noexcept = 0;

    virtual bool Seal(
        const uint8_t* key, std::size_t keySize,
        const uint8_t* nonce, std::size_t nonceSize,
        const uint8_t* aad, std::size_t aadSize,
        const uint8_t* plaintext, std::size_t plaintextSize,
        std::vector<uint8_t>& ciphertext,
        std::vector<uint8_t>& tag
    ) = 0;

    virtual bool Open(
        const uint8_t* key, std::size_t keySize,
        const uint8_t* nonce, std::size_t nonceSize,
        const uint8_t* aad, std::size_t aadSize,
        const uint8_t* ciphertext, std::size_t ciphertextSize,
        const uint8_t* tag, std::size_t tagSize,
        std::vector<uint8_t>& plaintext
    ) = 0;
};

}
