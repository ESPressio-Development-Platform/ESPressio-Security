#pragma once

#include <cstddef>
#include <cstdint>

#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

/// <summary>Abstracts an authenticated-encryption-with-associated-data algorithm.</summary>
class IAeadCipher {
public:
    virtual ~IAeadCipher() = default;
    virtual AeadAlgorithm Algorithm() const noexcept = 0;
    virtual const char* Name() const noexcept = 0;
    virtual std::size_t KeySize() const noexcept = 0;
    virtual std::size_t NonceSize() const noexcept = 0;
    virtual std::size_t TagSize() const noexcept = 0;

    /// <summary>Encrypts plaintext directly into caller-owned ciphertext and tag storage.</summary>
    virtual bool Seal(
        const uint8_t* key, std::size_t keySize,
        const uint8_t* nonce, std::size_t nonceSize,
        const uint8_t* aad, std::size_t aadSize,
        const uint8_t* plaintext, std::size_t plaintextSize,
        uint8_t* ciphertext, std::size_t ciphertextCapacity,
        uint8_t* tag, std::size_t tagCapacity
    ) = 0;

    /// <summary>Authenticates and decrypts ciphertext directly into caller-owned plaintext storage.</summary>
    virtual bool Open(
        const uint8_t* key, std::size_t keySize,
        const uint8_t* nonce, std::size_t nonceSize,
        const uint8_t* aad, std::size_t aadSize,
        const uint8_t* ciphertext, std::size_t ciphertextSize,
        const uint8_t* tag, std::size_t tagSize,
        uint8_t* plaintext, std::size_t plaintextCapacity
    ) = 0;
};

}
