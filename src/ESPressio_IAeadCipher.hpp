#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

/// <summary>Abstracts an authenticated-encryption-with-associated-data algorithm.</summary>
class IAeadCipher {
public:
    virtual ~IAeadCipher() = default;
    /// <summary>Gets the portable algorithm identifier implemented by this cipher.</summary>
    virtual AeadAlgorithm Algorithm() const noexcept = 0;
    /// <summary>Gets a human-readable algorithm name.</summary>
    virtual const char* Name() const noexcept = 0;
    /// <summary>Gets the required key size in bytes.</summary>
    virtual std::size_t KeySize() const noexcept = 0;
    /// <summary>Gets the required nonce size in bytes.</summary>
    virtual std::size_t NonceSize() const noexcept = 0;
    /// <summary>Gets the authentication-tag size in bytes.</summary>
    virtual std::size_t TagSize() const noexcept = 0;

    /// <summary>Encrypts plaintext and produces an authentication tag while authenticating optional associated data.</summary>
    /// <returns><c>true</c> when encryption and authentication-tag generation succeed.</returns>
    virtual bool Seal(
        const uint8_t* key, std::size_t keySize,
        const uint8_t* nonce, std::size_t nonceSize,
        const uint8_t* aad, std::size_t aadSize,
        const uint8_t* plaintext, std::size_t plaintextSize,
        std::vector<uint8_t>& ciphertext,
        std::vector<uint8_t>& tag
    ) = 0;

    /// <summary>Authenticates and decrypts ciphertext using its tag and optional associated data.</summary>
    /// <returns><c>true</c> only when authentication succeeds and plaintext is recovered.</returns>
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
