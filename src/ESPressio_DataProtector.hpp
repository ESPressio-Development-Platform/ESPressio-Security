#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

#include <ESPressio_Memory.hpp>

#include "ESPressio_AeadCipherRegistry.hpp"
#include "ESPressio_IDataProtector.hpp"
#include "ESPressio_IKeyProvider.hpp"
#include "ESPressio_IRandomSource.hpp"
#include "ESPressio_StaticKeyProvider.hpp"

namespace ESPressio::Security {

struct DataProtectionConfig {
    AeadAlgorithm Algorithm = AeadAlgorithm::AES256GCM;
    uint32_t KeyID = 1;
    std::size_t MaximumPlaintextBytes = 64u * 1024u;
};

class DataProtector final : public IDataProtector {
public:
    DataProtector(
        AeadCipherRegistry& ciphers,
        const IKeyProvider& keys,
        IRandomSource& random,
        DataProtectionConfig config = {}
    ) : _ciphers(ciphers), _keys(keys), _random(random), _config(config) {}

    const DataProtectionConfig& GetConfig() const noexcept { return _config; }
    void SetConfig(const DataProtectionConfig& config) { _config = config; }

    SecurityResult Protect(
        const uint8_t* plaintext,
        std::size_t plaintextSize,
        SecurityBuffer& protectedData,
        const DataProtectionContext& context = {}
    ) override {
        protectedData.clear();
        if ((plaintext == nullptr && plaintextSize != 0) ||
            (context.Data == nullptr && context.Size != 0) ||
            _config.KeyID == 0) {
            return SecurityResult::Fail(SecurityError::InvalidArgument, "Invalid data-protection argument");
        }
        if (plaintextSize > _config.MaximumPlaintextBytes) {
            return SecurityResult::Fail(SecurityError::BufferLimitExceeded, "Plaintext exceeds configured limit");
        }

        IAeadCipher* cipher = _ciphers.Find(_config.Algorithm);
        if (cipher == nullptr) {
            return SecurityResult::Fail(SecurityError::UnsupportedAlgorithm, "Requested data-protection algorithm is unavailable");
        }

        KeyMaterial key;
        if (!_keys.GetKey(_config.KeyID, _config.Algorithm, key)) {
            return SecurityResult::Fail(SecurityError::MissingKey, "Data-protection key is unavailable");
        }
        if (key.Bytes.size() != cipher->KeySize()) {
            StaticKeyProvider::SecureErase(key.Bytes);
            return SecurityResult::Fail(SecurityError::InvalidKeyLength, "Data-protection key length is invalid");
        }

        const std::size_t nonceSize = cipher->NonceSize();
        const std::size_t tagOffset = HeaderSize + nonceSize;
        const std::size_t ciphertextOffset = tagOffset + cipher->TagSize();
        const std::size_t envelopeSize = ciphertextOffset + plaintextSize;

        // Allocate the final externally-preferred envelope once. The nonce is
        // generated directly into its final location rather than into a second
        // temporary vector that would subsequently be copied here.
        protectedData.resize(envelopeSize);
        WriteHeader(
            protectedData.data(),
            _config.Algorithm,
            _config.KeyID,
            static_cast<uint16_t>(nonceSize),
            static_cast<uint16_t>(cipher->TagSize()),
            static_cast<uint32_t>(plaintextSize)
        );

        uint8_t* nonce = protectedData.data() + HeaderSize;
        if (!_random.Fill(nonce, nonceSize)) {
            StaticKeyProvider::SecureErase(key.Bytes);
            protectedData.clear();
            return SecurityResult::Fail(SecurityError::RandomFailure, "Unable to generate data-protection nonce");
        }

        // The fixed header already occupies contiguous final storage and can be
        // authenticated in place. Only callers supplying additional context need
        // a combined AAD scratch buffer.
        SecurityBuffer aad;
        const uint8_t* aadData = protectedData.data();
        std::size_t aadSize = HeaderSize;
        if (context.Size != 0) {
            aad.reserve(HeaderSize + context.Size);
            aad.insert(aad.end(), protectedData.begin(), protectedData.begin() + HeaderSize);
            aad.insert(aad.end(), context.Data, context.Data + context.Size);
            aadData = aad.data();
            aadSize = aad.size();
        }

        const bool sealed = cipher->Seal(
            key.Bytes.data(), key.Bytes.size(),
            nonce, nonceSize,
            aadData, aadSize,
            plaintext, plaintextSize,
            protectedData.data() + ciphertextOffset, plaintextSize,
            protectedData.data() + tagOffset, cipher->TagSize()
        );
        StaticKeyProvider::SecureErase(key.Bytes);
        if (!sealed) {
            protectedData.clear();
            return SecurityResult::Fail(SecurityError::EncryptionFailed, "Authenticated data protection failed");
        }
        return SecurityResult::Ok(true);
    }

    SecurityResult Unprotect(
        const uint8_t* protectedData,
        std::size_t protectedDataSize,
        SecurityBuffer& plaintext,
        const DataProtectionContext& context = {}
    ) override {
        plaintext.clear();
        if (protectedData == nullptr || protectedDataSize < HeaderSize ||
            (context.Data == nullptr && context.Size != 0)) {
            return SecurityResult::Fail(SecurityError::InvalidArgument, "Invalid protected-data argument");
        }

        Header decoded{};
        if (!ReadHeader(protectedData, protectedDataSize, decoded)) {
            return SecurityResult::Fail(SecurityError::MalformedEnvelope, "Malformed protected-data envelope");
        }
        if (decoded.Version != FormatVersion) {
            return SecurityResult::Fail(SecurityError::UnsupportedVersion, "Unsupported protected-data format version");
        }
        if (decoded.PlaintextSize > _config.MaximumPlaintextBytes) {
            return SecurityResult::Fail(SecurityError::BufferLimitExceeded, "Protected plaintext exceeds configured limit");
        }

        IAeadCipher* cipher = _ciphers.Find(decoded.Algorithm);
        if (cipher == nullptr) {
            return SecurityResult::Fail(SecurityError::UnsupportedAlgorithm, "Protected-data algorithm is unavailable");
        }
        if (decoded.NonceSize != cipher->NonceSize() || decoded.TagSize != cipher->TagSize()) {
            return SecurityResult::Fail(SecurityError::MalformedEnvelope, "Protected-data nonce or tag size is invalid");
        }

        const std::size_t expected = HeaderSize + decoded.NonceSize + decoded.TagSize + decoded.PlaintextSize;
        if (expected != protectedDataSize) {
            return SecurityResult::Fail(SecurityError::MalformedEnvelope, "Protected-data envelope length is invalid");
        }

        KeyMaterial key;
        if (!_keys.GetKey(decoded.KeyID, decoded.Algorithm, key)) {
            return SecurityResult::Fail(SecurityError::MissingKey, "Protected-data key is unavailable");
        }
        if (key.Bytes.size() != cipher->KeySize()) {
            StaticKeyProvider::SecureErase(key.Bytes);
            return SecurityResult::Fail(SecurityError::InvalidKeyLength, "Protected-data key length is invalid");
        }

        const uint8_t* nonce = protectedData + HeaderSize;
        const uint8_t* tag = nonce + decoded.NonceSize;
        const uint8_t* ciphertext = tag + decoded.TagSize;

        SecurityBuffer aad;
        const uint8_t* aadData = protectedData;
        std::size_t aadSize = HeaderSize;
        if (context.Size != 0) {
            aad.reserve(HeaderSize + context.Size);
            aad.insert(aad.end(), protectedData, protectedData + HeaderSize);
            aad.insert(aad.end(), context.Data, context.Data + context.Size);
            aadData = aad.data();
            aadSize = aad.size();
        }

        plaintext.resize(decoded.PlaintextSize);
        const bool opened = cipher->Open(
            key.Bytes.data(), key.Bytes.size(),
            nonce, decoded.NonceSize,
            aadData, aadSize,
            ciphertext, decoded.PlaintextSize,
            tag, decoded.TagSize,
            plaintext.data(), plaintext.size()
        );
        StaticKeyProvider::SecureErase(key.Bytes);
        if (!opened) {
            plaintext.clear();
            return SecurityResult::Fail(SecurityError::AuthenticationFailed, "Protected data could not be authenticated or decrypted");
        }
        return SecurityResult::Ok(true);
    }

private:
    static constexpr uint8_t FormatVersion = 1;
    static constexpr std::size_t HeaderSize = 18;

    struct Header {
        uint8_t Version = 0;
        AeadAlgorithm Algorithm = AeadAlgorithm::Unknown;
        uint32_t KeyID = 0;
        uint16_t NonceSize = 0;
        uint16_t TagSize = 0;
        uint32_t PlaintextSize = 0;
    };

    static void WriteU16(uint8_t* out, uint16_t value) noexcept {
        out[0] = static_cast<uint8_t>(value);
        out[1] = static_cast<uint8_t>(value >> 8u);
    }

    static void WriteU32(uint8_t* out, uint32_t value) noexcept {
        for (unsigned shift = 0; shift < 32; shift += 8) {
            *out++ = static_cast<uint8_t>(value >> shift);
        }
    }

    static uint16_t ReadU16(const uint8_t* p) {
        return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8u);
    }

    static uint32_t ReadU32(const uint8_t* p) {
        return static_cast<uint32_t>(p[0]) |
            (static_cast<uint32_t>(p[1]) << 8u) |
            (static_cast<uint32_t>(p[2]) << 16u) |
            (static_cast<uint32_t>(p[3]) << 24u);
    }

    static void WriteHeader(
        uint8_t* out,
        AeadAlgorithm algorithm,
        uint32_t keyID,
        uint16_t nonceSize,
        uint16_t tagSize,
        uint32_t plaintextSize
    ) noexcept {
        out[0] = 'E';
        out[1] = 'S';
        out[2] = 'D';
        out[3] = 'P';
        out[4] = FormatVersion;
        out[5] = static_cast<uint8_t>(algorithm);
        WriteU32(out + 6, keyID);
        WriteU16(out + 10, nonceSize);
        WriteU16(out + 12, tagSize);
        WriteU32(out + 14, plaintextSize);
    }

    static bool ReadHeader(const uint8_t* data, std::size_t size, Header& out) {
        if (size < HeaderSize || data[0] != 'E' || data[1] != 'S' || data[2] != 'D' || data[3] != 'P') return false;
        out.Version = data[4];
        out.Algorithm = static_cast<AeadAlgorithm>(data[5]);
        out.KeyID = ReadU32(data + 6);
        out.NonceSize = ReadU16(data + 10);
        out.TagSize = ReadU16(data + 12);
        out.PlaintextSize = ReadU32(data + 14);
        return out.KeyID != 0;
    }

    AeadCipherRegistry& _ciphers;
    const IKeyProvider& _keys;
    IRandomSource& _random;
    DataProtectionConfig _config;
};

}
