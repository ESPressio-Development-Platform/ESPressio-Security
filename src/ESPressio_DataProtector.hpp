#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

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
        std::vector<uint8_t>& protectedData,
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

        ExternalBytes nonce(cipher->NonceSize());
        if (!_random.Fill(nonce.data(), nonce.size())) {
            StaticKeyProvider::SecureErase(key.Bytes);
            return SecurityResult::Fail(SecurityError::RandomFailure, "Unable to generate data-protection nonce");
        }

        // The serialized header is itself the first part of AEAD AAD. Build it
        // directly in the AAD buffer instead of materialising header + copied AAD.
        ExternalBytes aad;
        aad.reserve(HeaderSize + context.Size);
        AppendHeader(
            aad,
            _config.Algorithm,
            _config.KeyID,
            static_cast<uint16_t>(nonce.size()),
            static_cast<uint16_t>(cipher->TagSize()),
            static_cast<uint32_t>(plaintextSize)
        );
        if (context.Size != 0) {
            aad.insert(aad.end(), context.Data, context.Data + context.Size);
        }

        // IAeadCipher intentionally retains its existing std::vector contract.
        // These are output buffers rather than duplicated framing scratch.
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> tag;
        const bool sealed = cipher->Seal(
            key.Bytes.data(), key.Bytes.size(),
            nonce.data(), nonce.size(),
            aad.data(), aad.size(),
            plaintext, plaintextSize,
            ciphertext, tag
        );
        StaticKeyProvider::SecureErase(key.Bytes);
        if (!sealed || tag.size() != cipher->TagSize()) {
            return SecurityResult::Fail(SecurityError::EncryptionFailed, "Authenticated data protection failed");
        }

        protectedData.reserve(HeaderSize + nonce.size() + tag.size() + ciphertext.size());
        protectedData.insert(protectedData.end(), aad.begin(), aad.begin() + HeaderSize);
        protectedData.insert(protectedData.end(), nonce.begin(), nonce.end());
        protectedData.insert(protectedData.end(), tag.begin(), tag.end());
        protectedData.insert(protectedData.end(), ciphertext.begin(), ciphertext.end());
        return SecurityResult::Ok(true);
    }

    SecurityResult Unprotect(
        const uint8_t* protectedData,
        std::size_t protectedDataSize,
        std::vector<uint8_t>& plaintext,
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
        ExternalBytes aad;
        aad.reserve(HeaderSize + context.Size);
        aad.insert(aad.end(), protectedData, protectedData + HeaderSize);
        if (context.Size != 0) {
            aad.insert(aad.end(), context.Data, context.Data + context.Size);
        }

        const bool opened = cipher->Open(
            key.Bytes.data(), key.Bytes.size(),
            nonce, decoded.NonceSize,
            aad.data(), aad.size(),
            ciphertext, decoded.PlaintextSize,
            tag, decoded.TagSize,
            plaintext
        );
        StaticKeyProvider::SecureErase(key.Bytes);
        if (!opened || plaintext.size() != decoded.PlaintextSize) {
            plaintext.clear();
            return SecurityResult::Fail(SecurityError::AuthenticationFailed, "Protected data could not be authenticated or decrypted");
        }
        return SecurityResult::Ok(true);
    }

private:
    using ExternalBytes = System::Memory::Vector<
        uint8_t,
        System::Memory::MemoryPolicy::ExternalPreferred
    >;

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

    template<typename TBuffer>
    static void AppendU16(TBuffer& out, uint16_t value) {
        out.push_back(static_cast<uint8_t>(value));
        out.push_back(static_cast<uint8_t>(value >> 8u));
    }

    template<typename TBuffer>
    static void AppendU32(TBuffer& out, uint32_t value) {
        for (unsigned shift = 0; shift < 32; shift += 8) {
            out.push_back(static_cast<uint8_t>(value >> shift));
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

    template<typename TBuffer>
    static void AppendHeader(
        TBuffer& out,
        AeadAlgorithm algorithm,
        uint32_t keyID,
        uint16_t nonceSize,
        uint16_t tagSize,
        uint32_t plaintextSize
    ) {
        out.clear();
        out.insert(out.end(), {'E','S','D','P', FormatVersion, static_cast<uint8_t>(algorithm)});
        AppendU32(out, keyID);
        AppendU16(out, nonceSize);
        AppendU16(out, tagSize);
        AppendU32(out, plaintextSize);
    }

    static bool ReadHeader(const uint8_t* data, std::size_t size, Header& out) {
        if (size < HeaderSize || data[0] != 'E' || data[1] != 'S' || data[2] != 'D' || data[3] != 'P') return false;
        out.Version = data[4]; out.Algorithm = static_cast<AeadAlgorithm>(data[5]);
        out.KeyID = ReadU32(data + 6); out.NonceSize = ReadU16(data + 10); out.TagSize = ReadU16(data + 12);
        out.PlaintextSize = ReadU32(data + 14); return out.KeyID != 0;
    }

    AeadCipherRegistry& _ciphers;
    const IKeyProvider& _keys;
    IRandomSource& _random;
    DataProtectionConfig _config;
};

} // namespace ESPressio::Security
