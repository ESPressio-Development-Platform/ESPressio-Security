#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>

#include <ESPressio_Memory.hpp>
#include <ESPressio_ThreadSafeObservable.hpp>

#include "ESPressio_AeadCipherRegistry.hpp"
#include "ESPressio_IKeyProvider.hpp"
#include "ESPressio_IRandomSource.hpp"
#include "ESPressio_ITransportSecurityObserver.hpp"
#include "ESPressio_ReplayWindow.hpp"
#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

class TransportSecurity final {
public:
    static constexpr uint32_t EnvelopeMagic = 0x53505345u;
    static constexpr uint8_t EnvelopeVersion = 1;
    static constexpr std::size_t FixedHeaderSize = 44;

private:
    static constexpr auto ExternalPreferred =
        System::Memory::MemoryPolicy::ExternalPreferred;

    class SecurityObservable final : public Observable::ThreadSafeObservable {
    private:
        template <typename Callback>
        void Notify(Callback&& callback) {
            ExecuteNotification([&](NotificationContext& notification) {
                notification.WithObservers<ITransportSecurityObserver>(
                    [&](ITransportSecurityObserver* observer) {
                        try { callback(observer); } catch (...) {}
                    }
                );
            });
        }

    public:
        void ConfigurationChanged(const TransportSecurityConfig& before, const TransportSecurityConfig& after) {
            Notify([&](ITransportSecurityObserver* observer) {
                observer->OnTransportSecurityConfigurationChanged(before, after);
            });
        }
        void SessionReset(uint64_t previousSessionID) {
            Notify([&](ITransportSecurityObserver* observer) {
                observer->OnTransportSecuritySessionReset(previousSessionID);
            });
        }
        void SessionEstablished(uint64_t sessionID) {
            Notify([&](ITransportSecurityObserver* observer) {
                observer->OnTransportSecuritySessionEstablished(sessionID);
            });
        }
        void ReplayProtectionReset() {
            Notify([](ITransportSecurityObserver* observer) {
                observer->OnTransportSecurityReplayProtectionReset();
            });
        }
        void Failure(const SecurityResult& result) {
            Notify([&](ITransportSecurityObserver* observer) {
                observer->OnTransportSecurityFailure(result);
            });
        }
    };

    AeadCipherRegistry& _ciphers;
    const IKeyProvider& _keys;
    IRandomSource& _random;
    TransportSecurityConfig _config;
    ReplayWindow _replay;
    uint64_t _sessionID = 0;
    uint64_t _nextSequence = 1;
    bool _sessionReady = false;
    std::shared_ptr<SecurityObservable> _observable;

    /// <summary>Materializes observer bookkeeping only when an observer is explicitly registered.</summary>
    bool EnsureObservable() noexcept {
        if (_observable) return true;
        try {
            _observable = System::Memory::MakeShared<
                SecurityObservable,
                ExternalPreferred
            >();
            return static_cast<bool>(_observable);
        } catch (...) {
            return false;
        }
    }

    SecurityResult ReportFailure(SecurityResult result) {
        if (_observable) _observable->Failure(result);
        return result;
    }

    bool EnsureSessionID() {
        if (_sessionReady) return true;
        if (_config.SessionID != 0) {
            _sessionID = _config.SessionID;
            _sessionReady = true;
            if (_observable) _observable->SessionEstablished(_sessionID);
            return true;
        }
        for (unsigned attempt = 0; attempt < 4; ++attempt) {
            uint64_t candidate = 0;
            if (!_random.Fill(reinterpret_cast<uint8_t*>(&candidate), sizeof(candidate))) return false;
            if (candidate != 0) {
                _sessionID = candidate;
                _sessionReady = true;
                if (_observable) _observable->SessionEstablished(_sessionID);
                return true;
            }
        }
        return false;
    }

    template<typename TBuffer>
    static void SecureErase(TBuffer& bytes) noexcept {
        volatile uint8_t* p = bytes.empty() ? nullptr : bytes.data();
        for (std::size_t i = 0; p && i < bytes.size(); ++i) p[i] = 0;
        bytes.clear();
    }

    template<typename TBuffer>
    static void Append16(TBuffer& o, uint16_t v) {
        o.push_back(static_cast<uint8_t>(v));
        o.push_back(static_cast<uint8_t>(v >> 8));
    }
    template<typename TBuffer>
    static void Append32(TBuffer& o, uint32_t v) {
        for (int i = 0; i < 4; ++i) o.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }
    template<typename TBuffer>
    static void Append64(TBuffer& o, uint64_t v) {
        for (int i = 0; i < 8; ++i) o.push_back(static_cast<uint8_t>(v >> (i * 8)));
    }

    static bool Read8(const uint8_t* i, std::size_t s, std::size_t& o, uint8_t& v) {
        if (o + 1 > s) return false; v = i[o++]; return true;
    }
    static bool Read16(const uint8_t* i, std::size_t s, std::size_t& o, uint16_t& v) {
        if (o + 2 > s) return false;
        v = static_cast<uint16_t>(i[o]) | (static_cast<uint16_t>(i[o + 1]) << 8);
        o += 2; return true;
    }
    static bool Read32(const uint8_t* i, std::size_t s, std::size_t& o, uint32_t& v) {
        if (o + 4 > s) return false; v = 0;
        for (int n = 0; n < 4; ++n) v |= static_cast<uint32_t>(i[o + n]) << (n * 8);
        o += 4; return true;
    }
    static bool Read64(const uint8_t* i, std::size_t s, std::size_t& o, uint64_t& v) {
        if (o + 8 > s) return false; v = 0;
        for (int n = 0; n < 8; ++n) v |= static_cast<uint64_t>(i[o + n]) << (n * 8);
        o += 8; return true;
    }

public:
    TransportSecurity(
        AeadCipherRegistry& ciphers,
        const IKeyProvider& keys,
        IRandomSource& random,
        TransportSecurityConfig config = {}
    ) : _ciphers(ciphers), _keys(keys), _random(random),
        _config(std::move(config)), _replay(_config.ReplayWindowSize) {
        if (_config.SessionID != 0) {
            _sessionID = _config.SessionID;
            _sessionReady = true;
        }
    }

    const TransportSecurityConfig& GetConfig() const noexcept { return _config; }
    uint64_t GetSessionID() const noexcept { return _sessionID; }

    /// <summary>Registers a transport-security observer, allocating observer infrastructure on first use.</summary>
    Observable::ObserverHandlePtr RegisterObserver(ITransportSecurityObserver* observer) {
        if (observer == nullptr || !EnsureObservable()) return {};
        return _observable->RegisterObserver(observer);
    }
    void UnregisterObserver(ITransportSecurityObserver* observer) {
        if (_observable) _observable->UnregisterObserver(observer);
    }

    void SetConfig(TransportSecurityConfig config) {
        const TransportSecurityConfig before = _config;
        const uint64_t previousSessionID = _sessionID;
        _config = std::move(config);
        _replay = ReplayWindow(_config.ReplayWindowSize);
        _nextSequence = 1;
        _sessionID = _config.SessionID;
        _sessionReady = _sessionID != 0;
        if (_observable) {
            _observable->ConfigurationChanged(before, _config);
            if (previousSessionID != 0 && previousSessionID != _sessionID) _observable->SessionReset(previousSessionID);
            if (_sessionReady && _sessionID != previousSessionID) _observable->SessionEstablished(_sessionID);
        }
    }

    void ResetReplayProtection() {
        _replay.Reset();
        if (_observable) _observable->ReplayProtectionReset();
    }

    /// <summary>Protects a transport payload into caller-selected contiguous byte storage.</summary>
    /// <typeparam name="TBuffer">Vector-compatible byte buffer supporting clear, reserve, resize, begin and data operations. Its allocator controls final envelope placement.</typeparam>
    /// <param name="protocol">Application protocol identifier authenticated into the envelope.</param>
    /// <param name="plaintext">Plaintext bytes, or null only when <paramref name="plaintextSize"/> is zero.</param>
    /// <param name="plaintextSize">Number of plaintext bytes to protect.</param>
    /// <param name="output">Destination buffer receiving the protected envelope.</param>
    /// <returns>The protection result and whether the returned payload is cryptographically protected.</returns>
    /// <remarks>The fixed header and nonce are constructed directly in final output storage. Key material is borrowed from the provider, so protection performs no per-operation key allocation or copy.</remarks>
    template<typename TBuffer>
    SecurityResult Protect(
        uint8_t protocol,
        const uint8_t* plaintext,
        std::size_t plaintextSize,
        TBuffer& output
    ) {
        output.clear();
        if ((plaintext == nullptr && plaintextSize != 0) || plaintextSize > _config.MaximumPlaintextBytes) {
            return ReportFailure(SecurityResult::Fail(SecurityError::InvalidArgument, "Invalid or oversized plaintext payload"));
        }

        if (_config.Policy == TransportSecurityPolicy::Disabled) {
            if (plaintextSize) output.assign(plaintext, plaintext + plaintextSize);
            return SecurityResult::Ok(false);
        }

        IAeadCipher* cipher = _ciphers.Find(_config.OutboundAlgorithm);
        KeyMaterialView key;
        const bool haveKey = _keys.GetKey(_config.OutboundKeyID, _config.OutboundAlgorithm, key);
        if (cipher == nullptr || !haveKey) {
            if (_config.Policy == TransportSecurityPolicy::Preferred) {
                if (plaintextSize) output.assign(plaintext, plaintext + plaintextSize);
                return SecurityResult::Ok(false);
            }
            return ReportFailure(SecurityResult::Fail(
                cipher == nullptr ? SecurityError::UnsupportedAlgorithm : SecurityError::MissingKey,
                cipher == nullptr ? "Outbound AEAD algorithm is not registered" : "Outbound key is unavailable"
            ));
        }
        if (key.Size != cipher->KeySize()) {
            return ReportFailure(SecurityResult::Fail(SecurityError::InvalidKeyLength, "Outbound key length does not match AEAD algorithm"));
        }
        if (!EnsureSessionID()) {
            return ReportFailure(SecurityResult::Fail(SecurityError::RandomFailure, "Transport security session ID generation failed"));
        }
        if (_nextSequence == 0 || _nextSequence == std::numeric_limits<uint64_t>::max()) {
            return ReportFailure(SecurityResult::Fail(SecurityError::SequenceExhausted, "Outbound sequence exhausted; establish a new session before continuing"));
        }

        const std::size_t nonceSize = cipher->NonceSize();
        const std::size_t tagSize = cipher->TagSize();
        if (nonceSize > 0xFFu || tagSize > 0xFFu || plaintextSize > 0xFFFFFFFFu) {
            return ReportFailure(SecurityResult::Fail(SecurityError::BufferLimitExceeded, "Transport security envelope fields exceed wire-format limits"));
        }

        const uint64_t sequence = _nextSequence++;
        const std::size_t ciphertextOffset = FixedHeaderSize + nonceSize;
        const std::size_t tagOffset = ciphertextOffset + plaintextSize;
        const std::size_t totalSize = tagOffset + tagSize;

        try {
            output.reserve(totalSize);
            Append32(output, EnvelopeMagic);
            output.push_back(EnvelopeVersion);
            output.push_back(static_cast<uint8_t>(cipher->Algorithm()));
            output.push_back(0);
            output.push_back(protocol);
            Append32(output, _config.OutboundKeyID);
            Append64(output, _config.SenderID);
            Append64(output, _sessionID);
            Append64(output, sequence);
            output.push_back(static_cast<uint8_t>(nonceSize));
            output.push_back(static_cast<uint8_t>(tagSize));
            Append16(output, 0);
            Append32(output, static_cast<uint32_t>(plaintextSize));
            if (output.size() != FixedHeaderSize) {
                SecureErase(output);
                return ReportFailure(SecurityResult::Fail(SecurityError::MalformedEnvelope, "Transport security header size is inconsistent"));
            }
            output.resize(totalSize);
        } catch (...) {
            SecureErase(output);
            return ReportFailure(SecurityResult::Fail(SecurityError::BufferLimitExceeded, "Protected output allocation failed"));
        }

        uint8_t* const nonce = output.data() + FixedHeaderSize;
        if (!_random.Fill(nonce, nonceSize)) {
            SecureErase(output);
            return ReportFailure(SecurityResult::Fail(SecurityError::RandomFailure, "Cryptographic nonce generation failed"));
        }

        const bool encrypted = cipher->Seal(
            key.Data, key.Size,
            nonce, nonceSize,
            output.data(), FixedHeaderSize,
            plaintext, plaintextSize,
            output.data() + ciphertextOffset, plaintextSize,
            output.data() + tagOffset, tagSize
        );
        if (!encrypted) {
            SecureErase(output);
            return ReportFailure(SecurityResult::Fail(SecurityError::EncryptionFailed, "AEAD encryption failed"));
        }
        return SecurityResult::Ok(true);
    }

    /// <summary>Authenticates and decrypts a transport envelope using borrowed key material.</summary>
    SecurityResult Unprotect(
        uint8_t expectedProtocol,
        const uint8_t* input,
        std::size_t inputSize,
        UnprotectedPayload& output
    ) {
        output = {};
        if (input == nullptr && inputSize != 0) {
            return ReportFailure(SecurityResult::Fail(SecurityError::InvalidArgument, "Invalid protected input"));
        }
        if (!LooksProtected(input, inputSize)) {
            if (_config.Policy == TransportSecurityPolicy::Required) {
                return ReportFailure(SecurityResult::Fail(SecurityError::PlaintextRejected, "Plaintext transport payload rejected by Required policy"));
            }
            output.Protocol = expectedProtocol;
            output.Protected = false;
            if (inputSize) output.Data.assign(input, input + inputSize);
            return SecurityResult::Ok(false);
        }
        if (inputSize < FixedHeaderSize) {
            return ReportFailure(SecurityResult::Fail(SecurityError::MalformedEnvelope, "Transport security envelope is truncated"));
        }

        std::size_t offset = 0;
        uint32_t magic = 0, keyID = 0, ciphertextLength = 0;
        uint64_t senderID = 0, sessionID = 0, sequence = 0;
        uint16_t reserved = 0;
        uint8_t version = 0, algorithmRaw = 0, flags = 0, protocol = 0, nonceLength = 0, tagLength = 0;
        if (!Read32(input,inputSize,offset,magic) || !Read8(input,inputSize,offset,version) || !Read8(input,inputSize,offset,algorithmRaw) ||
            !Read8(input,inputSize,offset,flags) || !Read8(input,inputSize,offset,protocol) || !Read32(input,inputSize,offset,keyID) ||
            !Read64(input,inputSize,offset,senderID) || !Read64(input,inputSize,offset,sessionID) || !Read64(input,inputSize,offset,sequence) ||
            !Read8(input,inputSize,offset,nonceLength) || !Read8(input,inputSize,offset,tagLength) || !Read16(input,inputSize,offset,reserved) ||
            !Read32(input,inputSize,offset,ciphertextLength)) {
            return ReportFailure(SecurityResult::Fail(SecurityError::MalformedEnvelope, "Transport security header is malformed"));
        }
        (void)flags;
        (void)reserved;

        if (magic != EnvelopeMagic || version != EnvelopeVersion) {
            return ReportFailure(SecurityResult::Fail(
                version != EnvelopeVersion ? SecurityError::UnsupportedVersion : SecurityError::MalformedEnvelope,
                version != EnvelopeVersion ? "Unsupported transport security envelope version" : "Invalid transport security envelope magic"
            ));
        }
        if (ciphertextLength > _config.MaximumPlaintextBytes) {
            return ReportFailure(SecurityResult::Fail(SecurityError::BufferLimitExceeded, "Protected payload exceeds configured limit"));
        }
        const std::size_t expectedSize = FixedHeaderSize + nonceLength + ciphertextLength + tagLength;
        if (expectedSize != inputSize || sessionID == 0 || sequence == 0 || keyID == 0) {
            return ReportFailure(SecurityResult::Fail(SecurityError::MalformedEnvelope, "Transport security envelope lengths or identifiers are inconsistent"));
        }

        const AeadAlgorithm algorithm = static_cast<AeadAlgorithm>(algorithmRaw);
        IAeadCipher* cipher = _ciphers.Find(algorithm);
        if (cipher == nullptr) {
            return ReportFailure(SecurityResult::Fail(SecurityError::UnsupportedAlgorithm, "Inbound AEAD algorithm is not registered"));
        }
        if (nonceLength != cipher->NonceSize() || tagLength != cipher->TagSize()) {
            return ReportFailure(SecurityResult::Fail(SecurityError::MalformedEnvelope, "Nonce/tag size does not match AEAD algorithm"));
        }
        if (!_replay.WouldAccept(senderID, keyID, sessionID, sequence)) {
            return ReportFailure(SecurityResult::Fail(SecurityError::ReplayDetected, "Replay or stale protected transport payload rejected"));
        }

        KeyMaterialView key;
        if (!_keys.GetKey(keyID, algorithm, key)) {
            return ReportFailure(SecurityResult::Fail(SecurityError::MissingKey, "Inbound key is unavailable"));
        }
        if (key.Size != cipher->KeySize()) {
            return ReportFailure(SecurityResult::Fail(SecurityError::InvalidKeyLength, "Inbound key length does not match AEAD algorithm"));
        }

        const uint8_t* nonce = input + FixedHeaderSize;
        const uint8_t* ciphertext = nonce + nonceLength;
        const uint8_t* tag = ciphertext + ciphertextLength;
        output.Data.resize(ciphertextLength);
        const bool authenticated = cipher->Open(
            key.Data, key.Size,
            nonce, nonceLength,
            input, FixedHeaderSize,
            ciphertext, ciphertextLength,
            tag, tagLength,
            output.Data.data(), output.Data.size()
        );
        if (!authenticated) {
            SecureErase(output.Data);
            return ReportFailure(SecurityResult::Fail(SecurityError::AuthenticationFailed, "AEAD authentication/decryption failed"));
        }
        if (protocol != expectedProtocol) {
            SecureErase(output.Data);
            return ReportFailure(SecurityResult::Fail(SecurityError::ProtocolMismatch, "Authenticated payload protocol does not match expected transport protocol"));
        }

        _replay.Commit(senderID, keyID, sessionID, sequence);
        output.Protocol = protocol;
        output.KeyID = keyID;
        output.SenderID = senderID;
        output.SessionID = sessionID;
        output.Sequence = sequence;
        output.Algorithm = algorithm;
        output.Protected = true;
        return SecurityResult::Ok(true);
    }

    static bool LooksProtected(const uint8_t* input, std::size_t inputSize) {
        if (input == nullptr || inputSize < 4) return false;
        return (static_cast<uint32_t>(input[0]) |
            (static_cast<uint32_t>(input[1]) << 8) |
            (static_cast<uint32_t>(input[2]) << 16) |
            (static_cast<uint32_t>(input[3]) << 24)) == EnvelopeMagic;
    }
};

} // namespace ESPressio::Security