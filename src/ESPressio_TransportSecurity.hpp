#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

#include <ESPressio_ThreadSafeObservable.hpp>

#include "ESPressio_AeadCipherRegistry.hpp"
#include "ESPressio_IKeyProvider.hpp"
#include "ESPressio_IRandomSource.hpp"
#include "ESPressio_ITransportSecurityObserver.hpp"
#include "ESPressio_ReplayWindow.hpp"
#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

/// <summary>Applies configurable authenticated transport protection, session sequencing, key lookup, and replay prevention.</summary>
/// <remarks>The engine is transport-agnostic: callers provide a protocol discriminator and raw payload bytes, while registered AEAD ciphers, key providers, and random sources supply cryptographic primitives.</remarks>
class TransportSecurity final {
public:
    /// <summary>Magic value identifying an ESPressio protected transport envelope.</summary>
    static constexpr uint32_t EnvelopeMagic = 0x53505345u;
    /// <summary>Current protected transport envelope format version.</summary>
    static constexpr uint8_t EnvelopeVersion = 1;
    /// <summary>Number of fixed header bytes preceding nonce, ciphertext, and authentication tag.</summary>
    static constexpr std::size_t FixedHeaderSize = 44;

private:
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
    std::shared_ptr<SecurityObservable> _observable = std::make_shared<SecurityObservable>();

    SecurityResult ReportFailure(SecurityResult result) {
        _observable->Failure(result);
        return result;
    }

    bool EnsureSessionID() {
        if (_sessionReady) return true;
        if (_config.SessionID != 0) {
            _sessionID = _config.SessionID;
            _sessionReady = true;
            _observable->SessionEstablished(_sessionID);
            return true;
        }
        for (unsigned attempt = 0; attempt < 4; ++attempt) {
            uint64_t candidate = 0;
            if (!_random.Fill(reinterpret_cast<uint8_t*>(&candidate), sizeof(candidate))) return false;
            if (candidate != 0) {
                _sessionID = candidate;
                _sessionReady = true;
                _observable->SessionEstablished(_sessionID);
                return true;
            }
        }
        return false;
    }

    static void SecureErase(std::vector<uint8_t>& bytes) noexcept {
        volatile uint8_t* p = bytes.empty() ? nullptr : bytes.data();
        for (std::size_t i = 0; p && i < bytes.size(); ++i) p[i] = 0;
        bytes.clear();
    }
    static void Append16(std::vector<uint8_t>& o, uint16_t v) { o.push_back(static_cast<uint8_t>(v)); o.push_back(static_cast<uint8_t>(v >> 8)); }
    static void Append32(std::vector<uint8_t>& o, uint32_t v) { for (int i=0;i<4;++i) o.push_back(static_cast<uint8_t>(v >> (i*8))); }
    static void Append64(std::vector<uint8_t>& o, uint64_t v) { for (int i=0;i<8;++i) o.push_back(static_cast<uint8_t>(v >> (i*8))); }
    static bool Read8(const uint8_t* i,std::size_t s,std::size_t& o,uint8_t& v){if(o+1>s)return false;v=i[o++];return true;}
    static bool Read16(const uint8_t* i,std::size_t s,std::size_t& o,uint16_t& v){if(o+2>s)return false;v=static_cast<uint16_t>(i[o])|(static_cast<uint16_t>(i[o+1])<<8);o+=2;return true;}
    static bool Read32(const uint8_t* i,std::size_t s,std::size_t& o,uint32_t& v){if(o+4>s)return false;v=0;for(int n=0;n<4;++n)v|=static_cast<uint32_t>(i[o+n])<<(n*8);o+=4;return true;}
    static bool Read64(const uint8_t* i,std::size_t s,std::size_t& o,uint64_t& v){if(o+8>s)return false;v=0;for(int n=0;n<8;++n)v|=static_cast<uint64_t>(i[o+n])<<(n*8);o+=8;return true;}

public:
    /// <summary>Creates a transport-security engine using the supplied cipher registry, key source, random source, and policy.</summary>
    /// <param name="ciphers">Registry used to resolve configured AEAD algorithms.</param>
    /// <param name="keys">Key provider used for outbound and inbound key lookup.</param>
    /// <param name="random">Cryptographically suitable random source used for generated session IDs and nonces.</param>
    /// <param name="config">Initial transport-security configuration.</param>
    TransportSecurity(AeadCipherRegistry& ciphers, const IKeyProvider& keys, IRandomSource& random, TransportSecurityConfig config = {})
        : _ciphers(ciphers), _keys(keys), _random(random), _config(std::move(config)), _replay(_config.ReplayWindowSize) {
        if (_config.SessionID != 0) {
            _sessionID = _config.SessionID;
            _sessionReady = true;
        }
    }

    /// <summary>Returns the active transport-security configuration.</summary>
    const TransportSecurityConfig& GetConfig() const noexcept { return _config; }
    /// <summary>Returns the current outbound session identifier, or zero until a session is established.</summary>
    uint64_t GetSessionID() const noexcept { return _sessionID; }

    /// <summary>Registers an observer for configuration, session, replay-protection, and failure notifications.</summary>
    Observable::ObserverHandlePtr RegisterObserver(ITransportSecurityObserver* observer) {
        return _observable->RegisterObserver(observer);
    }
    /// <summary>Explicitly unregisters a transport-security observer.</summary>
    void UnregisterObserver(ITransportSecurityObserver* observer) {
        _observable->UnregisterObserver(observer);
    }

    /// <summary>Replaces the active configuration and resets sequence/replay state for the new policy.</summary>
    /// <remarks>Changing configuration resets the outbound sequence to one, rebuilds the replay window, and emits session reset/established notifications when the configured session identity changes.</remarks>
    void SetConfig(TransportSecurityConfig config) {
        const TransportSecurityConfig before = _config;
        const uint64_t previousSessionID = _sessionID;
        _config = std::move(config);
        _replay = ReplayWindow(_config.ReplayWindowSize);
        _nextSequence = 1;
        _sessionID = _config.SessionID;
        _sessionReady = _sessionID != 0;
        _observable->ConfigurationChanged(before, _config);
        if (previousSessionID != 0 && previousSessionID != _sessionID) _observable->SessionReset(previousSessionID);
        if (_sessionReady && _sessionID != previousSessionID) _observable->SessionEstablished(_sessionID);
    }

    /// <summary>Clears all retained inbound replay-window state.</summary>
    void ResetReplayProtection() {
        _replay.Reset();
        _observable->ReplayProtectionReset();
    }

    /// <summary>Protects an outbound payload according to the configured security policy.</summary>
    /// <param name="protocol">Transport/application protocol discriminator authenticated by the envelope.</param>
    /// <param name="plaintext">Plaintext payload bytes.</param>
    /// <param name="plaintextSize">Plaintext size in bytes.</param>
    /// <param name="output">Receives either a protected envelope or, when policy permits fallback, the original plaintext.</param>
    /// <returns>A detailed security result indicating success, failure, and whether protection was applied.</returns>
    /// <remarks>Successful protected output carries a session ID, strictly increasing sequence number, random nonce, authenticated fixed header, ciphertext, and AEAD tag. Sensitive key and transient cryptographic buffers are explicitly erased before return where applicable.</remarks>
    SecurityResult Protect(uint8_t protocol, const uint8_t* plaintext, std::size_t plaintextSize, std::vector<uint8_t>& output) {
        output.clear();
        if ((plaintext == nullptr && plaintextSize != 0) || plaintextSize > _config.MaximumPlaintextBytes)
            return ReportFailure(SecurityResult::Fail(SecurityError::InvalidArgument, "Invalid or oversized plaintext payload"));

        if (_config.Policy == TransportSecurityPolicy::Disabled) {
            if (plaintextSize) output.assign(plaintext, plaintext + plaintextSize);
            return SecurityResult::Ok(false);
        }

        IAeadCipher* cipher = _ciphers.Find(_config.OutboundAlgorithm);
        KeyMaterial key;
        const bool haveKey = _keys.GetKey(_config.OutboundKeyID, _config.OutboundAlgorithm, key);
        if (cipher == nullptr || !haveKey) {
            if (_config.Policy == TransportSecurityPolicy::Preferred) {
                if (plaintextSize) output.assign(plaintext, plaintext + plaintextSize);
                SecureErase(key.Bytes);
                return SecurityResult::Ok(false);
            }
            SecureErase(key.Bytes);
            return ReportFailure(SecurityResult::Fail(cipher == nullptr ? SecurityError::UnsupportedAlgorithm : SecurityError::MissingKey,
                cipher == nullptr ? "Outbound AEAD algorithm is not registered" : "Outbound key is unavailable"));
        }
        if (key.Bytes.size() != cipher->KeySize()) {
            SecureErase(key.Bytes);
            return ReportFailure(SecurityResult::Fail(SecurityError::InvalidKeyLength, "Outbound key length does not match AEAD algorithm"));
        }
        if (!EnsureSessionID()) {
            SecureErase(key.Bytes);
            return ReportFailure(SecurityResult::Fail(SecurityError::RandomFailure, "Transport security session ID generation failed"));
        }
        if (_nextSequence == 0 || _nextSequence == std::numeric_limits<uint64_t>::max()) {
            SecureErase(key.Bytes);
            return ReportFailure(SecurityResult::Fail(SecurityError::SequenceExhausted, "Outbound sequence exhausted; establish a new session before continuing"));
        }

        const uint64_t sequence = _nextSequence++;
        std::vector<uint8_t> nonce(cipher->NonceSize());
        if (!_random.Fill(nonce.data(), nonce.size())) {
            SecureErase(key.Bytes); SecureErase(nonce);
            return ReportFailure(SecurityResult::Fail(SecurityError::RandomFailure, "Cryptographic nonce generation failed"));
        }

        std::vector<uint8_t> header;
        header.reserve(FixedHeaderSize);
        Append32(header, EnvelopeMagic);
        header.push_back(EnvelopeVersion);
        header.push_back(static_cast<uint8_t>(cipher->Algorithm()));
        header.push_back(0);
        header.push_back(protocol);
        Append32(header, _config.OutboundKeyID);
        Append64(header, _config.SenderID);
        Append64(header, _sessionID);
        Append64(header, sequence);
        header.push_back(static_cast<uint8_t>(nonce.size()));
        header.push_back(static_cast<uint8_t>(cipher->TagSize()));
        Append16(header, 0);
        Append32(header, static_cast<uint32_t>(plaintextSize));

        std::vector<uint8_t> ciphertext, tag;
        const bool encrypted = cipher->Seal(key.Bytes.data(), key.Bytes.size(), nonce.data(), nonce.size(), header.data(), header.size(),
            plaintext, plaintextSize, ciphertext, tag);
        SecureErase(key.Bytes);
        if (!encrypted || ciphertext.size() != plaintextSize || tag.size() != cipher->TagSize()) {
            SecureErase(nonce); SecureErase(ciphertext); SecureErase(tag);
            return ReportFailure(SecurityResult::Fail(SecurityError::EncryptionFailed, "AEAD encryption failed"));
        }

        output.reserve(header.size() + nonce.size() + ciphertext.size() + tag.size());
        output.insert(output.end(), header.begin(), header.end());
        output.insert(output.end(), nonce.begin(), nonce.end());
        output.insert(output.end(), ciphertext.begin(), ciphertext.end());
        output.insert(output.end(), tag.begin(), tag.end());
        SecureErase(nonce); SecureErase(ciphertext); SecureErase(tag);
        return SecurityResult::Ok(true);
    }

    /// <summary>Authenticates and opens an inbound payload according to the configured security policy and replay window.</summary>
    /// <param name="expectedProtocol">Protocol discriminator expected by the receiving transport.</param>
    /// <param name="input">Inbound protected envelope or permitted plaintext bytes.</param>
    /// <param name="inputSize">Inbound byte count.</param>
    /// <param name="output">Receives authenticated metadata and plaintext on success.</param>
    /// <returns>A detailed result indicating whether the payload was accepted and whether it was cryptographically protected.</returns>
    /// <remarks>Replay state is committed only after successful AEAD authentication and protocol validation, so malformed or unauthenticated traffic cannot advance the replay window.</remarks>
    SecurityResult Unprotect(uint8_t expectedProtocol, const uint8_t* input, std::size_t inputSize, UnprotectedPayload& output) {
        output = {};
        if (input == nullptr && inputSize != 0) return ReportFailure(SecurityResult::Fail(SecurityError::InvalidArgument, "Invalid protected input"));
        if (!LooksProtected(input, inputSize)) {
            if (_config.Policy == TransportSecurityPolicy::Required)
                return ReportFailure(SecurityResult::Fail(SecurityError::PlaintextRejected, "Plaintext transport payload rejected by Required policy"));
            output.Protocol = expectedProtocol; output.Protected = false;
            if (inputSize) output.Data.assign(input, input + inputSize);
            return SecurityResult::Ok(false);
        }
        if (inputSize < FixedHeaderSize) return ReportFailure(SecurityResult::Fail(SecurityError::MalformedEnvelope, "Transport security envelope is truncated"));

        std::size_t offset = 0;
        uint32_t magic = 0, keyID = 0, ciphertextLength = 0;
        uint64_t senderID = 0, sessionID = 0, sequence = 0;
        uint16_t reserved = 0;
        uint8_t version = 0, algorithmRaw = 0, flags = 0, protocol = 0, nonceLength = 0, tagLength = 0;
        if (!Read32(input,inputSize,offset,magic)||!Read8(input,inputSize,offset,version)||!Read8(input,inputSize,offset,algorithmRaw)||
            !Read8(input,inputSize,offset,flags)||!Read8(input,inputSize,offset,protocol)||!Read32(input,inputSize,offset,keyID)||
            !Read64(input,inputSize,offset,senderID)||!Read64(input,inputSize,offset,sessionID)||!Read64(input,inputSize,offset,sequence)||
            !Read8(input,inputSize,offset,nonceLength)||!Read8(input,inputSize,offset,tagLength)||!Read16(input,inputSize,offset,reserved)||
            !Read32(input,inputSize,offset,ciphertextLength))
            return ReportFailure(SecurityResult::Fail(SecurityError::MalformedEnvelope, "Transport security header is malformed"));
        (void)flags; (void)reserved;
        if (magic != EnvelopeMagic || version != EnvelopeVersion)
            return ReportFailure(SecurityResult::Fail(version != EnvelopeVersion ? SecurityError::UnsupportedVersion : SecurityError::MalformedEnvelope,
                version != EnvelopeVersion ? "Unsupported transport security envelope version" : "Invalid transport security envelope magic"));
        if (ciphertextLength > _config.MaximumPlaintextBytes) return ReportFailure(SecurityResult::Fail(SecurityError::BufferLimitExceeded, "Protected payload exceeds configured limit"));
        const std::size_t expectedSize = FixedHeaderSize + nonceLength + ciphertextLength + tagLength;
        if (expectedSize != inputSize || sessionID == 0 || sequence == 0 || keyID == 0)
            return ReportFailure(SecurityResult::Fail(SecurityError::MalformedEnvelope, "Transport security envelope lengths or identifiers are inconsistent"));

        const AeadAlgorithm algorithm = static_cast<AeadAlgorithm>(algorithmRaw);
        IAeadCipher* cipher = _ciphers.Find(algorithm);
        if (cipher == nullptr) return ReportFailure(SecurityResult::Fail(SecurityError::UnsupportedAlgorithm, "Inbound AEAD algorithm is not registered"));
        if (nonceLength != cipher->NonceSize() || tagLength != cipher->TagSize())
            return ReportFailure(SecurityResult::Fail(SecurityError::MalformedEnvelope, "Nonce/tag size does not match AEAD algorithm"));
        if (!_replay.WouldAccept(senderID, keyID, sessionID, sequence))
            return ReportFailure(SecurityResult::Fail(SecurityError::ReplayDetected, "Replay or stale protected transport payload rejected"));

        KeyMaterial key;
        if (!_keys.GetKey(keyID,algorithm,key)) return ReportFailure(SecurityResult::Fail(SecurityError::MissingKey, "Inbound key is unavailable"));
        if (key.Bytes.size()!=cipher->KeySize()) { SecureErase(key.Bytes); return ReportFailure(SecurityResult::Fail(SecurityError::InvalidKeyLength, "Inbound key length does not match AEAD algorithm")); }

        const uint8_t* nonce=input+FixedHeaderSize;
        const uint8_t* ciphertext=nonce+nonceLength;
        const uint8_t* tag=ciphertext+ciphertextLength;
        std::vector<uint8_t> plaintext;
        const bool authenticated=cipher->Open(key.Bytes.data(),key.Bytes.size(),nonce,nonceLength,input,FixedHeaderSize,ciphertext,ciphertextLength,tag,tagLength,plaintext);
        SecureErase(key.Bytes);
        if (!authenticated) { SecureErase(plaintext); return ReportFailure(SecurityResult::Fail(SecurityError::AuthenticationFailed, "AEAD authentication/decryption failed")); }
        if (protocol != expectedProtocol) { SecureErase(plaintext); return ReportFailure(SecurityResult::Fail(SecurityError::ProtocolMismatch, "Authenticated payload protocol does not match expected transport protocol")); }

        _replay.Commit(senderID, keyID, sessionID, sequence);
        output.Protocol=protocol;
        output.KeyID=keyID;
        output.SenderID=senderID;
        output.SessionID=sessionID;
        output.Sequence=sequence;
        output.Algorithm=algorithm;
        output.Protected=true;
        output.Data=std::move(plaintext);
        return SecurityResult::Ok(true);
    }

    /// <summary>Tests whether an input begins with the ESPressio protected-envelope magic value.</summary>
    static bool LooksProtected(const uint8_t* input, std::size_t inputSize) {
        if (input == nullptr || inputSize < 4) return false;
        return (static_cast<uint32_t>(input[0]) | (static_cast<uint32_t>(input[1])<<8) |
            (static_cast<uint32_t>(input[2])<<16) | (static_cast<uint32_t>(input[3])<<24)) == EnvelopeMagic;
    }
};

} // namespace ESPressio::Security