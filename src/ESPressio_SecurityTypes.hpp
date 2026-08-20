#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ESPressio::Security {

constexpr uint32_t ESPRESSIO_SECURITY_VERSION_MAJOR = 0;
constexpr uint32_t ESPRESSIO_SECURITY_VERSION_MINOR = 2;
constexpr uint32_t ESPRESSIO_SECURITY_VERSION_PATCH = 0;
constexpr const char* ESPRESSIO_SECURITY_VERSION = "0.2.0";

enum class AeadAlgorithm : uint8_t {
    Unknown = 0,
    AES128GCM = 1,
    AES256GCM = 2,
    AES128CCM = 3,
    AES256CCM = 4,
    ChaCha20Poly1305 = 5,
    TestOnly = 250
};

enum class TransportSecurityPolicy : uint8_t {
    Disabled = 0,
    Preferred = 1,
    Required = 2
};

enum class SecurityError : uint8_t {
    None = 0,
    InvalidArgument,
    PlaintextRejected,
    MalformedEnvelope,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    MissingKey,
    InvalidKeyLength,
    RandomFailure,
    EncryptionFailed,
    AuthenticationFailed,
    ProtocolMismatch,
    ReplayDetected,
    SequenceExhausted,
    BufferLimitExceeded
};

struct SecurityResult {
    bool Success = false;
    bool Protected = false;
    SecurityError Error = SecurityError::None;
    std::string Message;

    static SecurityResult Ok(bool protectedPayload = true) {
        return {true, protectedPayload, SecurityError::None, {}};
    }

    static SecurityResult Fail(SecurityError error, std::string message) {
        return {false, false, error, std::move(message)};
    }
};

struct KeyMaterial {
    uint32_t KeyID = 0;
    std::vector<uint8_t> Bytes;
};

struct TransportSecurityConfig {
    TransportSecurityPolicy Policy = TransportSecurityPolicy::Required;
    AeadAlgorithm OutboundAlgorithm = AeadAlgorithm::AES256GCM;
    uint32_t OutboundKeyID = 1;
    uint64_t SenderID = 0;

    /*
     * Authenticated sender-session/epoch identifier. Zero means generate a
     * fresh non-zero value from IRandomSource when the first protected packet
     * is produced. Applications may supply a non-zero value when session
     * identity is provisioned externally or deterministic behavior is needed.
     */
    uint64_t SessionID = 0;

    std::size_t MaximumPlaintextBytes = 16384;
    std::size_t ReplayWindowSize = 64;
};

struct UnprotectedPayload {
    uint8_t Protocol = 0;
    uint32_t KeyID = 0;
    uint64_t SenderID = 0;
    uint64_t SessionID = 0;
    uint64_t Sequence = 0;
    AeadAlgorithm Algorithm = AeadAlgorithm::Unknown;
    bool Protected = false;
    std::vector<uint8_t> Data;
};

}
