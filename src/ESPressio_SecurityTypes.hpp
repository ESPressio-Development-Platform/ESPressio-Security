#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>

#include <ESPressio_Memory.hpp>

namespace ESPressio::Security {

constexpr uint32_t ESPRESSIO_SECURITY_VERSION_MAJOR = 0;
constexpr uint32_t ESPRESSIO_SECURITY_VERSION_MINOR = 4;
constexpr uint32_t ESPRESSIO_SECURITY_VERSION_PATCH = 0;
constexpr const char* ESPRESSIO_SECURITY_VERSION = "0.4.0";

/// <summary>Externally preferred byte storage used for non-DMA security payload and key material.</summary>
using SecurityBuffer = System::Memory::Vector<
    uint8_t,
    System::Memory::MemoryPolicy::ExternalPreferred
>;

/// <summary>Externally preferred text storage used for security diagnostics.</summary>
using SecurityString = System::Memory::String<
    System::Memory::MemoryPolicy::ExternalPreferred
>;

/// <summary>Identifies the authenticated-encryption algorithm used by a protected payload.</summary>
enum class AeadAlgorithm : uint8_t {
    Unknown = 0,
    AES128GCM = 1,
    AES256GCM = 2,
    AES128CCM = 3,
    AES256CCM = 4,
    ChaCha20Poly1305 = 5,
    TestOnly = 250
};

/// <summary>Controls whether transport payload protection is disabled, opportunistic, or mandatory.</summary>
enum class TransportSecurityPolicy : uint8_t {
    Disabled = 0,
    Preferred = 1,
    Required = 2
};

/// <summary>Identifies portable failures that can occur while protecting or unprotecting transport data.</summary>
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

/// <summary>Reports the outcome of a security operation together with protection state and diagnostic detail.</summary>
struct SecurityResult {
    bool Success = false;
    bool Protected = false;
    SecurityError Error = SecurityError::None;
    SecurityString Message;

    /// <summary>Creates a successful security result without allocating diagnostic text.</summary>
    static SecurityResult Ok(bool protectedPayload = true) {
        return {true, protectedPayload, SecurityError::None, {}};
    }

    /// <summary>Creates a failed result with diagnostic text retained in externally preferred storage.</summary>
    static SecurityResult Fail(SecurityError error, std::string_view message) {
        SecurityResult result;
        result.Success = false;
        result.Protected = false;
        result.Error = error;
        result.Message.assign(message.data(), message.size());
        return result;
    }
};

/// <summary>Immutable shared backing storage for borrowed cryptographic key views.</summary>
/// <remarks>Key bytes are securely overwritten when the last retained view releases the storage. This allows a provider to rotate or remove an entry without invalidating an operation that already borrowed it.</remarks>
struct KeyMaterialStorage final {
    SecurityBuffer Bytes;

    ~KeyMaterialStorage() {
        volatile uint8_t* pointer = Bytes.empty() ? nullptr : Bytes.data();
        for (std::size_t index = 0;
             pointer != nullptr && index < Bytes.size();
             ++index) {
            pointer[index] = 0;
        }
        Bytes.clear();
    }
};

/// <summary>Read-only key view that pins the provider-published key storage for its full lifetime.</summary>
/// <remarks>
/// The view avoids copying cryptographic key bytes for every protection operation while retaining shared ownership of
/// immutable backing storage. Provider mutation may remove or replace an entry, but an already returned view remains
/// valid until that view is destroyed. Callers must not modify or release <c>Data</c> directly.
/// </remarks>
struct KeyMaterialView {
    uint32_t KeyID = 0;
    const uint8_t* Data = nullptr;
    std::size_t Size = 0;
    std::shared_ptr<const KeyMaterialStorage> Storage;

    /// <summary>Binds this view to immutable shared key storage.</summary>
    void Bind(
        uint32_t keyID,
        std::shared_ptr<const KeyMaterialStorage> storage
    ) noexcept {
        Storage = std::move(storage);
        KeyID = keyID;
        Data = Storage && !Storage->Bytes.empty()
            ? Storage->Bytes.data()
            : nullptr;
        Size = Storage ? Storage->Bytes.size() : 0;
    }

    /// <summary>Returns whether the view contains no key bytes.</summary>
    constexpr bool Empty() const noexcept { return Data == nullptr || Size == 0; }
};

/// <summary>Configures transport protection policy, outbound identity, limits, and replay handling.</summary>
struct TransportSecurityConfig {
    TransportSecurityPolicy Policy = TransportSecurityPolicy::Required;
    AeadAlgorithm OutboundAlgorithm = AeadAlgorithm::AES256GCM;
    uint32_t OutboundKeyID = 1;
    uint64_t SenderID = 0;
    uint64_t SessionID = 0;
    std::size_t MaximumPlaintextBytes = 16384;
    std::size_t ReplayWindowSize = 64;
};

/// <summary>Decoded transport payload plus security metadata recovered from its envelope.</summary>
struct UnprotectedPayload {
    uint8_t Protocol = 0;
    uint32_t KeyID = 0;
    uint64_t SenderID = 0;
    uint64_t SessionID = 0;
    uint64_t Sequence = 0;
    AeadAlgorithm Algorithm = AeadAlgorithm::Unknown;
    bool Protected = false;
    SecurityBuffer Data;
};

}