#pragma once

#include <cstddef>
#include <cstdint>

namespace ESPressio::Security {

class DigestAlgorithmIdentifier final {
    std::uint16_t value_{};
public:
    constexpr DigestAlgorithmIdentifier() noexcept = default;
    constexpr explicit DigestAlgorithmIdentifier(std::uint16_t value) noexcept : value_(value) {}
    constexpr std::uint16_t Value() const noexcept { return value_; }
    constexpr explicit operator bool() const noexcept { return value_ != 0U; }
    constexpr bool operator==(DigestAlgorithmIdentifier other) const noexcept { return value_ == other.value_; }
    constexpr bool operator!=(DigestAlgorithmIdentifier other) const noexcept { return !(*this == other); }
    constexpr bool operator<(DigestAlgorithmIdentifier other) const noexcept { return value_ < other.value_; }
};
static_assert(sizeof(DigestAlgorithmIdentifier) == 2U, "DigestAlgorithmIdentifier must be exactly two bytes");

class SignatureAlgorithmIdentifier final {
    std::uint16_t value_{};
public:
    constexpr SignatureAlgorithmIdentifier() noexcept = default;
    constexpr explicit SignatureAlgorithmIdentifier(std::uint16_t value) noexcept : value_(value) {}
    constexpr std::uint16_t Value() const noexcept { return value_; }
    constexpr explicit operator bool() const noexcept { return value_ != 0U; }
    constexpr bool operator==(SignatureAlgorithmIdentifier other) const noexcept { return value_ == other.value_; }
    constexpr bool operator!=(SignatureAlgorithmIdentifier other) const noexcept { return !(*this == other); }
    constexpr bool operator<(SignatureAlgorithmIdentifier other) const noexcept { return value_ < other.value_; }
};
static_assert(sizeof(SignatureAlgorithmIdentifier) == 2U, "SignatureAlgorithmIdentifier must be exactly two bytes");

class TrustAnchorIdentifier final {
    std::uint32_t value_{};
public:
    constexpr TrustAnchorIdentifier() noexcept = default;
    constexpr explicit TrustAnchorIdentifier(std::uint32_t value) noexcept : value_(value) {}
    constexpr std::uint32_t Value() const noexcept { return value_; }
    constexpr explicit operator bool() const noexcept { return value_ != 0U; }
    constexpr bool operator==(TrustAnchorIdentifier other) const noexcept { return value_ == other.value_; }
    constexpr bool operator!=(TrustAnchorIdentifier other) const noexcept { return !(*this == other); }
    constexpr bool operator<(TrustAnchorIdentifier other) const noexcept { return value_ < other.value_; }
};
static_assert(sizeof(TrustAnchorIdentifier) == 4U, "TrustAnchorIdentifier must be exactly four bytes");

class TrustPolicyIdentifier final {
    std::uint32_t value_{};
public:
    constexpr TrustPolicyIdentifier() noexcept = default;
    constexpr explicit TrustPolicyIdentifier(std::uint32_t value) noexcept : value_(value) {}
    constexpr std::uint32_t Value() const noexcept { return value_; }
    constexpr explicit operator bool() const noexcept { return value_ != 0U; }
    constexpr bool operator==(TrustPolicyIdentifier other) const noexcept { return value_ == other.value_; }
    constexpr bool operator!=(TrustPolicyIdentifier other) const noexcept { return !(*this == other); }
    constexpr bool operator<(TrustPolicyIdentifier other) const noexcept { return value_ < other.value_; }
};
static_assert(sizeof(TrustPolicyIdentifier) == 4U, "TrustPolicyIdentifier must be exactly four bytes");

struct ByteView final {
    const std::uint8_t* Data{nullptr};
    std::size_t Size{0};

    constexpr bool IsValid() const noexcept { return Data != nullptr || Size == 0U; }
};

struct TrustAnchorView final {
    TrustAnchorIdentifier Identifier{};
    ByteView PublicKey{};

    constexpr explicit operator bool() const noexcept {
        return bool(Identifier) && PublicKey.IsValid() && PublicKey.Size != 0U;
    }
};

enum class TrustPurpose : std::uint8_t {
    SoftwareUpdateManifest = 1
};

enum class VerificationStatus : std::uint8_t {
    Success,
    InvalidArgument,
    UnsupportedAlgorithm,
    TrustAnchorUnavailable,
    UntrustedSigner,
    InvalidSignature,
    DigestMismatch,
    CapacityUnavailable,
    Failed
};

struct VerificationResult final {
    VerificationStatus Status{VerificationStatus::Failed};
    std::int32_t NativeCode{0};

    constexpr explicit operator bool() const noexcept {
        return Status == VerificationStatus::Success;
    }

    static constexpr VerificationResult Ok() noexcept {
        return {VerificationStatus::Success, 0};
    }
};

class IStreamingDigestVerifier {
public:
    virtual ~IStreamingDigestVerifier() = default;
    virtual bool Supports(DigestAlgorithmIdentifier algorithm) const noexcept = 0;
    virtual std::size_t DigestSize(DigestAlgorithmIdentifier algorithm) const noexcept = 0;
    virtual VerificationResult Begin(DigestAlgorithmIdentifier algorithm) noexcept = 0;
    virtual VerificationResult Update(ByteView bytes) noexcept = 0;
    virtual VerificationResult VerifyFinal(ByteView expectedDigest) noexcept = 0;
};

class ITrustAnchorProvider {
public:
    virtual ~ITrustAnchorProvider() = default;
    virtual VerificationResult Resolve(
        TrustAnchorIdentifier identifier,
        TrustAnchorView& anchor) const noexcept = 0;
};

class ITrustPolicy {
public:
    virtual ~ITrustPolicy() = default;
    virtual VerificationResult Authorize(
        TrustPolicyIdentifier policy,
        TrustPurpose purpose,
        TrustAnchorIdentifier anchor) const noexcept = 0;
};

class ISignatureVerifier {
public:
    virtual ~ISignatureVerifier() = default;
    virtual bool Supports(SignatureAlgorithmIdentifier algorithm) const noexcept = 0;
    virtual VerificationResult Verify(
        SignatureAlgorithmIdentifier algorithm,
        ByteView canonicalContent,
        ByteView signature,
        const TrustAnchorView& anchor) noexcept = 0;
};

} // namespace ESPressio::Security
