#include <array>
#include <cstddef>
#include <cstdint>

#include "ESPressio_Security.hpp"

using namespace ESPressio::Security;

namespace {

constexpr DigestAlgorithmIdentifier TestDigest{1U};
constexpr SignatureAlgorithmIdentifier TestSignature{1U};
constexpr TrustAnchorIdentifier TestAnchor{7U};
constexpr TrustPolicyIdentifier TestPolicy{3U};

class FakeDigest final : public IStreamingDigest, public IStreamingDigestVerifier {
    std::uint8_t sum_{0U};
    bool active_{false};
public:
    bool Supports(DigestAlgorithmIdentifier algorithm) const noexcept override {
        return algorithm == TestDigest;
    }

    std::size_t DigestSize(DigestAlgorithmIdentifier algorithm) const noexcept override {
        return Supports(algorithm) ? 1U : 0U;
    }

    VerificationResult Begin(DigestAlgorithmIdentifier algorithm) noexcept override {
        if (!Supports(algorithm)) return {VerificationStatus::UnsupportedAlgorithm, 0};
        sum_ = 0U;
        active_ = true;
        return VerificationResult::Ok();
    }

    VerificationResult Update(ByteView bytes) noexcept override {
        if (!active_ || !bytes.IsValid()) return {VerificationStatus::InvalidArgument, 0};
        for (std::size_t i = 0; i < bytes.Size; ++i) sum_ = static_cast<std::uint8_t>(sum_ + bytes.Data[i]);
        return VerificationResult::Ok();
    }

    VerificationResult Finalize(MutableByteView output, std::size_t& written) noexcept override {
        written = 0U;
        if (!active_ || !output.IsValid()) return {VerificationStatus::InvalidArgument, 0};
        if (output.Size < 1U) return {VerificationStatus::CapacityUnavailable, 0};
        output.Data[0] = sum_;
        written = 1U;
        active_ = false;
        return VerificationResult::Ok();
    }

    VerificationResult VerifyFinal(ByteView expectedDigest) noexcept override {
        if (!active_ || !expectedDigest.IsValid() || expectedDigest.Size != 1U) {
            return {VerificationStatus::InvalidArgument, 0};
        }
        active_ = false;
        return expectedDigest.Data[0] == sum_
            ? VerificationResult::Ok()
            : VerificationResult{VerificationStatus::DigestMismatch, 0};
    }
};

class FakeTrustAnchors final : public ITrustAnchorProvider {
    std::array<std::uint8_t, 3> key_{{1U, 2U, 3U}};
public:
    VerificationResult Resolve(TrustAnchorIdentifier identifier, TrustAnchorView& anchor) const noexcept override {
        if (identifier != TestAnchor) return {VerificationStatus::TrustAnchorUnavailable, 0};
        anchor = {identifier, {key_.data(), key_.size()}};
        return VerificationResult::Ok();
    }
};

class FakeTrustPolicy final : public ITrustPolicy {
public:
    VerificationResult Authorize(
        TrustPolicyIdentifier policy,
        TrustPurpose purpose,
        TrustAnchorIdentifier anchor) const noexcept override {
        if (policy != TestPolicy || purpose != TrustPurpose::SoftwareUpdateManifest || anchor != TestAnchor) {
            return {VerificationStatus::UntrustedSigner, 0};
        }
        return VerificationResult::Ok();
    }
};

class FakeSignatureVerifier final : public ISignatureVerifier {
public:
    bool Supports(SignatureAlgorithmIdentifier algorithm) const noexcept override {
        return algorithm == TestSignature;
    }

    VerificationResult Verify(
        SignatureAlgorithmIdentifier algorithm,
        ByteView canonicalContent,
        ByteView signature,
        const TrustAnchorView& anchor) noexcept override {
        if (!Supports(algorithm)) return {VerificationStatus::UnsupportedAlgorithm, 0};
        if (!canonicalContent.IsValid() || !signature.IsValid() || !anchor) {
            return {VerificationStatus::InvalidArgument, 0};
        }
        if (signature.Size != 1U || canonicalContent.Size == 0U) {
            return {VerificationStatus::InvalidSignature, 0};
        }
        return signature.Data[0] == canonicalContent.Data[0]
            ? VerificationResult::Ok()
            : VerificationResult{VerificationStatus::InvalidSignature, 0};
    }
};

} // namespace

int main() {
    static_assert(sizeof(DigestAlgorithmIdentifier) == 2U);
    static_assert(sizeof(SignatureAlgorithmIdentifier) == 2U);
    static_assert(sizeof(TrustAnchorIdentifier) == 4U);
    static_assert(sizeof(TrustPolicyIdentifier) == 4U);
    static_assert(DigestAlgorithm::SHA256.Value() == 1U);

    const std::uint8_t bytes[]{2U, 3U, 4U};
    const std::uint8_t goodDigest[]{9U};
    FakeDigest digest;
    if (!digest.Begin(TestDigest)) return 1;
    if (!digest.Update({bytes, sizeof(bytes)})) return 2;
    if (!digest.VerifyFinal({goodDigest, sizeof(goodDigest)})) return 3;

    if (!digest.Begin(TestDigest)) return 4;
    if (!digest.Update({bytes, sizeof(bytes)})) return 5;
    std::uint8_t produced[1]{};
    std::size_t written = 0U;
    if (!digest.Finalize({produced, sizeof(produced)}, written)) return 6;
    if (written != 1U || produced[0] != goodDigest[0]) return 7;

    FakeTrustAnchors anchors;
    TrustAnchorView anchor{};
    if (!anchors.Resolve(TestAnchor, anchor)) return 8;

    FakeTrustPolicy policy;
    if (!policy.Authorize(TestPolicy, TrustPurpose::SoftwareUpdateManifest, TestAnchor)) return 9;

    FakeSignatureVerifier verifier;
    const std::uint8_t signature[]{2U};
    if (!verifier.Verify(TestSignature, {bytes, sizeof(bytes)}, {signature, sizeof(signature)}, anchor)) return 10;

    const std::uint8_t badSignature[]{8U};
    const auto rejected = verifier.Verify(
        TestSignature,
        {bytes, sizeof(bytes)},
        {badSignature, sizeof(badSignature)},
        anchor);
    return rejected.Status == VerificationStatus::InvalidSignature ? 0 : 11;
}
