#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>

#include <ESPressio_MeshV1MbedTLSProvider.hpp>

using namespace ESPressio;

template<typename TValue>
static TValue NonZero(std::uint8_t first) {
    TValue value{};
    for (std::size_t index = 0; index < value.Value.size(); ++index) {
        value.Value[index] = static_cast<std::uint8_t>(first + index);
    }
    return value;
}

template<typename TIdentity>
static TIdentity Identity(std::uint8_t first) {
    typename TIdentity::Storage bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(first + index);
    }
    return TIdentity{bytes};
}

class TestRandom final : public Security::IRandomSource {
    std::uint8_t _next;
public:
    explicit TestRandom(std::uint8_t first) : _next(first) {}
    bool Fill(std::uint8_t* output, std::size_t size) override {
        if (output == nullptr && size != 0U) return false;
        for (std::size_t index = 0; index < size; ++index) {
            output[index] = _next++;
            if (_next == 0U) _next = 1U;
        }
        return true;
    }
};

class UnusedSigner final : public Security::IMeshV1IdentitySigner {
public:
    System::DeviceIdentifier Device() const noexcept override { return {}; }
    bool SignP256Sha256Digest(
        const Mesh::MeshSecurityDigest&,
        Mesh::MeshIdentitySignature&
    ) noexcept override { return false; }
};

class UnusedIdentities final : public Security::IMeshV1RegisteredIdentitySource {
public:
    bool LookupP256PublicKey(
        const System::DeviceIdentifier&,
        Mesh::MeshIdentityPublicKey&
    ) const noexcept override { return false; }
};

int main() {
    static_assert(ESPRESSIO_SECURITY_HAS_MESH_V1_MBEDTLS == 1);
    TestRandom initiatorRandom{1U};
    TestRandom responderRandom{65U};
    UnusedSigner signer;
    UnusedIdentities identities;
    Security::MeshV1MbedTLSProvider<2, 2> initiator(initiatorRandom, signer, identities);
    Security::MeshV1MbedTLSProvider<2, 2> responder(responderRandom, signer, identities);

    Mesh::MeshEphemeralKeyHandle initiatorEphemeral{};
    Mesh::MeshEphemeralKeyHandle responderEphemeral{};
    Mesh::MeshEphemeralPublicKey initiatorPublic{};
    Mesh::MeshEphemeralPublicKey responderPublic{};
    assert(initiator.GenerateEphemeralKey(initiatorEphemeral, initiatorPublic));
    assert(responder.GenerateEphemeralKey(responderEphemeral, responderPublic));

    const auto mesh = Identity<Mesh::MeshIdentifier>(1U);
    const auto initiatorDevice = Identity<System::DeviceIdentifier>(21U);
    const auto responderDevice = Identity<System::DeviceIdentifier>(41U);
    const auto initiatorIncarnation = Identity<Mesh::MembershipIncarnation>(61U);
    const auto responderIncarnation = Identity<Mesh::MembershipIncarnation>(81U);
    const auto initiatorNonce = NonZero<Mesh::MeshHandshakeNonce>(101U);
    const auto responderNonce = NonZero<Mesh::MeshHandshakeNonce>(131U);
    const auto transcript = NonZero<Mesh::MeshSecurityDigest>(151U);
    const auto channel = NonZero<Mesh::MeshSecurityChannelBinding>(181U);

    Mesh::MeshSecuritySessionHandle initiatorSession{};
    Mesh::MeshSecuritySessionHandle responderSession{};
    Mesh::MeshSecuritySessionIdentifier initiatorIdentifier{};
    Mesh::MeshSecuritySessionIdentifier responderIdentifier{};
    assert(initiator.DeriveSession(
        initiatorEphemeral, responderPublic, mesh, channel,
        initiatorDevice, initiatorIncarnation, initiatorNonce,
        responderDevice, responderIncarnation, responderNonce,
        transcript, Mesh::MeshSecuritySessionRole::Initiator,
        initiatorSession, initiatorIdentifier));
    assert(responder.DeriveSession(
        responderEphemeral, initiatorPublic, mesh, channel,
        initiatorDevice, initiatorIncarnation, initiatorNonce,
        responderDevice, responderIncarnation, responderNonce,
        transcript, Mesh::MeshSecuritySessionRole::Responder,
        responderSession, responderIdentifier));
    assert(initiatorIdentifier.Value == responderIdentifier.Value);
    assert(initiator.ReleaseEphemeralKey(initiatorEphemeral));
    assert(responder.ReleaseEphemeralKey(responderEphemeral));

    const std::array<std::uint8_t, 3> aad{{7U, 8U, 9U}};
    const std::array<std::uint8_t, 5> plaintext{{10U, 11U, 12U, 13U, 14U}};
    std::array<std::uint8_t, plaintext.size()> ciphertext{};
    std::array<std::uint8_t, plaintext.size()> opened{};
    Mesh::MeshAuthenticationTag tag{};
    assert(initiator.Seal(
        initiatorSession, Mesh::MeshSecurityTrafficPurpose::Hop, 1U,
        aad.data(), aad.size(), plaintext.data(), plaintext.size(), ciphertext.data(), tag));
    assert(responder.Open(
        responderSession, Mesh::MeshSecurityTrafficPurpose::Hop, 1U,
        aad.data(), aad.size(), ciphertext.data(), ciphertext.size(), tag, opened.data()));
    assert(opened == plaintext);

    Mesh::MeshAuthenticationTag confirmation{};
    assert(responder.Seal(
        responderSession, Mesh::MeshSecurityTrafficPurpose::KeyConfirmation, 1U,
        transcript.Value.data(), transcript.Value.size(), nullptr, 0U, nullptr, confirmation));
    assert(initiator.Open(
        initiatorSession, Mesh::MeshSecurityTrafficPurpose::KeyConfirmation, 1U,
        transcript.Value.data(), transcript.Value.size(), nullptr, 0U, confirmation, nullptr));

    Mesh::MeshEphemeralKeyHandle secondInitiatorEphemeral{};
    Mesh::MeshEphemeralKeyHandle secondResponderEphemeral{};
    Mesh::MeshEphemeralPublicKey secondInitiatorPublic{};
    Mesh::MeshEphemeralPublicKey secondResponderPublic{};
    assert(initiator.GenerateEphemeralKey(secondInitiatorEphemeral, secondInitiatorPublic));
    assert(responder.GenerateEphemeralKey(secondResponderEphemeral, secondResponderPublic));
    auto otherChannel = channel;
    otherChannel.Value[0] ^= 0x80U;
    Mesh::MeshSecuritySessionHandle mismatchedInitiatorSession{};
    Mesh::MeshSecuritySessionHandle mismatchedResponderSession{};
    Mesh::MeshSecuritySessionIdentifier mismatchedInitiatorIdentifier{};
    Mesh::MeshSecuritySessionIdentifier mismatchedResponderIdentifier{};
    assert(initiator.DeriveSession(
        secondInitiatorEphemeral, secondResponderPublic, mesh, otherChannel,
        initiatorDevice, initiatorIncarnation, initiatorNonce,
        responderDevice, responderIncarnation, responderNonce,
        transcript, Mesh::MeshSecuritySessionRole::Initiator,
        mismatchedInitiatorSession, mismatchedInitiatorIdentifier));
    assert(responder.DeriveSession(
        secondResponderEphemeral, secondInitiatorPublic, mesh, channel,
        initiatorDevice, initiatorIncarnation, initiatorNonce,
        responderDevice, responderIncarnation, responderNonce,
        transcript, Mesh::MeshSecuritySessionRole::Responder,
        mismatchedResponderSession, mismatchedResponderIdentifier));
    assert(mismatchedInitiatorIdentifier.Value != mismatchedResponderIdentifier.Value);
    assert(initiator.ReleaseEphemeralKey(secondInitiatorEphemeral));
    assert(responder.ReleaseEphemeralKey(secondResponderEphemeral));

    initiator.ResetForControlledShutdown();
    assert(!initiator.Seal(
        initiatorSession, Mesh::MeshSecurityTrafficPurpose::Hop, 2U,
        aad.data(), aad.size(), plaintext.data(), plaintext.size(), ciphertext.data(), tag));
    responder.ResetForControlledShutdown();
    return 0;
}
