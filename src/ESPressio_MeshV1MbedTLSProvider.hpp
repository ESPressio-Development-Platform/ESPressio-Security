#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

#include <ESPressio_MeshV1Security.hpp>

#include "ESPressio_IRandomSource.hpp"

#if __has_include(<mbedtls/ecdh.h>) && __has_include(<mbedtls/ecdsa.h>) && \
    __has_include(<mbedtls/gcm.h>) && __has_include(<mbedtls/md.h>) && \
    __has_include(<mbedtls/sha256.h>)
#define ESPRESSIO_SECURITY_HAS_MESH_V1_MBEDTLS 1
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#else
#define ESPRESSIO_SECURITY_HAS_MESH_V1_MBEDTLS 0
#endif

namespace ESPressio::Security {

/// <summary>Provisioned local long-term Mesh identity signer.</summary>
/// <remarks>The implementation may use protected flash, a secure element or another platform policy. Private key bytes never cross this interface.</remarks>
class IMeshV1IdentitySigner {
public:
    virtual ~IMeshV1IdentitySigner() = default;
    virtual System::DeviceIdentifier Device() const noexcept = 0;
    virtual bool SignP256Sha256Digest(
        const Mesh::MeshSecurityDigest& digest,
        Mesh::MeshIdentitySignature& signature
    ) noexcept = 0;
};

/// <summary>Operator-authorized public identities (the composition's bounded “My Devices” source).</summary>
class IMeshV1RegisteredIdentitySource {
public:
    virtual ~IMeshV1RegisteredIdentitySource() = default;
    virtual bool LookupP256PublicKey(
        const System::DeviceIdentifier& device,
        Mesh::MeshIdentityPublicKey& publicKey
    ) const noexcept = 0;
};

#if ESPRESSIO_SECURITY_HAS_MESH_V1_MBEDTLS

/// <summary>Fixed-retention mbedTLS implementation of the frozen Mesh v1 cryptographic provider.</summary>
/// <remarks>
/// Ephemeral private scalars and derived session material live only in fixed arrays. mbedTLS big-number contexts are
/// operation-local and freed before return; there is no retained heap-backed key/session registry. The concrete signer
/// and registered identity source remain injected provisioning boundaries.
/// </remarks>
template<std::size_t EphemeralCapacity, std::size_t SessionCapacity>
class MeshV1MbedTLSProvider final : public Mesh::IMeshV1CryptographicProvider {
    static_assert(EphemeralCapacity > 0U && EphemeralCapacity < std::numeric_limits<std::uint16_t>::max());
    static_assert(SessionCapacity > 0U && SessionCapacity < std::numeric_limits<std::uint16_t>::max());

    static constexpr std::size_t PurposeCount = 6U;
    static constexpr std::size_t P256ScalarBytes = 32U;

    struct EphemeralSlot final {
        std::array<std::uint8_t, P256ScalarBytes> Private{};
        std::uint16_t Generation{0};
        bool Used{false};
    };
    struct SessionSlot final {
        std::array<std::array<std::uint8_t, Mesh::MeshV1SecuritySuite::TrafficKeyBytes>, PurposeCount> Keys{};
        std::array<std::array<std::uint8_t, Mesh::MeshV1SecuritySuite::TrafficNonceBytes>, PurposeCount> Ivs{};
        Mesh::MeshSecuritySessionIdentifier Identifier{};
        Mesh::MeshSecuritySessionRole Role{Mesh::MeshSecuritySessionRole::Initiator};
        std::uint16_t Generation{0};
        bool Used{false};
    };

    IRandomSource& _random;
    IMeshV1IdentitySigner& _signer;
    const IMeshV1RegisteredIdentitySource& _identities;
    std::array<EphemeralSlot, EphemeralCapacity> _ephemeral{};
    std::array<SessionSlot, SessionCapacity> _sessions{};

    static std::uint16_t NextGeneration(std::uint16_t current) noexcept {
        const auto next = static_cast<std::uint16_t>(current + 1U);
        return next == 0U ? 1U : next;
    }
    static void Erase(std::uint8_t* bytes, std::size_t size) noexcept {
        volatile std::uint8_t* destination = bytes;
        for (std::size_t index = 0; index < size; ++index) destination[index] = 0U;
    }
    template<typename T>
    static void Erase(T& value) noexcept { Erase(reinterpret_cast<std::uint8_t*>(&value), sizeof(value)); }

    static int RandomCallback(void* context, unsigned char* output, std::size_t size) noexcept {
        auto* self = static_cast<MeshV1MbedTLSProvider*>(context);
        return self != nullptr && self->_random.Fill(output, size) ? 0 : -1;
    }
    EphemeralSlot* Resolve(Mesh::MeshEphemeralKeyHandle handle) noexcept {
        if (!handle || handle.Slot >= EphemeralCapacity) return nullptr;
        auto& slot = _ephemeral[handle.Slot];
        return slot.Used && slot.Generation == handle.Generation ? &slot : nullptr;
    }
    SessionSlot* Resolve(Mesh::MeshSecuritySessionHandle handle) noexcept {
        if (!handle || handle.Slot >= SessionCapacity) return nullptr;
        auto& slot = _sessions[handle.Slot];
        return slot.Used && slot.Generation == handle.Generation ? &slot : nullptr;
    }
    const SessionSlot* Resolve(Mesh::MeshSecuritySessionHandle handle) const noexcept {
        if (!handle || handle.Slot >= SessionCapacity) return nullptr;
        const auto& slot = _sessions[handle.Slot];
        return slot.Used && slot.Generation == handle.Generation ? &slot : nullptr;
    }
    static std::size_t PurposeIndex(
        const SessionSlot& session,
        Mesh::MeshSecurityTrafficPurpose purpose,
        bool outbound
    ) noexcept {
        const bool localIsInitiator = session.Role == Mesh::MeshSecuritySessionRole::Initiator;
        const bool initiatorToResponder = outbound ? localIsInitiator : !localIsInitiator;
        switch (purpose) {
            case Mesh::MeshSecurityTrafficPurpose::Hop: return initiatorToResponder ? 0U : 1U;
            case Mesh::MeshSecurityTrafficPurpose::EndToEnd: return initiatorToResponder ? 2U : 3U;
            case Mesh::MeshSecurityTrafficPurpose::KeyConfirmation: return initiatorToResponder ? 4U : 5U;
        }
        return PurposeCount;
    }
    static void Nonce(
        const std::array<std::uint8_t, Mesh::MeshV1SecuritySuite::TrafficNonceBytes>& iv,
        std::uint64_t sequence,
        std::array<std::uint8_t, Mesh::MeshV1SecuritySuite::TrafficNonceBytes>& nonce
    ) noexcept {
        nonce = iv;
        for (std::size_t index = 0; index < 8U; ++index) {
            nonce[nonce.size() - 1U - index] ^= static_cast<std::uint8_t>(sequence >> (index * 8U));
        }
    }
    static bool ValidLowSSignature(const Mesh::MeshIdentitySignature& signature) noexcept {
        mbedtls_ecp_group group;
        mbedtls_mpi s;
        mbedtls_mpi halfOrder;
        mbedtls_ecp_group_init(&group);
        mbedtls_mpi_init(&s);
        mbedtls_mpi_init(&halfOrder);
        const bool valid =
            mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
            mbedtls_mpi_read_binary(&s, signature.Value.data() + P256ScalarBytes, P256ScalarBytes) == 0 &&
            mbedtls_mpi_cmp_int(&s, 0) > 0 &&
            mbedtls_mpi_copy(&halfOrder, &group.N) == 0 &&
            mbedtls_mpi_shift_r(&halfOrder, 1U) == 0 &&
            mbedtls_mpi_cmp_mpi(&s, &halfOrder) <= 0;
        mbedtls_mpi_free(&halfOrder);
        mbedtls_mpi_free(&s);
        mbedtls_ecp_group_free(&group);
        return valid;
    }
    static bool Append(std::uint8_t*& cursor, const std::uint8_t* bytes, std::size_t size) noexcept {
        if (bytes == nullptr && size != 0U) return false;
        std::memcpy(cursor, bytes, size);
        cursor += size;
        return true;
    }
    template<std::size_t InfoBytes, std::size_t OutputBytes>
    static bool HkdfSha256(
        const std::uint8_t* salt,
        std::size_t saltBytes,
        const std::uint8_t* inputKeyMaterial,
        std::size_t inputKeyMaterialBytes,
        const std::array<std::uint8_t, InfoBytes>& info,
        std::array<std::uint8_t, OutputBytes>& output
    ) noexcept {
        static_assert(OutputBytes <= 255U * Mesh::MeshV1SecuritySuite::DigestBytes);
        output.fill(0U);
        if ((salt == nullptr && saltBytes != 0U) ||
            (inputKeyMaterial == nullptr && inputKeyMaterialBytes != 0U)) return false;
        const auto* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (md == nullptr || mbedtls_md_get_size(md) != Mesh::MeshV1SecuritySuite::DigestBytes) return false;

        Mesh::MeshSecurityDigest pseudorandomKey{};
        Mesh::MeshSecurityDigest block{};
        std::array<std::uint8_t, Mesh::MeshV1SecuritySuite::DigestBytes + InfoBytes + 1U> blockInput{};
        if (mbedtls_md_hmac(md, salt, saltBytes, inputKeyMaterial, inputKeyMaterialBytes,
                            pseudorandomKey.Value.data()) != 0) {
            Erase(pseudorandomKey);
            return false;
        }

        std::size_t produced = 0U;
        std::size_t previousBytes = 0U;
        std::uint8_t counter = 1U;
        while (produced < output.size()) {
            auto* cursor = blockInput.data();
            if (previousBytes != 0U) {
                std::memcpy(cursor, block.Value.data(), previousBytes);
                cursor += previousBytes;
            }
            std::memcpy(cursor, info.data(), info.size());
            cursor += info.size();
            *cursor++ = counter;
            if (mbedtls_md_hmac(md, pseudorandomKey.Value.data(), pseudorandomKey.Value.size(),
                                blockInput.data(), static_cast<std::size_t>(cursor - blockInput.data()),
                                block.Value.data()) != 0) {
                Erase(pseudorandomKey);
                Erase(block);
                Erase(blockInput);
                Erase(output);
                return false;
            }
            const auto remaining = output.size() - produced;
            const auto copied = remaining < block.Value.size() ? remaining : block.Value.size();
            std::memcpy(output.data() + produced, block.Value.data(), copied);
            produced += copied;
            previousBytes = block.Value.size();
            ++counter;
        }
        Erase(pseudorandomKey);
        Erase(block);
        Erase(blockInput);
        return true;
    }

public:
    MeshV1MbedTLSProvider(
        IRandomSource& random,
        IMeshV1IdentitySigner& signer,
        const IMeshV1RegisteredIdentitySource& identities
    ) noexcept : _random(random), _signer(signer), _identities(identities) {}

    ~MeshV1MbedTLSProvider() override { ResetForControlledShutdown(); }

    bool GenerateEphemeralKey(
        Mesh::MeshEphemeralKeyHandle& handle,
        Mesh::MeshEphemeralPublicKey& publicKey
    ) noexcept override {
        handle = {};
        publicKey = {};
        std::size_t target = EphemeralCapacity;
        for (std::size_t index = 0; index < EphemeralCapacity; ++index) {
            if (!_ephemeral[index].Used) { target = index; break; }
        }
        if (target == EphemeralCapacity) return false;

        mbedtls_ecp_group group;
        mbedtls_mpi privateScalar;
        mbedtls_ecp_point publicPoint;
        mbedtls_ecp_group_init(&group);
        mbedtls_mpi_init(&privateScalar);
        mbedtls_ecp_point_init(&publicPoint);
        std::size_t written = 0U;
        const bool generated =
            mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
            mbedtls_ecp_gen_keypair(&group, &privateScalar, &publicPoint, RandomCallback, this) == 0 &&
            mbedtls_mpi_write_binary(&privateScalar, _ephemeral[target].Private.data(), P256ScalarBytes) == 0 &&
            mbedtls_ecp_point_write_binary(&group, &publicPoint, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                           &written, publicKey.Value.data(), publicKey.Value.size()) == 0 &&
            written == publicKey.Value.size();
        mbedtls_ecp_point_free(&publicPoint);
        mbedtls_mpi_free(&privateScalar);
        mbedtls_ecp_group_free(&group);
        if (!generated) {
            Erase(_ephemeral[target].Private);
            publicKey = {};
            return false;
        }
        auto& slot = _ephemeral[target];
        slot.Generation = NextGeneration(slot.Generation);
        slot.Used = true;
        handle = {static_cast<std::uint16_t>(target), slot.Generation};
        return true;
    }

    bool GenerateHandshakeNonce(Mesh::MeshHandshakeNonce& nonce) noexcept override {
        nonce = {};
        for (std::size_t attempt = 0; attempt < 4U; ++attempt) {
            if (!_random.Fill(nonce.Value.data(), nonce.Value.size())) return false;
            if (nonce) return true;
        }
        nonce = {};
        return false;
    }

    bool Hash(const std::uint8_t* bytes, std::size_t size, Mesh::MeshSecurityDigest& digest) noexcept override {
        digest = {};
        if (bytes == nullptr && size != 0U) return false;
        const std::uint8_t zero = 0U;
        return mbedtls_sha256_ret(size == 0U ? &zero : bytes, size, digest.Value.data(), 0) == 0;
    }

    bool SignIdentityDigest(
        const System::DeviceIdentifier& localDevice,
        const Mesh::MeshSecurityDigest& digest,
        Mesh::MeshIdentitySignature& signature
    ) noexcept override {
        signature = {};
        return localDevice && localDevice == _signer.Device() &&
               _signer.SignP256Sha256Digest(digest, signature) && ValidLowSSignature(signature);
    }

    Mesh::MeshIdentityVerificationResult VerifyRegisteredIdentityDigest(
        const System::DeviceIdentifier& claimedDevice,
        const Mesh::MeshSecurityDigest& digest,
        const Mesh::MeshIdentitySignature& signature
    ) noexcept override {
        if (!claimedDevice || !signature || !ValidLowSSignature(signature)) {
            return Mesh::MeshIdentityVerificationResult::InvalidSignature;
        }
        Mesh::MeshIdentityPublicKey publicKey{};
        if (!_identities.LookupP256PublicKey(claimedDevice, publicKey)) {
            return Mesh::MeshIdentityVerificationResult::Unregistered;
        }
        if (!publicKey || publicKey.Value[0] != 0x04U) return Mesh::MeshIdentityVerificationResult::Invalid;

        mbedtls_ecp_group group;
        mbedtls_ecp_point point;
        mbedtls_mpi r;
        mbedtls_mpi s;
        mbedtls_ecp_group_init(&group);
        mbedtls_ecp_point_init(&point);
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        const bool verified =
            mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
            mbedtls_ecp_point_read_binary(&group, &point, publicKey.Value.data(), publicKey.Value.size()) == 0 &&
            mbedtls_ecp_check_pubkey(&group, &point) == 0 &&
            mbedtls_mpi_read_binary(&r, signature.Value.data(), P256ScalarBytes) == 0 &&
            mbedtls_mpi_read_binary(&s, signature.Value.data() + P256ScalarBytes, P256ScalarBytes) == 0 &&
            mbedtls_ecdsa_verify(&group, digest.Value.data(), digest.Value.size(), &point, &r, &s) == 0;
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&r);
        mbedtls_ecp_point_free(&point);
        mbedtls_ecp_group_free(&group);
        return verified ? Mesh::MeshIdentityVerificationResult::Verified
                        : Mesh::MeshIdentityVerificationResult::InvalidSignature;
    }

    bool DeriveSession(
        Mesh::MeshEphemeralKeyHandle localEphemeral,
        const Mesh::MeshEphemeralPublicKey& peerEphemeral,
        const Mesh::MeshIdentifier& mesh,
        const Mesh::MeshSecurityChannelBinding& channelBinding,
        const System::DeviceIdentifier& initiatorDevice,
        const Mesh::MembershipIncarnation& initiatorIncarnation,
        const Mesh::MeshHandshakeNonce& initiatorNonce,
        const System::DeviceIdentifier& responderDevice,
        const Mesh::MembershipIncarnation& responderIncarnation,
        const Mesh::MeshHandshakeNonce& responderNonce,
        const Mesh::MeshSecurityDigest& signedHelloTranscriptDigest,
        Mesh::MeshSecuritySessionRole role,
        Mesh::MeshSecuritySessionHandle& session,
        Mesh::MeshSecuritySessionIdentifier& sessionIdentifier
    ) noexcept override {
        session = {};
        sessionIdentifier = {};
        auto* ephemeral = Resolve(localEphemeral);
        if (ephemeral == nullptr || !peerEphemeral || peerEphemeral.Value[0] != 0x04U || !mesh ||
            !channelBinding || !initiatorDevice || !initiatorIncarnation || !initiatorNonce ||
            !responderDevice || !responderIncarnation || !responderNonce) return false;
        std::size_t target = SessionCapacity;
        for (std::size_t index = 0; index < SessionCapacity; ++index) {
            if (!_sessions[index].Used) { target = index; break; }
        }
        if (target == SessionCapacity) return false;

        std::array<std::uint8_t, P256ScalarBytes> shared{};
        mbedtls_ecp_group group;
        mbedtls_mpi privateScalar;
        mbedtls_mpi sharedValue;
        mbedtls_ecp_point peerPoint;
        mbedtls_ecp_group_init(&group);
        mbedtls_mpi_init(&privateScalar);
        mbedtls_mpi_init(&sharedValue);
        mbedtls_ecp_point_init(&peerPoint);
        const bool agreed =
            mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
            mbedtls_mpi_read_binary(&privateScalar, ephemeral->Private.data(), ephemeral->Private.size()) == 0 &&
            mbedtls_ecp_check_privkey(&group, &privateScalar) == 0 &&
            mbedtls_ecp_point_read_binary(&group, &peerPoint, peerEphemeral.Value.data(), peerEphemeral.Value.size()) == 0 &&
            mbedtls_ecp_check_pubkey(&group, &peerPoint) == 0 &&
            mbedtls_ecdh_compute_shared(&group, &sharedValue, &peerPoint, &privateScalar,
                                        RandomCallback, this) == 0 &&
            mbedtls_mpi_write_binary(&sharedValue, shared.data(), shared.size()) == 0;
        mbedtls_ecp_point_free(&peerPoint);
        mbedtls_mpi_free(&sharedValue);
        mbedtls_mpi_free(&privateScalar);
        mbedtls_ecp_group_free(&group);
        if (!agreed) { Erase(shared); return false; }

        constexpr std::size_t SaltLabelBytes = sizeof(Mesh::MeshV1SecuritySuite::SaltLabel) - 1U;
        std::array<std::uint8_t, SaltLabelBytes + 2U * Mesh::MeshV1SecuritySuite::HandshakeNonceBytes> saltInput{};
        auto* saltCursor = saltInput.data();
        Append(saltCursor, reinterpret_cast<const std::uint8_t*>(Mesh::MeshV1SecuritySuite::SaltLabel), SaltLabelBytes);
        Append(saltCursor, initiatorNonce.Value.data(), initiatorNonce.Value.size());
        Append(saltCursor, responderNonce.Value.data(), responderNonce.Value.size());
        Mesh::MeshSecurityDigest salt{};
        if (!Hash(saltInput.data(), saltInput.size(), salt)) { Erase(shared); return false; }

        constexpr std::size_t SessionLabelBytes = sizeof(Mesh::MeshV1SecuritySuite::SessionLabel) - 1U;
        constexpr std::size_t InfoBytes = SessionLabelBytes + 2U + Mesh::MeshIdentifier::Size +
            Mesh::MeshV1SecuritySuite::ChannelBindingBytes + 4U * System::DeviceIdentifier::Size +
            Mesh::MeshV1SecuritySuite::DigestBytes;
        std::array<std::uint8_t, InfoBytes> info{};
        auto* infoCursor = info.data();
        Append(infoCursor, reinterpret_cast<const std::uint8_t*>(Mesh::MeshV1SecuritySuite::SessionLabel), SessionLabelBytes);
        *infoCursor++ = 1U;
        *infoCursor++ = 2U;
        Append(infoCursor, mesh.Bytes().data(), mesh.Bytes().size());
        Append(infoCursor, channelBinding.Value.data(), channelBinding.Value.size());
        Append(infoCursor, initiatorDevice.Bytes().data(), initiatorDevice.Bytes().size());
        Append(infoCursor, initiatorIncarnation.Bytes().data(), initiatorIncarnation.Bytes().size());
        Append(infoCursor, responderDevice.Bytes().data(), responderDevice.Bytes().size());
        Append(infoCursor, responderIncarnation.Bytes().data(), responderIncarnation.Bytes().size());
        Append(infoCursor, signedHelloTranscriptDigest.Value.data(), signedHelloTranscriptDigest.Value.size());

        std::array<std::uint8_t, Mesh::MeshV1SecuritySuite::DerivedBytes> derived{};
        const bool expanded = HkdfSha256(
            salt.Value.data(), salt.Value.size(), shared.data(), shared.size(), info, derived
        );
        Erase(shared);
        if (!expanded) { Erase(derived); return false; }

        auto& destination = _sessions[target];
        const auto* derivedCursor = derived.data();
        for (auto& key : destination.Keys) {
            std::memcpy(key.data(), derivedCursor, key.size());
            derivedCursor += key.size();
        }
        for (auto& iv : destination.Ivs) {
            std::memcpy(iv.data(), derivedCursor, iv.size());
            derivedCursor += iv.size();
        }
        std::memcpy(destination.Identifier.Value.data(), derivedCursor, destination.Identifier.Value.size());
        Erase(derived);
        if (!destination.Identifier) {
            const auto generation = destination.Generation;
            Erase(destination);
            destination.Generation = generation;
            return false;
        }
        destination.Role = role;
        destination.Generation = NextGeneration(destination.Generation);
        destination.Used = true;
        sessionIdentifier = destination.Identifier;
        session = {static_cast<std::uint16_t>(target), destination.Generation};
        return true;
    }

    bool Seal(
        Mesh::MeshSecuritySessionHandle session,
        Mesh::MeshSecurityTrafficPurpose purpose,
        std::uint64_t sequence,
        const std::uint8_t* authenticatedData,
        std::size_t authenticatedDataBytes,
        const std::uint8_t* plaintext,
        std::size_t plaintextBytes,
        std::uint8_t* ciphertext,
        Mesh::MeshAuthenticationTag& tag
    ) noexcept override {
        tag = {};
        const auto* state = Resolve(session);
        const auto index = state == nullptr ? PurposeCount : PurposeIndex(*state, purpose, true);
        if (state == nullptr || index >= PurposeCount || sequence == 0U ||
            (authenticatedData == nullptr && authenticatedDataBytes != 0U) ||
            (plaintext == nullptr && plaintextBytes != 0U) ||
            (ciphertext == nullptr && plaintextBytes != 0U)) return false;
        std::array<std::uint8_t, Mesh::MeshV1SecuritySuite::TrafficNonceBytes> nonce{};
        Nonce(state->Ivs[index], sequence, nonce);
        std::uint8_t dummy = 0U;
        mbedtls_gcm_context context;
        mbedtls_gcm_init(&context);
        const bool protectedPayload =
            mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, state->Keys[index].data(), 256U) == 0 &&
            mbedtls_gcm_crypt_and_tag(&context, MBEDTLS_GCM_ENCRYPT, plaintextBytes,
                                     nonce.data(), nonce.size(),
                                     authenticatedDataBytes == 0U ? &dummy : authenticatedData, authenticatedDataBytes,
                                     plaintextBytes == 0U ? &dummy : plaintext,
                                     plaintextBytes == 0U ? &dummy : ciphertext,
                                     tag.Value.size(), tag.Value.data()) == 0;
        mbedtls_gcm_free(&context);
        Erase(nonce);
        return protectedPayload;
    }

    bool Open(
        Mesh::MeshSecuritySessionHandle session,
        Mesh::MeshSecurityTrafficPurpose purpose,
        std::uint64_t sequence,
        const std::uint8_t* authenticatedData,
        std::size_t authenticatedDataBytes,
        const std::uint8_t* ciphertext,
        std::size_t ciphertextBytes,
        const Mesh::MeshAuthenticationTag& tag,
        std::uint8_t* plaintext
    ) noexcept override {
        const auto* state = Resolve(session);
        const auto index = state == nullptr ? PurposeCount : PurposeIndex(*state, purpose, false);
        if (state == nullptr || index >= PurposeCount || sequence == 0U ||
            (authenticatedData == nullptr && authenticatedDataBytes != 0U) ||
            (ciphertext == nullptr && ciphertextBytes != 0U) ||
            (plaintext == nullptr && ciphertextBytes != 0U)) return false;
        std::array<std::uint8_t, Mesh::MeshV1SecuritySuite::TrafficNonceBytes> nonce{};
        Nonce(state->Ivs[index], sequence, nonce);
        std::uint8_t dummy = 0U;
        mbedtls_gcm_context context;
        mbedtls_gcm_init(&context);
        const bool opened =
            mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, state->Keys[index].data(), 256U) == 0 &&
            mbedtls_gcm_auth_decrypt(&context, ciphertextBytes,
                                     nonce.data(), nonce.size(),
                                     authenticatedDataBytes == 0U ? &dummy : authenticatedData, authenticatedDataBytes,
                                     tag.Value.data(), tag.Value.size(),
                                     ciphertextBytes == 0U ? &dummy : ciphertext,
                                     ciphertextBytes == 0U ? &dummy : plaintext) == 0;
        mbedtls_gcm_free(&context);
        Erase(nonce);
        return opened;
    }

    bool ReleaseEphemeralKey(Mesh::MeshEphemeralKeyHandle handle) noexcept override {
        auto* slot = Resolve(handle);
        if (slot == nullptr) return false;
        const auto generation = slot->Generation;
        Erase(*slot);
        slot->Generation = generation;
        return true;
    }

    bool ReleaseSession(Mesh::MeshSecuritySessionHandle handle) noexcept override {
        auto* slot = Resolve(handle);
        if (slot == nullptr) return false;
        const auto generation = slot->Generation;
        Erase(*slot);
        slot->Generation = generation;
        return true;
    }

    void ResetForControlledShutdown() noexcept override {
        for (auto& slot : _ephemeral) {
            const auto generation = slot.Generation;
            Erase(slot);
            slot.Generation = generation;
        }
        for (auto& slot : _sessions) {
            const auto generation = slot.Generation;
            Erase(slot);
            slot.Generation = generation;
        }
    }
};

#endif

} // namespace ESPressio::Security
