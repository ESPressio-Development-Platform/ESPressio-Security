#include <array>
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>
#include "ESPressio_Security.hpp"

using namespace ESPressio::Security;

class DeterministicProtectionRandom final : public IRandomSource {
public:
    bool Fill(uint8_t* output, std::size_t size) override {
        if (output == nullptr && size != 0) return false;
        for (std::size_t i = 0; i < size; ++i) output[i] = _next++;
        return true;
    }
private:
    uint8_t _next = 1;
};

class ProtectionTestCipher final : public IAeadCipher {
public:
    AeadAlgorithm Algorithm() const noexcept override { return AeadAlgorithm::TestOnly; }
    const char* Name() const noexcept override { return "TEST-ONLY"; }
    std::size_t KeySize() const noexcept override { return 16; }
    std::size_t NonceSize() const noexcept override { return 12; }
    std::size_t TagSize() const noexcept override { return 16; }

    bool Seal(const uint8_t* key,std::size_t ks,const uint8_t* nonce,std::size_t ns,const uint8_t* aad,std::size_t as,const uint8_t* p,std::size_t ps,std::vector<uint8_t>& c,std::vector<uint8_t>& tag) override {
        if (ks != 16 || ns != 12) return false;
        c.resize(ps); for (std::size_t i=0;i<ps;++i) c[i]=p[i]^key[i%ks]^nonce[i%ns]; MakeTag(key,ks,nonce,ns,aad,as,c.data(),c.size(),tag); return true;
    }
    bool Open(const uint8_t* key,std::size_t ks,const uint8_t* nonce,std::size_t ns,const uint8_t* aad,std::size_t as,const uint8_t* c,std::size_t cs,const uint8_t* tag,std::size_t ts,std::vector<uint8_t>& p) override {
        if (ks != 16 || ns != 12 || ts != 16) return false;
        std::vector<uint8_t> expected; MakeTag(key,ks,nonce,ns,aad,as,c,cs,expected); uint8_t diff=0; for(std::size_t i=0;i<ts;++i) diff|=expected[i]^tag[i]; if(diff) return false;
        p.resize(cs); for(std::size_t i=0;i<cs;++i) p[i]=c[i]^key[i%ks]^nonce[i%ns]; return true;
    }
private:
    static void MakeTag(const uint8_t* key,std::size_t ks,const uint8_t* nonce,std::size_t ns,const uint8_t* aad,std::size_t as,const uint8_t* data,std::size_t ds,std::vector<uint8_t>& tag) {
        uint32_t h=2166136261u; auto mix=[&](const uint8_t*x,std::size_t n){for(std::size_t i=0;i<n;++i){h^=x[i];h*=16777619u;}}; mix(key,ks);mix(nonce,ns);mix(aad,as);mix(data,ds); tag.resize(16); for(std::size_t i=0;i<tag.size();++i){h^=static_cast<uint32_t>(i*37u+11u);h*=16777619u;tag[i]=static_cast<uint8_t>(h>>((i%4)*8));}
    }
};

int main() {
    ProtectionTestCipher cipher;
    AeadCipherRegistry registry; assert(registry.Register(cipher));
    StaticKeyProvider keys;
    constexpr std::array<uint8_t,16> key = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    assert(keys.Add(7, AeadAlgorithm::TestOnly, key));
    DeterministicProtectionRandom random;
    DataProtectionConfig config; config.Algorithm=AeadAlgorithm::TestOnly; config.KeyID=7; config.MaximumPlaintextBytes=128;
    DataProtector protector(registry, keys, random, config);

    const std::string contextText = "ESPressio.WiFi.Configuration";
    const DataProtectionContext context(contextText);
    std::vector<uint8_t> protectedBytes;
    assert(protector.ProtectString("secret-value", protectedBytes, context).Success);
    assert(protectedBytes.size() > std::string("secret-value").size());

    std::string restored;
    assert(protector.UnprotectString(protectedBytes.data(), protectedBytes.size(), restored, context).Success);
    assert(restored == "secret-value");

    std::string wrongContext;
    const auto contextFailure = protector.UnprotectString(protectedBytes.data(), protectedBytes.size(), wrongContext, DataProtectionContext("Other.Context"));
    assert(!contextFailure.Success && contextFailure.Error == SecurityError::AuthenticationFailed);

    auto tampered = protectedBytes; tampered.back() ^= 0x80;
    std::vector<uint8_t> ignored;
    const auto tamperFailure = protector.Unprotect(tampered.data(), tampered.size(), ignored, context);
    assert(!tamperFailure.Success && tamperFailure.Error == SecurityError::AuthenticationFailed);

    auto badHeader = protectedBytes; badHeader[0] = 'X';
    assert(protector.Unprotect(badHeader.data(), badHeader.size(), ignored, context).Error == SecurityError::MalformedEnvelope);

    std::vector<uint8_t> oversized(129, 0x55), output;
    assert(protector.Protect(oversized.data(), oversized.size(), output).Error == SecurityError::BufferLimitExceeded);

    return 0;
}
