#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
#include "ESPressio_Security.hpp"
using namespace ESPressio::Security;

class DeterministicRandom final : public IRandomSource {
public: bool Fill(uint8_t* output,std::size_t size) override { for(std::size_t i=0;i<size;++i) output[i]=next++; return true; }
private: uint8_t next=1;
};

class TestCipher final : public IAeadCipher {
public:
    AeadAlgorithm Algorithm() const noexcept override{return AeadAlgorithm::TestOnly;} const char* Name() const noexcept override{return "TEST-ONLY";}
    std::size_t KeySize() const noexcept override{return 16;} std::size_t NonceSize() const noexcept override{return 12;} std::size_t TagSize() const noexcept override{return 16;}
    bool Seal(const uint8_t* key,std::size_t ks,const uint8_t* nonce,std::size_t ns,const uint8_t* aad,std::size_t as,const uint8_t* p,std::size_t ps,uint8_t* c,std::size_t cc,uint8_t* tag,std::size_t tc) override {
        if(ks!=16||ns!=12||cc<ps||tc<16)return false;for(std::size_t i=0;i<ps;++i)c[i]=p[i]^key[i%ks]^nonce[i%ns];MakeTag(key,ks,nonce,ns,aad,as,c,ps,tag);return true;
    }
    bool Open(const uint8_t* key,std::size_t ks,const uint8_t* nonce,std::size_t ns,const uint8_t* aad,std::size_t as,const uint8_t* c,std::size_t cs,const uint8_t* tag,std::size_t ts,uint8_t* p,std::size_t pc) override {
        if(ks!=16||ns!=12||ts!=16||pc<cs)return false;uint8_t expected[16]{};MakeTag(key,ks,nonce,ns,aad,as,c,cs,expected);uint8_t diff=0;for(std::size_t i=0;i<ts;++i)diff|=expected[i]^tag[i];if(diff)return false;for(std::size_t i=0;i<cs;++i)p[i]=c[i]^key[i%ks]^nonce[i%ns];return true;
    }
private:
    static void MakeTag(const uint8_t* key,std::size_t ks,const uint8_t* nonce,std::size_t ns,const uint8_t* aad,std::size_t as,const uint8_t* data,std::size_t ds,uint8_t* tag){uint32_t h=2166136261u;auto mix=[&](const uint8_t*x,std::size_t n){for(std::size_t i=0;i<n;++i){h^=x[i];h*=16777619u;}};mix(key,ks);mix(nonce,ns);mix(aad,as);mix(data,ds);for(std::size_t i=0;i<16;++i){h^=static_cast<uint32_t>(i*37u+11u);h*=16777619u;tag[i]=static_cast<uint8_t>(h>>((i%4)*8));}}
};

static TransportSecurity MakeSecurity(AeadCipherRegistry& registry,StaticKeyProvider& keys,DeterministicRandom& random,TransportSecurityPolicy policy=TransportSecurityPolicy::Required,uint32_t keyID=1,uint64_t senderID=0x1122334455667788ULL,uint64_t sessionID=0){TransportSecurityConfig config;config.Policy=policy;config.OutboundAlgorithm=AeadAlgorithm::TestOnly;config.OutboundKeyID=keyID;config.SenderID=senderID;config.SessionID=sessionID;config.MaximumPlaintextBytes=1024;return TransportSecurity(registry,keys,random,config);}

int main(){
    TestCipher cipher;AeadCipherRegistry registry;assert(registry.Register(cipher));assert(!registry.Register(cipher));
    StaticKeyProvider keys;uint8_t key1[16],key2[16];for(int i=0;i<16;++i){key1[i]=static_cast<uint8_t>(i+1);key2[i]=static_cast<uint8_t>(0xA0+i);}assert(keys.Add(1,AeadAlgorithm::TestOnly,key1,16));assert(keys.Add(2,AeadAlgorithm::TestOnly,key2,16));
    DeterministicRandom random;auto security=MakeSecurity(registry,keys,random);const uint8_t protocol=7;const char* message="secure event/command payload";
    std::vector<uint8_t> protectedBytes;auto pr=security.Protect(protocol,reinterpret_cast<const uint8_t*>(message),std::strlen(message),protectedBytes);assert(pr.Success&&pr.Protected);assert(security.GetSessionID()!=0);assert(TransportSecurity::LooksProtected(protectedBytes.data(),protectedBytes.size()));
    UnprotectedPayload opened;auto op=security.Unprotect(protocol,protectedBytes.data(),protectedBytes.size(),opened);assert(op.Success&&opened.Protected);assert(opened.Protocol==protocol&&opened.KeyID==1&&opened.SenderID==0x1122334455667788ULL&&opened.SessionID==security.GetSessionID()&&opened.Sequence==1);assert(std::string(opened.Data.begin(),opened.Data.end())==message);
    UnprotectedPayload tmp;auto replay=security.Unprotect(protocol,protectedBytes.data(),protectedBytes.size(),tmp);assert(!replay.Success&&replay.Error==SecurityError::ReplayDetected);
    auto tampered=protectedBytes;tampered.back()^=1;auto receiver2=MakeSecurity(registry,keys,random);auto tr=receiver2.Unprotect(protocol,tampered.data(),tampered.size(),tmp);assert(!tr.Success&&tr.Error==SecurityError::AuthenticationFailed);assert(receiver2.Unprotect(protocol,protectedBytes.data(),protectedBytes.size(),tmp).Success);
    auto receiver3=MakeSecurity(registry,keys,random);auto mismatch=receiver3.Unprotect(protocol+1,protectedBytes.data(),protectedBytes.size(),tmp);assert(!mismatch.Success&&mismatch.Error==SecurityError::ProtocolMismatch);
    auto headerTamper=protectedBytes;headerTamper[7]^=1;auto receiver4=MakeSecurity(registry,keys,random);assert(!receiver4.Unprotect(protocol,headerTamper.data(),headerTamper.size(),tmp).Success);
    auto sessionTamper=protectedBytes;sessionTamper[20]^=1;auto receiverSessionTamper=MakeSecurity(registry,keys,random);auto str=receiverSessionTamper.Unprotect(protocol,sessionTamper.data(),sessionTamper.size(),tmp);assert(!str.Success&&str.Error==SecurityError::AuthenticationFailed);
    auto senderKey2=MakeSecurity(registry,keys,random,TransportSecurityPolicy::Required,2,0x99);std::vector<uint8_t> rotated;assert(senderKey2.Protect(protocol,reinterpret_cast<const uint8_t*>(message),std::strlen(message),rotated).Success);auto receiverKey2=MakeSecurity(registry,keys,random);assert(receiverKey2.Unprotect(protocol,rotated.data(),rotated.size(),tmp).Success);assert(tmp.KeyID==2&&tmp.SenderID==0x99&&tmp.SessionID!=0);
    auto requiredPlain=receiverKey2.Unprotect(protocol,reinterpret_cast<const uint8_t*>(message),std::strlen(message),tmp);assert(!requiredPlain.Success&&requiredPlain.Error==SecurityError::PlaintextRejected);
    auto preferred=MakeSecurity(registry,keys,random,TransportSecurityPolicy::Preferred);assert(preferred.Unprotect(protocol,reinterpret_cast<const uint8_t*>(message),std::strlen(message),tmp).Success&&!tmp.Protected);
    auto disabled=MakeSecurity(registry,keys,random,TransportSecurityPolicy::Disabled);std::vector<uint8_t> plain;auto dr=disabled.Protect(protocol,reinterpret_cast<const uint8_t*>(message),std::strlen(message),plain);assert(dr.Success&&!dr.Protected&&std::string(plain.begin(),plain.end())==message);
    AeadCipherRegistry empty;auto preferredNoCipher=MakeSecurity(empty,keys,random,TransportSecurityPolicy::Preferred);std::vector<uint8_t> fallback;auto fr=preferredNoCipher.Protect(protocol,reinterpret_cast<const uint8_t*>(message),std::strlen(message),fallback);assert(fr.Success&&!fr.Protected);
    auto senderSeq=MakeSecurity(registry,keys,random,TransportSecurityPolicy::Required,1,0xABC,0x1111);std::vector<uint8_t> p1,p2;assert(senderSeq.Protect(protocol,reinterpret_cast<const uint8_t*>("one"),3,p1).Success);assert(senderSeq.Protect(protocol,reinterpret_cast<const uint8_t*>("two"),3,p2).Success);auto receiverSeq=MakeSecurity(registry,keys,random);assert(receiverSeq.Unprotect(protocol,p2.data(),p2.size(),tmp).Success);assert(receiverSeq.Unprotect(protocol,p1.data(),p1.size(),tmp).Success);auto old=receiverSeq.Unprotect(protocol,p1.data(),p1.size(),tmp);assert(!old.Success&&old.Error==SecurityError::ReplayDetected);
    auto rebootedSender=MakeSecurity(registry,keys,random,TransportSecurityPolicy::Required,1,0xABC,0x2222);std::vector<uint8_t> afterReboot;assert(rebootedSender.Protect(protocol,reinterpret_cast<const uint8_t*>("new"),3,afterReboot).Success);assert(receiverSeq.Unprotect(protocol,afterReboot.data(),afterReboot.size(),tmp).Success);assert(tmp.Sequence==1&&tmp.SessionID==0x2222);assert(!receiverSeq.Unprotect(protocol,afterReboot.data(),afterReboot.size(),tmp).Success);
    auto configured=MakeSecurity(registry,keys,random,TransportSecurityPolicy::Required,1,0x55,0xABCDEF);std::vector<uint8_t> configuredPacket;assert(configured.Protect(protocol,reinterpret_cast<const uint8_t*>("cfg"),3,configuredPacket).Success);assert(configured.GetSessionID()==0xABCDEF);auto config=configured.GetConfig();config.SessionID=0;configured.SetConfig(config);assert(configured.GetSessionID()==0);assert(configured.Protect(protocol,reinterpret_cast<const uint8_t*>("auto"),4,configuredPacket).Success);assert(configured.GetSessionID()!=0&&configured.GetSessionID()!=0xABCDEF);
    auto truncated=p2;truncated.pop_back();auto malformedReceiver=MakeSecurity(registry,keys,random);auto mr=malformedReceiver.Unprotect(protocol,truncated.data(),truncated.size(),tmp);assert(!mr.Success&&mr.Error==SecurityError::MalformedEnvelope);
    std::vector<uint8_t> tooLarge(1025,0x55),ignored;assert(!security.Protect(protocol,tooLarge.data(),tooLarge.size(),ignored).Success);
    std::cout<<"All ESPressio Security tests passed\n";
}
