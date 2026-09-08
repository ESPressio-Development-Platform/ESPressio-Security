#include <cassert>
#include <cstdint>
#include <vector>

#include <ESPressio_Security.hpp>

using namespace ESPressio::Security;

/**
 * ESPressio Memory Audit
 * Inherited Memory Total: 4 bytes [0 bytes dynamic allocation]
 * Members:
 * - ConfigurationChanged (int): 4 bytes [0 bytes dynamic allocation]
 * - SessionReset (int): 4 bytes [0 bytes dynamic allocation]
 * - SessionEstablished (int): 4 bytes [0 bytes dynamic allocation]
 * - ReplayReset (int): 4 bytes [0 bytes dynamic allocation]
 * - Failures (int): 4 bytes [0 bytes dynamic allocation]
 * - LastSession (uint64_t): 8 bytes [0 bytes dynamic allocation]
 * Total Memory: 32 bytes [0 bytes dynamic allocation]
 * Basis: ESP32/Xtensa ILP32 reference ABI (4-byte pointers/size_t); ESPressio stateful allocators/deleters included; ABI-sensitive STL/platform internals are identified explicitly.
 * End ESPressio Memory Audit
 */
class Observer final : public ITransportSecurityObserver {
public:
    int ConfigurationChanged = 0;
    int SessionReset = 0;
    int SessionEstablished = 0;
    int ReplayReset = 0;
    int Failures = 0;
    uint64_t LastSession = 0;

    void OnTransportSecurityConfigurationChanged(
        const TransportSecurityConfig&,
        const TransportSecurityConfig&
    ) override { ++ConfigurationChanged; }

    void OnTransportSecuritySessionReset(uint64_t) override { ++SessionReset; }

    void OnTransportSecuritySessionEstablished(uint64_t sessionID) override {
        ++SessionEstablished;
        LastSession = sessionID;
    }

    void OnTransportSecurityReplayProtectionReset() override { ++ReplayReset; }

    void OnTransportSecurityFailure(const SecurityResult&) override { ++Failures; }
};

int main() {
    AeadCipherRegistry ciphers;
    StaticKeyProvider keys;
    StandardRandomSource random;
    TransportSecurity security(ciphers, keys, random);
    Observer observer;
    auto handle = security.RegisterObserver(&observer);
    assert(handle);

    TransportSecurityConfig config = security.GetConfig();
    config.SessionID = 42;
    security.SetConfig(config);
    assert(observer.ConfigurationChanged == 1);
    assert(observer.SessionEstablished == 1);
    assert(observer.LastSession == 42);

    config.SessionID = 84;
    security.SetConfig(config);
    assert(observer.ConfigurationChanged == 2);
    assert(observer.SessionReset == 1);
    assert(observer.SessionEstablished == 2);
    assert(observer.LastSession == 84);

    security.ResetReplayProtection();
    assert(observer.ReplayReset == 1);

    std::vector<uint8_t> output;
    auto result = security.Protect(1, nullptr, 1, output);
    assert(!result.Success);
    assert(observer.Failures == 1);

    handle.reset();
    security.ResetReplayProtection();
    assert(observer.ReplayReset == 1);
    return 0;
}
