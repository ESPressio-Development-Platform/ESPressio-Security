#pragma once

#include <ESPressio_ITransportSecurityObserver.hpp>
#include <ESPressio_TransportSecurity.hpp>

#include "ESPressio_SecurityEvents.hpp"

namespace ESPressio::Event {

/**
 * ESPressio Memory Audit
 * Inherited Memory Total: 4 bytes [0 bytes dynamic allocation]
 * Members:
 * - _observerHandle (Observable::ObserverHandlePtr): 12 bytes [owned object: 4 bytes]
 * - _initialized (bool): 1 bytes [0 bytes dynamic allocation]
 * Total Memory: 20 bytes [_observerHandle: owned object: 4 bytes]
 * Basis: ESP32/Xtensa ILP32 reference ABI (4-byte pointers/size_t); ESPressio stateful allocators/deleters included; ABI-sensitive STL/platform internals are identified explicitly.
 * Confidence: medium; compile-time sizeof on the concrete target remains authoritative for ABI-sensitive/opaque members.
 * End ESPressio Memory Audit
 */
class TransportSecurityEventBridge final :
    public Security::ITransportSecurityObserver {
private:
    Observable::ObserverHandlePtr _observerHandle;
    bool _initialized = false;

public:
    TransportSecurityEventBridge() = default;
    TransportSecurityEventBridge(const TransportSecurityEventBridge&) = delete;
    TransportSecurityEventBridge& operator=(const TransportSecurityEventBridge&) = delete;

    bool Initialize(Security::TransportSecurity& security) {
        if (_initialized) return true;
        _observerHandle = security.RegisterObserver(this);
        _initialized = static_cast<bool>(_observerHandle);
        return _initialized;
    }

    void Shutdown() {
        _observerHandle.reset();
        _initialized = false;
    }

    bool IsInitialized() const { return _initialized; }

    void OnTransportSecurityConfigurationChanged(
        const Security::TransportSecurityConfig& before,
        const Security::TransportSecurityConfig& after
    ) override {
        (new TransportSecurityConfigurationChangedEvent(before, after))->Queue();
    }

    void OnTransportSecuritySessionReset(uint64_t previousSessionID) override {
        (new TransportSecuritySessionResetEvent(previousSessionID))->Queue();
    }

    void OnTransportSecuritySessionEstablished(uint64_t sessionID) override {
        (new TransportSecuritySessionEstablishedEvent(sessionID))->Queue();
    }

    void OnTransportSecurityReplayProtectionReset() override {
        (new TransportSecurityReplayProtectionResetEvent())->Queue();
    }

    void OnTransportSecurityFailure(const Security::SecurityResult& result) override {
        (new TransportSecurityFailureEvent(result))->Queue();
    }
};

} // namespace ESPressio::Event
