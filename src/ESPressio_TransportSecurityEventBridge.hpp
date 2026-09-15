#pragma once

#include <atomic>
#include <cstdint>
#include <utility>

#include <ESPressio_ITransportSecurityObserver.hpp>
#include <ESPressio_TransportSecurity.hpp>

#include "ESPressio_SecurityEvents.hpp"

namespace ESPressio::Event {

/// Caller-owned optional projection from TransportSecurity observer callbacks
/// into the bounded Event family. Event pressure never blocks Security and never
/// changes Security-domain truth; missed diagnostic occurrences are counted.
class TransportSecurityEventBridge final :
    public Security::ITransportSecurityObserver {
private:
    Observable::ObserverHandlePtr _observerHandle;
    bool _initialized = false;
    std::atomic<std::uint64_t> _unavailableOccurrences{0U};

    template<class TEvent, class... Args>
    void Emit(Args&&... args) noexcept {
        try {
            if (!TEvent::TryDispatch(std::forward<Args>(args)...)) {
                ++_unavailableOccurrences;
            }
        } catch (...) {
            ++_unavailableOccurrences;
        }
    }

public:
    TransportSecurityEventBridge() = default;
    TransportSecurityEventBridge(const TransportSecurityEventBridge&) = delete;
    TransportSecurityEventBridge& operator=(const TransportSecurityEventBridge&) = delete;
    ~TransportSecurityEventBridge() override { Shutdown(); }

    bool Initialize(Security::TransportSecurity& security) {
        if (_initialized) return true;
        _observerHandle = security.RegisterObserver(this);
        _initialized = static_cast<bool>(_observerHandle);
        return _initialized;
    }

    void Shutdown() noexcept {
        _observerHandle.reset();
        _initialized = false;
    }

    bool IsInitialized() const noexcept { return _initialized; }

    std::uint64_t UnavailableOccurrences() const noexcept {
        return _unavailableOccurrences.load(std::memory_order_relaxed);
    }

    void OnTransportSecurityConfigurationChanged(
        const Security::TransportSecurityConfig& before,
        const Security::TransportSecurityConfig& after
    ) override {
        Emit<TransportSecurityConfigurationChangedEvent>(before, after);
    }

    void OnTransportSecuritySessionReset(std::uint64_t previousSessionID) override {
        Emit<TransportSecuritySessionResetEvent>(previousSessionID);
    }

    void OnTransportSecuritySessionEstablished(std::uint64_t sessionID) override {
        Emit<TransportSecuritySessionEstablishedEvent>(sessionID);
    }

    void OnTransportSecurityReplayProtectionReset() override {
        Emit<TransportSecurityReplayProtectionResetEvent>();
    }

    void OnTransportSecurityFailure(const Security::SecurityResult& result) override {
        Emit<TransportSecurityFailureEvent>(result);
    }
};

} // namespace ESPressio::Event
