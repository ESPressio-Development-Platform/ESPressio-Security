#pragma once

#include <cstdint>

#include <ESPressio_IObserver.hpp>

#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

/// <summary>Observes transport-security configuration, session, replay-protection, and failure events.</summary>
class ITransportSecurityObserver :
    public virtual Observable::IObserver {
public:
    virtual ~ITransportSecurityObserver() = default;

    /// <summary>Called after the active transport-security configuration changes.</summary>
    virtual void OnTransportSecurityConfigurationChanged(
        const TransportSecurityConfig&,
        const TransportSecurityConfig&
    ) {}

    /// <summary>Called when transport-security sequence/session state is reset.</summary>
    virtual void OnTransportSecuritySessionReset(
        uint64_t
    ) {}

    /// <summary>Called when a transport-security session becomes established.</summary>
    virtual void OnTransportSecuritySessionEstablished(
        uint64_t
    ) {}

    /// <summary>Called when inbound replay-protection state is reset.</summary>
    virtual void OnTransportSecurityReplayProtectionReset() {}

    /// <summary>Called when a transport-security operation reports a failure.</summary>
    virtual void OnTransportSecurityFailure(
        const SecurityResult&
    ) {}
};

} // namespace ESPressio::Security
