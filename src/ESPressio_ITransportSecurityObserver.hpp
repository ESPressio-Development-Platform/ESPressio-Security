#pragma once

#include <cstdint>

#include <ESPressio_IObserver.hpp>

#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

/// <summary>Observes transport-security configuration, session, replay-protection, and failure events.</summary>
/**
 * ESPressio Memory Audit
 * Inherited Memory Total: 4 bytes [0 bytes dynamic allocation]
 * Members: none; polymorphic/virtual-base object metadata is included in the total.
 * Total Memory: 4 bytes [0 bytes dynamic allocation]
 * Basis: ESP32/Xtensa ILP32 reference ABI (4-byte pointers/size_t); ESPressio stateful allocators/deleters included; ABI-sensitive STL/platform internals are identified explicitly.
 * End ESPressio Memory Audit
 */
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
