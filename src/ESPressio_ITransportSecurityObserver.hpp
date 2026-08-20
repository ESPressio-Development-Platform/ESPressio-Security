#pragma once

#include <cstdint>

#include <ESPressio_IObserver.hpp>

#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

class ITransportSecurityObserver :
    public virtual Observable::IObserver {
public:
    virtual ~ITransportSecurityObserver() = default;

    virtual void OnTransportSecurityConfigurationChanged(
        const TransportSecurityConfig&,
        const TransportSecurityConfig&
    ) {}

    virtual void OnTransportSecuritySessionReset(
        uint64_t
    ) {}

    virtual void OnTransportSecuritySessionEstablished(
        uint64_t
    ) {}

    virtual void OnTransportSecurityReplayProtectionReset() {}

    virtual void OnTransportSecurityFailure(
        const SecurityResult&
    ) {}
};

} // namespace ESPressio::Security
