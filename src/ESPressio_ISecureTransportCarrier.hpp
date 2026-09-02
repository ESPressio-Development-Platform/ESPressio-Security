#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

namespace ESPressio::Security {

/// <summary>Abstracts the underlying protocol-multiplexed carrier wrapped by transport security.</summary>
class ITransportSecurityCarrier {
public:
    /// <summary>Callback invoked when a protocol payload is received from the underlying carrier.</summary>
    using Receiver = std::function<void(uint8_t protocol, const uint8_t* data, std::size_t size)>;
    virtual ~ITransportSecurityCarrier() = default;
    /// <summary>Sends one protocol payload through the underlying carrier.</summary>
    virtual bool Send(uint8_t protocol, const uint8_t* data, std::size_t size) = 0;
    /// <summary>Installs the callback that consumes payloads received from the carrier.</summary>
    virtual void SetReceiver(Receiver receiver) = 0;
};

}
