#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

namespace ESPressio::Security {

class ITransportSecurityCarrier {
public:
    using Receiver = std::function<void(uint8_t protocol, const uint8_t* data, std::size_t size)>;
    virtual ~ITransportSecurityCarrier() = default;
    virtual bool Send(uint8_t protocol, const uint8_t* data, std::size_t size) = 0;
    virtual void SetReceiver(Receiver receiver) = 0;
};

}
