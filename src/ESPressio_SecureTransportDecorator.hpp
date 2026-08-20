#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

#include "ESPressio_ISecureTransportCarrier.hpp"
#include "ESPressio_TransportSecurity.hpp"

namespace ESPressio::Security {

class SecureTransportDecorator final {
public:
    using Receiver = std::function<void(uint8_t protocol, const UnprotectedPayload& payload)>;
    using ErrorObserver = std::function<void(uint8_t protocol, const SecurityResult& result)>;

    SecureTransportDecorator(ITransportSecurityCarrier& carrier, TransportSecurity& security)
        : _carrier(carrier), _security(security) {
        _carrier.SetReceiver([this](uint8_t protocol, const uint8_t* data, std::size_t size) { HandleReceive(protocol, data, size); });
    }

    ~SecureTransportDecorator() { _carrier.SetReceiver({}); }

    bool Send(uint8_t protocol, const uint8_t* data, std::size_t size, SecurityResult* result = nullptr) {
        std::vector<uint8_t> secured;
        SecurityResult current = _security.Protect(protocol, data, size, secured);
        if (result != nullptr) *result = current;
        if (!current.Success) return false;
        return _carrier.Send(protocol, secured.data(), secured.size());
    }

    void SetReceiver(Receiver receiver) { _receiver = std::move(receiver); }
    void SetErrorObserver(ErrorObserver observer) { _errorObserver = std::move(observer); }

private:
    ITransportSecurityCarrier& _carrier;
    TransportSecurity& _security;
    Receiver _receiver;
    ErrorObserver _errorObserver;

    void HandleReceive(uint8_t protocol, const uint8_t* data, std::size_t size) {
        UnprotectedPayload payload;
        SecurityResult result = _security.Unprotect(protocol, data, size, payload);
        if (!result.Success) { if (_errorObserver) _errorObserver(protocol, result); return; }
        if (_receiver) _receiver(protocol, payload);
    }
};

}
