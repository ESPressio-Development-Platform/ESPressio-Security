#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

#include "ESPressio_ISecureTransportCarrier.hpp"
#include "ESPressio_TransportSecurity.hpp"

namespace ESPressio::Security {

/// <summary>Decorates a transport carrier with authenticated protection and unprotection supplied by <c>TransportSecurity</c>.</summary>
/// <remarks>The decorator borrows both the carrier and security service for its lifetime and installs itself as the carrier receiver until destruction.</remarks>
class SecureTransportDecorator final {
public:
    /// <summary>Callback receiving successfully authenticated and unprotected application payloads.</summary>
    using Receiver = std::function<void(uint8_t protocol, const UnprotectedPayload& payload)>;
    /// <summary>Callback receiving inbound security failures that prevent payload delivery.</summary>
    using ErrorObserver = std::function<void(uint8_t protocol, const SecurityResult& result)>;

    /// <summary>Creates a secure decorator and binds its inbound handler to the supplied carrier.</summary>
    /// <param name="carrier">Underlying transport carrier used to transmit and receive secured bytes.</param>
    /// <param name="security">Security service used to protect outbound and unprotect inbound payloads.</param>
    SecureTransportDecorator(ITransportSecurityCarrier& carrier, TransportSecurity& security)
        : _carrier(carrier), _security(security) {
        _carrier.SetReceiver([this](uint8_t protocol, const uint8_t* data, std::size_t size) { HandleReceive(protocol, data, size); });
    }

    /// <summary>Detaches the carrier receive callback.</summary>
    ~SecureTransportDecorator() { _carrier.SetReceiver({}); }

    /// <summary>Protects an application payload and sends the resulting secured envelope through the carrier.</summary>
    /// <param name="protocol">Application protocol discriminator included in security processing.</param>
    /// <param name="data">Plaintext payload bytes.</param>
    /// <param name="size">Plaintext payload size in bytes.</param>
    /// <param name="result">Optional destination for the protection result.</param>
    /// <returns><c>true</c> only when protection succeeds and the carrier accepts the secured envelope.</returns>
    bool Send(uint8_t protocol, const uint8_t* data, std::size_t size, SecurityResult* result = nullptr) {
        std::vector<uint8_t> secured;
        SecurityResult current = _security.Protect(protocol, data, size, secured);
        if (result != nullptr) *result = current;
        if (!current.Success) return false;
        return _carrier.Send(protocol, secured.data(), secured.size());
    }

    /// <summary>Sets the callback that receives successfully unprotected inbound payloads.</summary>
    void SetReceiver(Receiver receiver) { _receiver = std::move(receiver); }
    /// <summary>Sets the callback notified when inbound security processing fails.</summary>
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
