#pragma once

#include <cstdint>
#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

/// <summary>Resolves read-only cryptographic key views by key identifier and authenticated-encryption algorithm.</summary>
class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;

    /// <summary>Attempts to borrow key material suitable for the requested algorithm without allocating or copying its bytes.</summary>
    /// <param name="keyID">Application-defined key identifier.</param>
    /// <param name="algorithm">Algorithm for which the key will be used.</param>
    /// <param name="key">Receives a non-owning view of the provider's retained key material.</param>
    /// <returns><c>true</c> when matching key material is available.</returns>
    /// <remarks>The returned view is valid only until the provider is mutated or destroyed and must be consumed synchronously.</remarks>
    virtual bool GetKey(uint32_t keyID, AeadAlgorithm algorithm, KeyMaterialView& key) const = 0;
};

}