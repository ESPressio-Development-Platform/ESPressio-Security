#pragma once

#include <cstdint>
#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

/// <summary>Resolves cryptographic key material by key identifier and authenticated-encryption algorithm.</summary>
class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;
    /// <summary>Attempts to resolve key material suitable for the requested algorithm.</summary>
    /// <param name="keyID">Application-defined key identifier.</param>
    /// <param name="algorithm">Algorithm for which the key will be used.</param>
    /// <param name="key">Receives the resolved key material.</param>
    /// <returns><c>true</c> when matching key material is available.</returns>
    virtual bool GetKey(uint32_t keyID, AeadAlgorithm algorithm, KeyMaterial& key) const = 0;
};

}
