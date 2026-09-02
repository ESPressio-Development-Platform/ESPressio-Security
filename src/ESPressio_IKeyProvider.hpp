#pragma once

#include <cstdint>
#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

/// <summary>Resolves read-only cryptographic key views by key identifier and authenticated-encryption algorithm.</summary>
class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;

    /// <summary>Attempts to borrow key material suitable for the requested algorithm without copying its bytes.</summary>
    /// <param name="keyID">Application-defined key identifier.</param>
    /// <param name="algorithm">Algorithm for which the key will be used.</param>
    /// <param name="key">Receives a read-only view that pins the resolved key storage for the view lifetime.</param>
    /// <returns><c>true</c> when matching key material is available.</returns>
    /// <remarks>Implementations must ensure an already returned view remains valid even if the provider is subsequently mutated. Callers should retain the view only for the duration of the cryptographic operation so retired key material can be erased promptly.</remarks>
    virtual bool GetKey(uint32_t keyID, AeadAlgorithm algorithm, KeyMaterialView& key) const = 0;
};

}