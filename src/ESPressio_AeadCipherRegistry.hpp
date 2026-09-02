#pragma once

#include <algorithm>
#include <ESPressio_Memory.hpp>
#include "ESPressio_IAeadCipher.hpp"

namespace ESPressio::Security {

/// <summary>Maintains non-owning registrations of authenticated-encryption implementations keyed by algorithm.</summary>
/// <remarks>Registry capacity uses ESPressio System ExternalPreferred storage because cipher registrations do not require internal or DMA-capable RAM.</remarks>
class AeadCipherRegistry {
public:
    /// <summary>Registers a cipher when no implementation for the same algorithm already exists.</summary>
    /// <returns><c>true</c> when the cipher was added.</returns>
    bool Register(IAeadCipher& cipher) {
        if (Find(cipher.Algorithm()) != nullptr) return false;
        _ciphers.push_back(&cipher);
        return true;
    }

    /// <summary>Removes the registered cipher for an algorithm.</summary>
    bool Unregister(AeadAlgorithm algorithm) {
        auto found = std::find_if(_ciphers.begin(), _ciphers.end(), [&](IAeadCipher* current) { return current->Algorithm() == algorithm; });
        if (found == _ciphers.end()) return false;
        _ciphers.erase(found);
        return true;
    }

    /// <summary>Finds the registered cipher implementing the requested algorithm.</summary>
    /// <returns>The registered cipher, or null when the algorithm is unavailable.</returns>
    IAeadCipher* Find(AeadAlgorithm algorithm) const noexcept {
        auto found = std::find_if(_ciphers.begin(), _ciphers.end(), [&](IAeadCipher* current) { return current->Algorithm() == algorithm; });
        return found == _ciphers.end() ? nullptr : *found;
    }

private:
    System::Memory::Vector<
        IAeadCipher*,
        System::Memory::MemoryPolicy::ExternalPreferred
    > _ciphers;
};

}
