#pragma once

#include <algorithm>
#include <vector>
#include "ESPressio_IAeadCipher.hpp"

namespace ESPressio::Security {

class AeadCipherRegistry {
public:
    bool Register(IAeadCipher& cipher) {
        if (Find(cipher.Algorithm()) != nullptr) return false;
        _ciphers.push_back(&cipher);
        return true;
    }

    bool Unregister(AeadAlgorithm algorithm) {
        auto found = std::find_if(_ciphers.begin(), _ciphers.end(), [&](IAeadCipher* current) { return current->Algorithm() == algorithm; });
        if (found == _ciphers.end()) return false;
        _ciphers.erase(found);
        return true;
    }

    IAeadCipher* Find(AeadAlgorithm algorithm) const noexcept {
        auto found = std::find_if(_ciphers.begin(), _ciphers.end(), [&](IAeadCipher* current) { return current->Algorithm() == algorithm; });
        return found == _ciphers.end() ? nullptr : *found;
    }

private:
    std::vector<IAeadCipher*> _ciphers;
};

}
