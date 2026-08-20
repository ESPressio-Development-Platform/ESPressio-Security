#pragma once

#include <cstdint>
#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;
    virtual bool GetKey(uint32_t keyID, AeadAlgorithm algorithm, KeyMaterial& key) const = 0;
};

}
