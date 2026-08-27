#pragma once

#include <ESPressio_Entropy.hpp>
#include "ESPressio_IRandomSource.hpp"

namespace ESPressio::Security {

class RandomSource final : public IRandomSource {
public:
    bool Fill(uint8_t* output, std::size_t size) override {
        if (!System::Entropy::Source().IsCryptographicallySecure()) {
            return false;
        }
        return static_cast<bool>(
            System::Entropy::Source().Fill(output, size)
        );
    }
};

} // namespace ESPressio::Security
