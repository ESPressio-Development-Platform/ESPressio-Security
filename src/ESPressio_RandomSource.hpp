#pragma once

#include <ESPressio_SystemPlatformEntropy.hpp>
#include "ESPressio_IRandomSource.hpp"

namespace ESPressio::Security {

class RandomSource final : public IRandomSource {
public:
    bool Fill(uint8_t* output, std::size_t size) override {
        if (output == nullptr && size != 0) {
            return false;
        }

        auto& source = System::Entropy::Source();
        if (!source.IsCryptographicallySuitable()) {
            return false;
        }

        return static_cast<bool>(source.Fill(output, size));
    }
};

} // namespace ESPressio::Security
