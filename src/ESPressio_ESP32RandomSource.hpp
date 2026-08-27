#pragma once

#include "ESPressio_IRandomSource.hpp"

#include <ESPressio_Entropy.hpp>

namespace ESPressio::Security {

class SystemEntropyRandomSource final : public IRandomSource {
public:
    bool Fill(uint8_t* output, std::size_t size) override {
        if (output == nullptr && size != 0) return false;

        auto& source = System::Entropy::Source();
        if (!source.IsCryptographicallySuitable()) return false;

        return static_cast<bool>(source.Fill(output, size));
    }
};

// Compatibility name retained for applications that previously selected the
// ESP32-specific random source explicitly. Entropy ownership now belongs to
// ESPressio-System and its installed platform provider.
using ESP32RandomSource = SystemEntropyRandomSource;

} // namespace ESPressio::Security
