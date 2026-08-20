#pragma once

#include "ESPressio_IRandomSource.hpp"

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
#include <esp_system.h>

namespace ESPressio::Security {

class ESP32RandomSource final : public IRandomSource {
public:
    bool Fill(uint8_t* output, std::size_t size) override {
        if (output == nullptr && size != 0) return false;
        if (size != 0) esp_fill_random(output, size);
        return true;
    }
};

}
#endif
