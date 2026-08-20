#pragma once

#include <cstddef>
#include <cstdint>
#include <random>

namespace ESPressio::Security {

class IRandomSource {
public:
    virtual ~IRandomSource() = default;
    virtual bool Fill(uint8_t* output, std::size_t size) = 0;
};

class StandardRandomSource final : public IRandomSource {
public:
    bool Fill(uint8_t* output, std::size_t size) override {
        if (output == nullptr && size != 0) return false;
        std::random_device rd;
        for (std::size_t i = 0; i < size; ++i) output[i] = static_cast<uint8_t>(rd());
        return true;
    }
};

}
