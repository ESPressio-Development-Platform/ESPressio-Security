#pragma once

#include <cstddef>
#include <cstdint>
#include <random>

namespace ESPressio::Security {

/// <summary>Provides random bytes for nonces, session identifiers, and other security material.</summary>
class IRandomSource {
public:
    virtual ~IRandomSource() = default;
    /// <summary>Fills the supplied output buffer with random bytes.</summary>
    /// <returns><c>true</c> when all requested bytes are produced.</returns>
    virtual bool Fill(uint8_t* output, std::size_t size) = 0;
};

/// <summary>Portable random source backed by <c>std::random_device</c>.</summary>
class StandardRandomSource final : public IRandomSource {
public:
    /// <inheritdoc/>
    bool Fill(uint8_t* output, std::size_t size) override {
        if (output == nullptr && size != 0) return false;
        std::random_device rd;
        for (std::size_t i = 0; i < size; ++i) output[i] = static_cast<uint8_t>(rd());
        return true;
    }
};

}
