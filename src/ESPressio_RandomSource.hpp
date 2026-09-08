#pragma once

#include <ESPressio_SystemPlatformEntropy.hpp>
#include "ESPressio_IRandomSource.hpp"

namespace ESPressio::Security {

/// <summary>Security random source backed by the active cryptographically suitable System entropy provider.</summary>
/**
 * ESPressio Memory Audit
 * Inherited Memory Total: 4 bytes [0 bytes dynamic allocation]
 * Members: none; polymorphic/virtual-base object metadata is included in the total.
 * Total Memory: 4 bytes [0 bytes dynamic allocation]
 * Basis: ESP32/Xtensa ILP32 reference ABI (4-byte pointers/size_t); ESPressio stateful allocators/deleters included; ABI-sensitive STL/platform internals are identified explicitly.
 * End ESPressio Memory Audit
 */
class RandomSource final : public IRandomSource {
public:
    /// <inheritdoc/>
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
