#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

/// <summary>Non-owning associated context authenticated alongside protected data.</summary>
struct DataProtectionContext {
    const uint8_t* Data = nullptr;
    std::size_t Size = 0;

    DataProtectionContext() = default;
    DataProtectionContext(const uint8_t* data, std::size_t size) : Data(data), Size(size) {}
    explicit DataProtectionContext(const char* text)
        : Data(reinterpret_cast<const uint8_t*>(text)),
          Size(text == nullptr ? 0 : std::char_traits<char>::length(text)) {}
    explicit DataProtectionContext(const std::string& text)
        : Data(reinterpret_cast<const uint8_t*>(text.data())), Size(text.size()) {}
};

/// <summary>Protects and unprotects opaque application data using an implementation-defined authenticated envelope.</summary>
class IDataProtector {
public:
    virtual ~IDataProtector() = default;

    virtual SecurityResult Protect(
        const uint8_t* plaintext,
        std::size_t plaintextSize,
        SecurityBuffer& protectedData,
        const DataProtectionContext& context = {}
    ) = 0;

    virtual SecurityResult Unprotect(
        const uint8_t* protectedData,
        std::size_t protectedDataSize,
        SecurityBuffer& plaintext,
        const DataProtectionContext& context = {}
    ) = 0;

    SecurityResult ProtectString(
        const std::string& plaintext,
        SecurityBuffer& protectedData,
        const DataProtectionContext& context = {}
    ) {
        return Protect(
            reinterpret_cast<const uint8_t*>(plaintext.data()),
            plaintext.size(),
            protectedData,
            context
        );
    }

    SecurityResult UnprotectString(
        const uint8_t* protectedData,
        std::size_t protectedDataSize,
        std::string& plaintext,
        const DataProtectionContext& context = {}
    ) {
        SecurityBuffer bytes;
        const SecurityResult result = Unprotect(
            protectedData,
            protectedDataSize,
            bytes,
            context
        );
        if (!result.Success) return result;
        plaintext.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        return result;
    }
};

} // namespace ESPressio::Security
