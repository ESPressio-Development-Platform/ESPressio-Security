#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

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
    explicit DataProtectionContext(std::string_view text)
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

    /// <summary>Protects a borrowed string view without constructing an intermediate owning string.</summary>
    SecurityResult ProtectString(
        std::string_view plaintext,
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

    /// <summary>Unprotects text directly into caller-selected string storage.</summary>
    /// <typeparam name="TString">String-like destination supporting <c>assign(const char*, size_t)</c>.</typeparam>
    /// <remarks>Using <c>SecurityString</c> keeps the recovered text in externally preferred memory; standard strings remain available at explicit application boundaries.</remarks>
    template<typename TString>
    SecurityResult UnprotectString(
        const uint8_t* protectedData,
        std::size_t protectedDataSize,
        TString& plaintext,
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
