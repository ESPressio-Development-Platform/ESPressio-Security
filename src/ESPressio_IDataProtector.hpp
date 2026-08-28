#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "ESPressio_SecurityTypes.hpp"

namespace ESPressio::Security {

/// <summary>Non-owning associated context authenticated alongside protected data.</summary>
struct DataProtectionContext {
    /// <summary>Pointer to context bytes, or null when no context is supplied.</summary>
    const uint8_t* Data = nullptr;
    /// <summary>Number of context bytes.</summary>
    std::size_t Size = 0;

    /// <summary>Creates an empty protection context.</summary>
    DataProtectionContext() = default;
    /// <summary>Creates a non-owning protection context over a byte range.</summary>
    DataProtectionContext(const uint8_t* data, std::size_t size) : Data(data), Size(size) {}
    /// <summary>Creates a protection context over a null-terminated text value.</summary>
    explicit DataProtectionContext(const char* text)
        : Data(reinterpret_cast<const uint8_t*>(text)),
          Size(text == nullptr ? 0 : std::char_traits<char>::length(text)) {}
    /// <summary>Creates a protection context over the bytes of a string.</summary>
    explicit DataProtectionContext(const std::string& text)
        : Data(reinterpret_cast<const uint8_t*>(text.data())), Size(text.size()) {}
};

/// <summary>Protects and unprotects opaque application data using an implementation-defined authenticated envelope.</summary>
class IDataProtector {
public:
    virtual ~IDataProtector() = default;

    /// <summary>Protects plaintext bytes and writes the resulting authenticated envelope.</summary>
    /// <param name="plaintext">Plaintext bytes to protect.</param>
    /// <param name="plaintextSize">Number of plaintext bytes.</param>
    /// <param name="protectedData">Receives the protected envelope.</param>
    /// <param name="context">Optional associated context authenticated with the payload.</param>
    virtual SecurityResult Protect(
        const uint8_t* plaintext,
        std::size_t plaintextSize,
        std::vector<uint8_t>& protectedData,
        const DataProtectionContext& context = {}
    ) = 0;

    /// <summary>Authenticates and recovers plaintext from protected data.</summary>
    /// <param name="protectedData">Protected envelope bytes.</param>
    /// <param name="protectedDataSize">Number of protected bytes.</param>
    /// <param name="plaintext">Receives recovered plaintext.</param>
    /// <param name="context">Associated context that must match the context used during protection.</param>
    virtual SecurityResult Unprotect(
        const uint8_t* protectedData,
        std::size_t protectedDataSize,
        std::vector<uint8_t>& plaintext,
        const DataProtectionContext& context = {}
    ) = 0;

    /// <summary>Protects the bytes of a string using the underlying byte-oriented protector.</summary>
    SecurityResult ProtectString(
        const std::string& plaintext,
        std::vector<uint8_t>& protectedData,
        const DataProtectionContext& context = {}
    ) {
        return Protect(
            reinterpret_cast<const uint8_t*>(plaintext.data()),
            plaintext.size(),
            protectedData,
            context
        );
    }

    /// <summary>Authenticates protected data and recovers it as a string.</summary>
    SecurityResult UnprotectString(
        const uint8_t* protectedData,
        std::size_t protectedDataSize,
        std::string& plaintext,
        const DataProtectionContext& context = {}
    ) {
        std::vector<uint8_t> bytes;
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
