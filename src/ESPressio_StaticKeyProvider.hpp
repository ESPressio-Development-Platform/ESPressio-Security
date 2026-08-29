#pragma once

#include <algorithm>
#include <array>
#include <cstdint>

#include <ESPressio_Memory.hpp>

#include "ESPressio_IKeyProvider.hpp"

namespace ESPressio::Security {

/// <summary>In-memory key provider that owns a static set of algorithm-specific key entries.</summary>
class StaticKeyProvider final : public IKeyProvider {
public:
    /// <summary>Owned key entry identified by key ID and authenticated-encryption algorithm.</summary>
    /// <remarks>Key bytes use the common Security buffer type so retained key storage follows the System external-preferred policy consistently.</remarks>
    struct Entry {
        uint32_t KeyID = 0;
        AeadAlgorithm Algorithm = AeadAlgorithm::Unknown;
        SecurityBuffer Bytes;
    };

    /// <summary>Securely clears retained key bytes before destruction.</summary>
    ~StaticKeyProvider() override { Clear(); }

    /// <summary>Adds or replaces a key entry from a raw byte range.</summary>
    bool Add(uint32_t keyID, AeadAlgorithm algorithm, const uint8_t* key, std::size_t size) {
        if (keyID == 0 || key == nullptr || size == 0) return false;
        Remove(keyID, algorithm);
        Entry entry;
        entry.KeyID = keyID;
        entry.Algorithm = algorithm;
        entry.Bytes.assign(key, key + size);
        _entries.push_back(std::move(entry));
        return true;
    }

    /// <summary>Adds or replaces a key entry from a fixed-size byte array.</summary>
    template<std::size_t N>
    bool Add(uint32_t keyID, AeadAlgorithm algorithm, const std::array<uint8_t, N>& key) {
        static_assert(N > 0, "A static key must contain at least one byte");
        return Add(keyID, algorithm, key.data(), key.size());
    }

    /// <summary>Removes and securely erases the matching key entry.</summary>
    bool Remove(uint32_t keyID, AeadAlgorithm algorithm) {
        auto found = std::find_if(
            _entries.begin(),
            _entries.end(),
            [&](const Entry& entry) {
                return entry.KeyID == keyID && entry.Algorithm == algorithm;
            }
        );
        if (found == _entries.end()) return false;
        SecureErase(found->Bytes);
        _entries.erase(found);
        return true;
    }

    /// <summary>Securely erases all retained key entries.</summary>
    void Clear() {
        for (auto& entry : _entries) SecureErase(entry.Bytes);
        _entries.clear();
    }

    /// <inheritdoc/>
    bool GetKey(uint32_t keyID, AeadAlgorithm algorithm, KeyMaterial& key) const override {
        auto found = std::find_if(
            _entries.begin(),
            _entries.end(),
            [&](const Entry& entry) {
                return entry.KeyID == keyID && entry.Algorithm == algorithm;
            }
        );
        if (found == _entries.end()) return false;
        key.KeyID = found->KeyID;
        key.Bytes = found->Bytes;
        return true;
    }

    /// <summary>Overwrites an owned byte buffer before releasing its logical contents.</summary>
    template<typename TBuffer>
    static void SecureErase(TBuffer& bytes) noexcept {
        volatile uint8_t* pointer = bytes.empty() ? nullptr : bytes.data();
        for (std::size_t index = 0;
             pointer != nullptr && index < bytes.size();
             ++index) {
            pointer[index] = 0;
        }
        bytes.clear();
    }

private:
    System::Memory::Vector<
        Entry,
        System::Memory::MemoryPolicy::ExternalPreferred
    > _entries;
};

}
