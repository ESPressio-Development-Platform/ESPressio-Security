#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <mutex>

#include <ESPressio_Memory.hpp>
#include <ESPressio_Synchronization.hpp>

#include "ESPressio_IKeyProvider.hpp"

namespace ESPressio::Security {

/// <summary>In-memory key provider that owns a static set of algorithm-specific key entries.</summary>
/// <remarks>Entry mutation is serialized and returned key views retain immutable shared backing storage, so key rotation/removal cannot invalidate an in-flight cryptographic operation.</remarks>
class StaticKeyProvider final : public IKeyProvider {
private:
    static constexpr auto ExternalPreferred =
        System::Memory::MemoryPolicy::ExternalPreferred;

public:
    /// <summary>Owned key entry identified by key ID and authenticated-encryption algorithm.</summary>
    /// <remarks>The entry retains immutable shared key storage whose byte buffer follows the System external-preferred policy consistently.</remarks>
    struct Entry {
        uint32_t KeyID = 0;
        AeadAlgorithm Algorithm = AeadAlgorithm::Unknown;
        std::shared_ptr<KeyMaterialStorage> Storage;
    };

    /// <summary>Securely clears retained key bytes before destruction once all in-flight views have released them.</summary>
    ~StaticKeyProvider() override { Clear(); }

    /// <summary>Adds or replaces a key entry from a raw byte range.</summary>
    bool Add(uint32_t keyID, AeadAlgorithm algorithm, const uint8_t* key, std::size_t size) {
        if (keyID == 0 || key == nullptr || size == 0) return false;

        std::shared_ptr<KeyMaterialStorage> storage;
        try {
            storage = System::Memory::MakeShared<
                KeyMaterialStorage,
                ExternalPreferred
            >();
            storage->Bytes.assign(key, key + size);
        } catch (...) {
            return false;
        }

        std::lock_guard<System::Synchronization::Mutex> lock(_mutex);
        auto found = FindLocked(keyID, algorithm);
        if (found != _entries.end()) {
            found->Storage = std::move(storage);
            return true;
        }

        try {
            _entries.push_back(Entry{
                keyID,
                algorithm,
                std::move(storage)
            });
        } catch (...) {
            return false;
        }
        return true;
    }

    /// <summary>Adds or replaces a key entry from a fixed-size byte array.</summary>
    template<std::size_t N>
    bool Add(uint32_t keyID, AeadAlgorithm algorithm, const std::array<uint8_t, N>& key) {
        static_assert(N > 0, "A static key must contain at least one byte");
        return Add(keyID, algorithm, key.data(), key.size());
    }

    /// <summary>Removes the matching key entry.</summary>
    /// <remarks>Storage is securely erased as soon as the last in-flight <c>KeyMaterialView</c> releases it; an active operation therefore keeps a valid immutable snapshot through rotation/removal.</remarks>
    bool Remove(uint32_t keyID, AeadAlgorithm algorithm) {
        std::lock_guard<System::Synchronization::Mutex> lock(_mutex);
        auto found = FindLocked(keyID, algorithm);
        if (found == _entries.end()) return false;
        _entries.erase(found);
        return true;
    }

    /// <summary>Removes all retained key entries.</summary>
    /// <remarks>Each key is securely erased when its final in-flight view is released.</remarks>
    void Clear() {
        System::Memory::Vector<Entry, ExternalPreferred> removed;
        {
            std::lock_guard<System::Synchronization::Mutex> lock(_mutex);
            removed.swap(_entries);
        }
    }

    /// <inheritdoc/>
    bool GetKey(uint32_t keyID, AeadAlgorithm algorithm, KeyMaterialView& key) const override {
        key = {};
        std::lock_guard<System::Synchronization::Mutex> lock(_mutex);
        auto found = FindLocked(keyID, algorithm);
        if (found == _entries.end() || !found->Storage) return false;
        key.Bind(found->KeyID, found->Storage);
        return !key.Empty();
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
    using EntryStorage = System::Memory::Vector<Entry, ExternalPreferred>;
    using EntryIterator = EntryStorage::iterator;
    using ConstEntryIterator = EntryStorage::const_iterator;

    EntryIterator FindLocked(uint32_t keyID, AeadAlgorithm algorithm) {
        return std::find_if(
            _entries.begin(),
            _entries.end(),
            [&](const Entry& entry) {
                return entry.KeyID == keyID && entry.Algorithm == algorithm;
            }
        );
    }

    ConstEntryIterator FindLocked(uint32_t keyID, AeadAlgorithm algorithm) const {
        return std::find_if(
            _entries.begin(),
            _entries.end(),
            [&](const Entry& entry) {
                return entry.KeyID == keyID && entry.Algorithm == algorithm;
            }
        );
    }

    mutable System::Synchronization::Mutex _mutex;
    EntryStorage _entries;
};

}