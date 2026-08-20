#pragma once

#include <algorithm>
#include <cstdint>
#include <vector>
#include "ESPressio_IKeyProvider.hpp"

namespace ESPressio::Security {

class StaticKeyProvider final : public IKeyProvider {
public:
    struct Entry { uint32_t KeyID = 0; AeadAlgorithm Algorithm = AeadAlgorithm::Unknown; std::vector<uint8_t> Bytes; };
    ~StaticKeyProvider() override { Clear(); }

    bool Add(uint32_t keyID, AeadAlgorithm algorithm, const uint8_t* key, std::size_t size) {
        if (keyID == 0 || key == nullptr || size == 0) return false;
        Remove(keyID, algorithm);
        Entry entry; entry.KeyID = keyID; entry.Algorithm = algorithm; entry.Bytes.assign(key, key + size);
        _entries.push_back(std::move(entry)); return true;
    }

    bool Remove(uint32_t keyID, AeadAlgorithm algorithm) {
        auto found = std::find_if(_entries.begin(), _entries.end(), [&](const Entry& e) { return e.KeyID == keyID && e.Algorithm == algorithm; });
        if (found == _entries.end()) return false;
        SecureErase(found->Bytes); _entries.erase(found); return true;
    }

    void Clear() { for (auto& entry : _entries) SecureErase(entry.Bytes); _entries.clear(); }

    bool GetKey(uint32_t keyID, AeadAlgorithm algorithm, KeyMaterial& key) const override {
        auto found = std::find_if(_entries.begin(), _entries.end(), [&](const Entry& e) { return e.KeyID == keyID && e.Algorithm == algorithm; });
        if (found == _entries.end()) return false;
        key.KeyID = found->KeyID; key.Bytes = found->Bytes; return true;
    }

    static void SecureErase(std::vector<uint8_t>& bytes) noexcept {
        volatile uint8_t* p = bytes.empty() ? nullptr : bytes.data();
        for (std::size_t i = 0; p != nullptr && i < bytes.size(); ++i) p[i] = 0;
        bytes.clear();
    }

private:
    std::vector<Entry> _entries;
};

}
