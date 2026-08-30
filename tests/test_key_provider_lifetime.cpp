#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <thread>

#include "ESPressio_StaticKeyProvider.hpp"

using namespace ESPressio::Security;

int main() {
    StaticKeyProvider keys;

    const std::array<uint8_t, 32> first = [] {
        std::array<uint8_t, 32> value{};
        value.fill(0x11);
        return value;
    }();
    const std::array<uint8_t, 32> second = [] {
        std::array<uint8_t, 32> value{};
        value.fill(0x22);
        return value;
    }();

    assert(keys.Add(1, AeadAlgorithm::AES256GCM, first));

    KeyMaterialView firstView;
    assert(keys.GetKey(1, AeadAlgorithm::AES256GCM, firstView));
    assert(firstView.Size == first.size());
    assert(firstView.Storage);
    for (std::size_t index = 0; index < firstView.Size; ++index) {
        assert(firstView.Data[index] == 0x11);
    }

    // Replacing an entry must not invalidate a view already handed to an
    // in-flight cryptographic operation.
    assert(keys.Add(1, AeadAlgorithm::AES256GCM, second));
    for (std::size_t index = 0; index < firstView.Size; ++index) {
        assert(firstView.Data[index] == 0x11);
    }

    KeyMaterialView secondView;
    assert(keys.GetKey(1, AeadAlgorithm::AES256GCM, secondView));
    assert(secondView.Size == second.size());
    for (std::size_t index = 0; index < secondView.Size; ++index) {
        assert(secondView.Data[index] == 0x22);
    }

    // Removal detaches future lookup but active views continue pinning their
    // immutable backing storage until the operation releases them.
    assert(keys.Remove(1, AeadAlgorithm::AES256GCM));
    KeyMaterialView missing;
    assert(!keys.GetKey(1, AeadAlgorithm::AES256GCM, missing));
    for (std::size_t index = 0; index < firstView.Size; ++index) {
        assert(firstView.Data[index] == 0x11);
        assert(secondView.Data[index] == 0x22);
    }

    // Stress concurrent rotation and lookup. Every returned view must expose
    // one complete immutable key generation rather than torn/reallocated data.
    std::atomic<bool> running{true};
    std::atomic<uint32_t> reads{0};
    std::thread reader([&] {
        while (running.load(std::memory_order_acquire)) {
            KeyMaterialView view;
            if (!keys.GetKey(7, AeadAlgorithm::AES256GCM, view)) {
                std::this_thread::yield();
                continue;
            }
            assert(view.Size == 32);
            assert(view.Data != nullptr);
            const uint8_t expected = view.Data[0];
            for (std::size_t index = 1; index < view.Size; ++index) {
                assert(view.Data[index] == expected);
            }
            reads.fetch_add(1, std::memory_order_relaxed);
        }
    });

    for (uint32_t generation = 1; generation <= 5000; ++generation) {
        std::array<uint8_t, 32> value{};
        value.fill(static_cast<uint8_t>((generation % 251U) + 1U));
        assert(keys.Add(7, AeadAlgorithm::AES256GCM, value));
        if ((generation % 17U) == 0U) {
            assert(keys.Remove(7, AeadAlgorithm::AES256GCM));
        }
    }

    running.store(false, std::memory_order_release);
    reader.join();
    assert(reads.load(std::memory_order_relaxed) > 0);

    keys.Clear();
    return 0;
}
