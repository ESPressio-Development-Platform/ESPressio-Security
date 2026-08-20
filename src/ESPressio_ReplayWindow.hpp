#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace ESPressio::Security {

class ReplayWindow {
public:
    explicit ReplayWindow(std::size_t windowSize = 64)
        : _windowSize(std::max<std::size_t>(1, std::min<std::size_t>(64, windowSize))) {}

    bool WouldAccept(uint64_t senderID, uint32_t keyID, uint64_t sequence) const {
        if (sequence == 0) return false;
        const State* state = Find(senderID, keyID);
        if (state == nullptr) return true;
        if (sequence > state->Highest) return true;
        const uint64_t delta = state->Highest - sequence;
        if (delta >= _windowSize) return false;
        return (state->Bitmap & (uint64_t{1} << delta)) == 0;
    }

    void Commit(uint64_t senderID, uint32_t keyID, uint64_t sequence) {
        State* state = FindMutable(senderID, keyID);
        if (state == nullptr) { _states.push_back({senderID, keyID, sequence, 1}); return; }
        if (sequence > state->Highest) {
            const uint64_t shift = sequence - state->Highest;
            state->Bitmap = shift >= 64 ? 1 : ((state->Bitmap << shift) | 1);
            state->Highest = sequence;
            return;
        }
        const uint64_t delta = state->Highest - sequence;
        if (delta < 64) state->Bitmap |= (uint64_t{1} << delta);
    }

    void Reset() { _states.clear(); }

private:
    struct State { uint64_t SenderID; uint32_t KeyID; uint64_t Highest; uint64_t Bitmap; };
    std::size_t _windowSize;
    std::vector<State> _states;

    const State* Find(uint64_t senderID, uint32_t keyID) const {
        auto found = std::find_if(_states.begin(), _states.end(), [&](const State& s) { return s.SenderID == senderID && s.KeyID == keyID; });
        return found == _states.end() ? nullptr : &*found;
    }

    State* FindMutable(uint64_t senderID, uint32_t keyID) {
        auto found = std::find_if(_states.begin(), _states.end(), [&](const State& s) { return s.SenderID == senderID && s.KeyID == keyID; });
        return found == _states.end() ? nullptr : &*found;
    }
};

}
