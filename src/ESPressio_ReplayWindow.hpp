#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ESPressio_Memory.hpp>

namespace ESPressio::Security {

/// <summary>Tracks recently accepted authenticated sequence numbers to reject replayed transport payloads.</summary>
/// <remarks>Replay-domain bookkeeping uses ESPressio System ExternalPreferred storage because authenticated sequence history is persistent metadata that does not require internal or DMA-capable RAM.</remarks>
class ReplayWindow {
public:
    /// <summary>Creates a replay window clamped to between one and 64 sequence positions.</summary>
    explicit ReplayWindow(std::size_t windowSize = 64)
        : _windowSize(std::max<std::size_t>(1, std::min<std::size_t>(64, windowSize))) {}

    /// <summary>Checks whether a sequence would be accepted without mutating replay state.</summary>
    /// <param name="senderID">Authenticated sender identity.</param>
    /// <param name="keyID">Authenticated key identifier.</param>
    /// <param name="sessionID">Authenticated non-zero session identifier.</param>
    /// <param name="sequence">Authenticated non-zero sequence number.</param>
    /// <returns><c>true</c> when the sequence is new enough and has not already been committed.</returns>
    bool WouldAccept(uint64_t senderID, uint32_t keyID, uint64_t sessionID, uint64_t sequence) const {
        if (sessionID == 0 || sequence == 0) return false;
        const State* state = Find(senderID, keyID, sessionID);
        if (state == nullptr) return true;
        if (sequence > state->Highest) return true;
        const uint64_t delta = state->Highest - sequence;
        if (delta >= _windowSize) return false;
        return (state->Bitmap & (uint64_t{1} << delta)) == 0;
    }

    /// <summary>Commits an authenticated sequence as observed for its sender/key/session replay domain.</summary>
    void Commit(uint64_t senderID, uint32_t keyID, uint64_t sessionID, uint64_t sequence) {
        State* state = FindMutable(senderID, keyID, sessionID);
        if (state == nullptr) {
            _states.push_back({senderID, keyID, sessionID, sequence, 1});
            return;
        }
        if (sequence > state->Highest) {
            const uint64_t shift = sequence - state->Highest;
            state->Bitmap = shift >= 64 ? 1 : ((state->Bitmap << shift) | 1);
            state->Highest = sequence;
            return;
        }
        const uint64_t delta = state->Highest - sequence;
        if (delta < 64) state->Bitmap |= (uint64_t{1} << delta);
    }

    /// <summary>Clears all remembered replay domains and accepted sequence history.</summary>
    void Reset() { _states.clear(); }

private:
    struct State {
        uint64_t SenderID;
        uint32_t KeyID;
        uint64_t SessionID;
        uint64_t Highest;
        uint64_t Bitmap;
    };

    std::size_t _windowSize;
    System::Memory::Vector<
        State,
        System::Memory::MemoryPolicy::ExternalPreferred
    > _states;

    const State* Find(uint64_t senderID, uint32_t keyID, uint64_t sessionID) const {
        auto found = std::find_if(_states.begin(), _states.end(), [&](const State& s) {
            return s.SenderID == senderID && s.KeyID == keyID && s.SessionID == sessionID;
        });
        return found == _states.end() ? nullptr : &*found;
    }

    State* FindMutable(uint64_t senderID, uint32_t keyID, uint64_t sessionID) {
        auto found = std::find_if(_states.begin(), _states.end(), [&](const State& s) {
            return s.SenderID == senderID && s.KeyID == keyID && s.SessionID == sessionID;
        });
        return found == _states.end() ? nullptr : &*found;
    }
};

}
