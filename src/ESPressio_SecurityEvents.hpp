#pragma once

#include <cstdint>

#include <ESPressio_Event.hpp>
#include <ESPressio_SecurityTypes.hpp>

namespace ESPressio::Event {

class TransportSecurityConfigurationChangedEvent final
    : public TypedEvent<TransportSecurityConfigurationChangedEvent> {
public:
    const Security::TransportSecurityConfig Before;
    const Security::TransportSecurityConfig After;
    TransportSecurityConfigurationChangedEvent(
        const Security::TransportSecurityConfig& before,
        const Security::TransportSecurityConfig& after
    ) : Before(before), After(after) {}
};

class TransportSecuritySessionResetEvent final
    : public TypedEvent<TransportSecuritySessionResetEvent> {
public:
    const uint64_t PreviousSessionID;
    explicit TransportSecuritySessionResetEvent(uint64_t previousSessionID)
        : PreviousSessionID(previousSessionID) {}
};

class TransportSecuritySessionEstablishedEvent final
    : public TypedEvent<TransportSecuritySessionEstablishedEvent> {
public:
    const uint64_t SessionID;
    explicit TransportSecuritySessionEstablishedEvent(uint64_t sessionID)
        : SessionID(sessionID) {}
};

class TransportSecurityReplayProtectionResetEvent final
    : public TypedEvent<TransportSecurityReplayProtectionResetEvent> {};

class TransportSecurityFailureEvent final
    : public TypedEvent<TransportSecurityFailureEvent> {
public:
    const Security::SecurityResult Result;
    explicit TransportSecurityFailureEvent(const Security::SecurityResult& result)
        : Result(result) {}
};

} // namespace ESPressio::Event
