#pragma once

#include <cstdint>

#include <ESPressio_Event.hpp>
#include <ESPressio_SecurityTypes.hpp>

namespace ESPressio::Event {

/// <summary>Event emitted when the active transport-security configuration changes.</summary>
class TransportSecurityConfigurationChangedEvent final
    : public TypedEvent<TransportSecurityConfigurationChangedEvent> {
public:
    /// <summary>Configuration active before the change.</summary>
    const Security::TransportSecurityConfig Before;
    /// <summary>Configuration active after the change.</summary>
    const Security::TransportSecurityConfig After;
    /// <summary>Creates a configuration-change event from the previous and current settings.</summary>
    TransportSecurityConfigurationChangedEvent(
        const Security::TransportSecurityConfig& before,
        const Security::TransportSecurityConfig& after
    ) : Before(before), After(after) {}
};

/// <summary>Event emitted when transport-security session state is reset.</summary>
class TransportSecuritySessionResetEvent final
    : public TypedEvent<TransportSecuritySessionResetEvent> {
public:
    /// <summary>Session identifier that was active before the reset.</summary>
    const uint64_t PreviousSessionID;
    /// <summary>Creates a session-reset event.</summary>
    explicit TransportSecuritySessionResetEvent(uint64_t previousSessionID)
        : PreviousSessionID(previousSessionID) {}
};

/// <summary>Event emitted when a transport-security session becomes established.</summary>
class TransportSecuritySessionEstablishedEvent final
    : public TypedEvent<TransportSecuritySessionEstablishedEvent> {
public:
    /// <summary>Established session identifier.</summary>
    const uint64_t SessionID;
    /// <summary>Creates a session-established event.</summary>
    explicit TransportSecuritySessionEstablishedEvent(uint64_t sessionID)
        : SessionID(sessionID) {}
};

/// <summary>Event emitted when transport replay-protection state is reset.</summary>
class TransportSecurityReplayProtectionResetEvent final
    : public TypedEvent<TransportSecurityReplayProtectionResetEvent> {};

/// <summary>Event emitted when a transport-security operation fails.</summary>
class TransportSecurityFailureEvent final
    : public TypedEvent<TransportSecurityFailureEvent> {
public:
    /// <summary>Security operation result describing the failure.</summary>
    const Security::SecurityResult Result;
    /// <summary>Creates a transport-security failure event.</summary>
    explicit TransportSecurityFailureEvent(const Security::SecurityResult& result)
        : Result(result) {}
};

} // namespace ESPressio::Event
