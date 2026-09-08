#pragma once

#include <cstdint>

#include <ESPressio_Event.hpp>
#include <ESPressio_SecurityTypes.hpp>

namespace ESPressio::Event {

/// <summary>Event emitted when the active transport-security configuration changes.</summary>
/**
 * ESPressio Memory Audit
 * Inherited Memory Total: 24 bytes [0 bytes dynamic allocation]
 * Members:
 * - Before (Security::TransportSecurityConfig): 32 bytes [0 bytes dynamic allocation]
 * - After (Security::TransportSecurityConfig): 32 bytes [0 bytes dynamic allocation]
 * Total Memory: 88 bytes [0 bytes dynamic allocation]
 * Basis: ESP32/Xtensa ILP32 reference ABI (4-byte pointers/size_t); ESPressio stateful allocators/deleters included; ABI-sensitive STL/platform internals are identified explicitly.
 * End ESPressio Memory Audit
 */
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
/**
 * ESPressio Memory Audit
 * Inherited Memory Total: 24 bytes [0 bytes dynamic allocation]
 * Members:
 * - PreviousSessionID (uint64_t): 8 bytes [0 bytes dynamic allocation]
 * Total Memory: 32 bytes [0 bytes dynamic allocation]
 * Basis: ESP32/Xtensa ILP32 reference ABI (4-byte pointers/size_t); ESPressio stateful allocators/deleters included; ABI-sensitive STL/platform internals are identified explicitly.
 * End ESPressio Memory Audit
 */
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
/**
 * ESPressio Memory Audit
 * Inherited Memory Total: 24 bytes [0 bytes dynamic allocation]
 * Members:
 * - SessionID (uint64_t): 8 bytes [0 bytes dynamic allocation]
 * Total Memory: 32 bytes [0 bytes dynamic allocation]
 * Basis: ESP32/Xtensa ILP32 reference ABI (4-byte pointers/size_t); ESPressio stateful allocators/deleters included; ABI-sensitive STL/platform internals are identified explicitly.
 * End ESPressio Memory Audit
 */
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
/**
 * ESPressio Memory Audit
 * Inherited Memory Total: 24 bytes [0 bytes dynamic allocation]
 * Members: none (standalone empty object occupies 1 byte; an eligible empty base may be optimized to 0 bytes).
 * Total Memory: 24 bytes [0 bytes dynamic allocation]
 * Basis: ESP32/Xtensa ILP32 reference ABI (4-byte pointers/size_t); ESPressio stateful allocators/deleters included; ABI-sensitive STL/platform internals are identified explicitly.
 * End ESPressio Memory Audit
 */
class TransportSecurityReplayProtectionResetEvent final
    : public TypedEvent<TransportSecurityReplayProtectionResetEvent> {};

/// <summary>Event emitted when a transport-security operation fails.</summary>
/**
 * ESPressio Memory Audit
 * Inherited Memory Total: 24 bytes [0 bytes dynamic allocation]
 * Members:
 * - Result (Security::SecurityResult): 28 bytes [Message: _value: Capacity + 1 bytes when capacity exceeds 15-byte SSO]
 * Total Memory: 52 bytes [Result: Message: _value: Capacity + 1 bytes when capacity exceeds 15-byte SSO]
 * Basis: ESP32/Xtensa ILP32 reference ABI (4-byte pointers/size_t); ESPressio stateful allocators/deleters included; ABI-sensitive STL/platform internals are identified explicitly.
 * Confidence: medium; compile-time sizeof on the concrete target remains authoritative for ABI-sensitive/opaque members.
 * End ESPressio Memory Audit
 */
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
