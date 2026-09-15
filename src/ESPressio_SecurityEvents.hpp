#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include <ESPressio_Event.hpp>
#include <ESPressio_SecurityTypes.hpp>

namespace ESPressio::Event {

namespace SecurityEventTypeIds {
inline constexpr EventTypeId TransportConfigurationChanged{0x4553534500000001ULL};
inline constexpr EventTypeId TransportSessionReset{0x4553534500000002ULL};
inline constexpr EventTypeId TransportSessionEstablished{0x4553534500000003ULL};
inline constexpr EventTypeId TransportReplayProtectionReset{0x4553534500000004ULL};
inline constexpr EventTypeId TransportFailure{0x4553534500000005ULL};
} // namespace SecurityEventTypeIds

/// Bounded optional diagnostic occurrence emitted after the active
/// transport-security configuration changes.
struct TransportSecurityConfigurationChangedEvent final
    : Event<TransportSecurityConfigurationChangedEvent> {
    static constexpr EventTypeId TypeId = SecurityEventTypeIds::TransportConfigurationChanged;
    static constexpr std::string_view CanonicalName =
        "espressio.security.transport-configuration-changed";
    static constexpr std::size_t MaximumLiveInstances = 4U;
    static constexpr std::size_t MaximumPendingInstances = 1U;

    Security::TransportSecurityConfig Before;
    Security::TransportSecurityConfig After;

    TransportSecurityConfigurationChangedEvent(
        const Security::TransportSecurityConfig& before,
        const Security::TransportSecurityConfig& after)
        : Before(before), After(after) {}
};

/// Bounded optional diagnostic occurrence emitted when transport-security
/// sequence/session state is reset.
struct TransportSecuritySessionResetEvent final
    : Event<TransportSecuritySessionResetEvent> {
    static constexpr EventTypeId TypeId = SecurityEventTypeIds::TransportSessionReset;
    static constexpr std::string_view CanonicalName =
        "espressio.security.transport-session-reset";
    static constexpr std::size_t MaximumLiveInstances = 4U;
    static constexpr std::size_t MaximumPendingInstances = 1U;

    std::uint64_t PreviousSessionID{};

    explicit TransportSecuritySessionResetEvent(std::uint64_t previousSessionID) noexcept
        : PreviousSessionID(previousSessionID) {}
};

/// Bounded optional diagnostic occurrence emitted when a transport-security
/// session becomes established.
struct TransportSecuritySessionEstablishedEvent final
    : Event<TransportSecuritySessionEstablishedEvent> {
    static constexpr EventTypeId TypeId = SecurityEventTypeIds::TransportSessionEstablished;
    static constexpr std::string_view CanonicalName =
        "espressio.security.transport-session-established";
    static constexpr std::size_t MaximumLiveInstances = 4U;
    static constexpr std::size_t MaximumPendingInstances = 1U;

    std::uint64_t SessionID{};

    explicit TransportSecuritySessionEstablishedEvent(std::uint64_t sessionID) noexcept
        : SessionID(sessionID) {}
};

/// Bounded optional diagnostic occurrence emitted when inbound replay-protection
/// state is reset.
struct TransportSecurityReplayProtectionResetEvent final
    : Event<TransportSecurityReplayProtectionResetEvent> {
    static constexpr EventTypeId TypeId = SecurityEventTypeIds::TransportReplayProtectionReset;
    static constexpr std::string_view CanonicalName =
        "espressio.security.transport-replay-protection-reset";
    static constexpr std::size_t MaximumLiveInstances = 4U;
    static constexpr std::size_t MaximumPendingInstances = 1U;
};

/// Bounded optional diagnostic occurrence emitted when a transport-security
/// operation reports a failure.
struct TransportSecurityFailureEvent final
    : Event<TransportSecurityFailureEvent> {
    static constexpr EventTypeId TypeId = SecurityEventTypeIds::TransportFailure;
    static constexpr std::string_view CanonicalName =
        "espressio.security.transport-failure";
    static constexpr std::size_t MaximumLiveInstances = 4U;
    static constexpr std::size_t MaximumPendingInstances = 1U;

    Security::SecurityResult Result;

    explicit TransportSecurityFailureEvent(const Security::SecurityResult& result)
        : Result(result) {}
};

} // namespace ESPressio::Event
