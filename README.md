# ESPressio Security

Transport-neutral authenticated encryption, authentication, replay protection and security lifecycle observation for the Flowduino ESPressio Development Platform.

ESPressio Security protects **opaque transport payloads** without knowing whether they contain Events, Commands, clock synchronization messages, application packets, or another protocol. Concrete transports such as ESP-NOW, UDP, TCP and WebSockets can therefore opt into the same security layer while higher-level application protocols remain independent of cryptography.

## Current Development Version

This branch targets **ESPressio Security 0.2.0**.

0.2.0 adds native ESPressio Observable coverage for externally meaningful transport-security state while preserving the existing protection/unprotection result API.

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Design goals

- Transport-neutral authenticated encryption.
- Runtime-selectable AEAD implementations.
- Explicit key-provider abstraction.
- Session-aware replay protection.
- No dependency on Event, ESP-NOW, Sockets or Command.
- Observable security lifecycle without replacing ordinary return-value/error handling.
- Event conversion remains optional and belongs to ESPressio Event.

## ESPressio dependencies

Security 0.2.0 requires:

- **ESPressio Observable >= 3.0.1 and < 4.0.0**.

Security does **not** require ESPressio Event. Applications that want asynchronous Event representations of Security observations may opt into **ESPressio Event 5.8.0+** and include `ESPressio_TransportSecurityEventBridge.hpp` from that library.

The dependency direction is therefore:

```text
ESPressio Observable
        |
        v
ESPressio Security

ESPressio Security ---- optional observer source ----> ESPressio Event bridge
```

See [ESPRESSIO_DEPENDENCY_CHART.md](ESPRESSIO_DEPENDENCY_CHART.md) for the repository-level dependency view.

## PlatformIO

```ini
lib_deps =
    flowduino/ESPressio-Security@^0.2.0
    flowduino/ESPressio-Observable@^3.0.1
```

When deliberately consuming this feature branch before the release is tagged:

```ini
lib_deps =
    https://github.com/Flowduino/ESPressio-Security.git#feature/observable-callback-coverage
    flowduino/ESPressio-Observable@^3.0.1
```

## Core API

The main umbrella is:

```cpp
#include <ESPressio_Security.hpp>
```

Principal types include:

- `TransportSecurity` — protects and authenticates transport payloads and performs inbound authentication/decryption.
- `TransportSecurityConfig` — policy, outbound algorithm/key, sender/session identity, payload limits and replay-window configuration.
- `SecurityResult` — success/failure result with `SecurityError` and diagnostic text.
- `IAeadCipher` / `AeadCipherRegistry` — pluggable AEAD algorithm abstraction and registry.
- `IKeyProvider` / `StaticKeyProvider` — key retrieval abstraction and simple in-memory provider.
- `IRandomSource` — cryptographic-randomness abstraction.
- `ReplayWindow` — session-scoped replay protection.
- `ITransportSecurityCarrier` / `SecureTransportDecorator` — generic transport decoration without coupling Security to a concrete carrier.
- `ITransportSecurityObserver` — synchronous lifecycle observer introduced in 0.2.0.

## Security policies

`TransportSecurityPolicy` provides three modes:

- `Disabled` — payloads pass without ESPressio Security protection.
- `Preferred` — protection is used when the configured algorithm/key is available, otherwise plaintext may be accepted/sent according to the existing contract.
- `Required` — protected transport payloads are required and plaintext inbound payloads are rejected.

Applications should choose policy according to their threat model. Transport-layer security such as TLS and ESPressio Security can also be used together where defence in depth is appropriate.

## Sessions and replay protection

Protected envelopes authenticate sender identity, session/epoch identity, sequence number, key identity, algorithm and application protocol.

A non-zero `SessionID` can be configured explicitly. When it is zero, `TransportSecurity` generates a fresh non-zero session ID from the configured `IRandomSource` when protection first requires one. Replay windows are scoped by sender, key and session, allowing a sender to restart its sequence safely after establishing a new authenticated session epoch.

`ResetReplayProtection()` clears the current inbound replay state without changing the public protection API.

## Observable security lifecycle

`TransportSecurity` can now be observed directly:

```cpp
class SecurityObserver final :
    public ESPressio::Security::ITransportSecurityObserver {
public:
    void OnTransportSecuritySessionEstablished(uint64_t sessionID) override {
        // React to the new authenticated sender session.
    }

    void OnTransportSecurityFailure(
        const ESPressio::Security::SecurityResult& result
    ) override {
        // Diagnostics, metrics, audit integration, etc.
    }
};

SecurityObserver observer;
auto observerHandle = security.RegisterObserver(&observer);
```

The observer surface covers:

- material configuration changes;
- session reset;
- session establishment;
- replay-protection reset; and
- security failures, including authentication/replay/protocol/key/algorithm/envelope failures reported by the normal Security API.

Observer notifications are supplementary. Existing `SecurityResult` return semantics remain authoritative and unchanged.

Observer exceptions are isolated from cryptographic state transitions so diagnostic consumers cannot interrupt protection or replay-state handling.

## Optional Event bridge

When ESPressio Event 5.8.0 or newer is selected, Security observations can be converted into asynchronous Events without adding Event as a Security dependency:

```cpp
#include <ESPressio_TransportSecurityEventBridge.hpp>

ESPressio::Event::TransportSecurityEventBridge bridge;
bridge.Initialize(security);
```

The bridge emits corresponding Security lifecycle Events for configuration changes, session changes, replay reset and failure notifications.

## Key handling

`IKeyProvider` deliberately keeps key ownership outside `TransportSecurity`. `StaticKeyProvider` is suitable for straightforward provisioned-key scenarios and performs best-effort erasure of replaced key material. More advanced applications can implement key providers backed by secure storage, provisioning services or hardware-specific facilities.

Key material is never exposed through observer callbacks or Event bridges.

## Algorithms

The library provides mbedTLS-backed implementations where the selected platform exposes the required APIs, including:

- AES-128-GCM;
- AES-256-GCM;
- AES-128-CCM;
- AES-256-CCM; and
- ChaCha20-Poly1305 when supported by the platform build.

Algorithm availability is represented through the registry rather than hard-coding a single cipher into the transport layer.

## Testing

The host suite covers the existing Security contracts plus the 0.2.0 observer lifecycle, including configuration/session transitions, replay reset, failure publication and observer-registration lifetime. ESP32 examples continue to compile through PlatformIO CI.

## Compatibility

ESPressio Security targets C++17 and is designed for the ESP32/Arduino-ESP32 ecosystem while retaining host-testable transport-neutral core components.

0.2.0 is a backward-compatible extension of 0.1.0 at the Security API level. Existing applications that do not register observers continue to use `TransportSecurity` in the same way; the only new core ESPressio dependency is Observable 3.x.

## License

Apache License 2.0. See [LICENSE](LICENSE).
