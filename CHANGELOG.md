# Changelog

## [0.4.0] - 2026-08-23

### Added

- Added `IDataProtector` as the generic authenticated data-at-rest protection contract.
- Added `DataProtector`, a transport-independent AEAD implementation built on the existing cipher registry, key-provider and random-source abstractions.
- Added `DataProtectionConfig` for algorithm, key ID and maximum-plaintext policy.
- Added `DataProtectionContext` so callers can bind protected bytes to an authenticated purpose/context without storing that context in plaintext.
- Added a versioned `ESDP` protected-data envelope carrying algorithm/key identity, nonce, authentication tag and ciphertext while never carrying key material.
- Added byte and string convenience APIs.
- Added `std::array` convenience support to `StaticKeyProvider` for compile-time/static key material.
- Added host tests covering round trips, context binding, tamper rejection, malformed envelopes and payload limits.

### Changed

- Updated the normal Security umbrella to expose the generic data-protection API alongside transport security.
- Updated package metadata and documentation for the 0.4.0 feature generation.

### Compatibility

- Backward-compatible interface extension; existing TransportSecurity APIs and wire format are unchanged.
- `IDataProtector` is intentionally independent of transport sessions, protocol IDs, replay windows and sequence counters.

### Tracking

- Implements #17.

## 0.3.1 — 2026-08-22

### Changed
- Published the post-migration ESPressio Security package generation from `ESPressio-Development-Platform`.
- Raised required ESPressio Observable to `>=3.0.2 <4.0.0`.
- Raised optional ESPressio Event integration to `>=6.0.1 <7.0.0`.
- Updated package metadata, README dependency/install guidance, CI validation, and dependency documentation.

### Compatibility
- No Security public API or runtime behaviour changes are introduced by this repository-relocation patch release.

All notable changes to ESPressio Security are documented in this file.

## [0.3.0] - 2026-08-21

### Added

- Moved Security lifecycle Event types and `TransportSecurityEventBridge` ownership into ESPressio Security.
- Added an opt-in Security -> Event integration targeting ESPressio Event 6.0.0 while keeping the normal Security core independent of Event.

### Changed

- Preserved the existing `ESPressio_SecurityEvents.hpp` and `ESPressio_TransportSecurityEventBridge.hpp` public names in their new owning package.
- Updated package metadata, documentation, dependency charts, and CI for the 0.3.0 architecture.
- The normal Security umbrella remains Event-free; Event is required only when the Event bridge headers are selected.

### Compatibility

- Core Security, encryption, replay-protection, and Observer APIs are unchanged.
- Applications using the Event bridge must obtain the bridge headers from ESPressio Security 0.3.0 rather than ESPressio Event 6.0.0.

### Tracking

- Implements #5.
- Coordinated with ESPressio-Development-Platform/ESPressio-Event#36.

## [0.2.0] - 2026-08-20

### Added

- Added `ITransportSecurityObserver` for externally meaningful transport-security lifecycle notifications.
- Added observable notifications for configuration changes, security-session reset/establishment, replay-protection reset, and security failures.
- Added ESPressio Observable as the foundational observer dependency.
- Added optional ESPressio Event bridge support through ESPressio Event 5.8.0.

### Changed

- Security failure paths now publish observer notifications without changing existing return-value semantics.

## [0.1.0] - 2026-08-20

### Added

- Initial ESPressio Security release.
- Transport-neutral authenticated-encryption envelope for opaque protocol payloads.
- `IAeadCipher` abstraction and `AeadCipherRegistry` for runtime-selectable cryptographic algorithms.
- mbedTLS-backed AES-128-GCM and AES-256-GCM implementations.
- mbedTLS-backed AES-128-CCM and AES-256-CCM implementations.
- mbedTLS-backed ChaCha20-Poly1305 implementation when available in the selected platform build.
- `IKeyProvider` abstraction and in-memory `StaticKeyProvider` with best-effort key erasure.
- `IRandomSource`, portable `StandardRandomSource`, and ESP32 `ESP32RandomSource` implementations.
- `Disabled`, `Preferred`, and `Required` transport security policies.
- Authenticated protocol, algorithm, key, sender, session/epoch, and sequence metadata.
- Automatically generated non-zero sender session IDs, with optional explicit session identity for externally managed deployments.
- Per-sender/per-key/per-session sliding replay protection so sequence numbers can restart safely after a sender reboot while duplicates remain rejected within each session.
- `ITransportSecurityCarrier` and `SecureTransportDecorator` for concrete transport integrations without Security depending on ESP-NOW, Sockets, Event or Command.
- Host-side CMake/CTest coverage for encryption/decryption contracts, authentication failure, protocol/session tampering, replay behavior, sender reboot/session rollover, key rotation, policy behavior, malformed envelopes, payload limits and decorator flow.
- Production-cipher contract tests covering all included mbedTLS-backed cipher classes through API-compatible host stubs.
- ESP32 mbedTLS examples and CI compile validation.
