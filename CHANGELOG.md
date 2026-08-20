# Changelog

All notable changes to ESPressio Security are documented in this file.

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
