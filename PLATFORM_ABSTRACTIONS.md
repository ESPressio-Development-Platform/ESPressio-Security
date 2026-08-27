# Platform Abstractions Audit Trail

This file records Security changes made during the platform-abstraction tranche tracked by issue #25.

## 2026-08-27

### Entropy
- Removed direct use of the ESP32 `esp_fill_random` API from ESPressio-Security.
- Added `SystemEntropyRandomSource`, adapting the installed `ESPressio::System::Entropy::IEntropySource` to Security's existing `IRandomSource` contract.
- Security refuses an installed entropy source that does not declare itself cryptographically suitable.
- Retained `ESP32RandomSource` as a source-compatible alias to `SystemEntropyRandomSource` during the migration.

## Boundary rule

Security continues to own cryptographic algorithms, nonce generation policy, key providers, replay protection and transport/data-protection semantics. Hardware entropy generation belongs to ESPressio-System and its concrete platform provider.
