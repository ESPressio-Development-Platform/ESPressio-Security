# ESPressio Security

Transport-neutral authenticated encryption, authentication, replay protection and key abstraction for the Flowduino ESPressio Development Platform.

ESPressio Security protects **opaque transport payloads** without knowing whether they contain Events, Commands, clock synchronization messages, application packets, or another protocol. Concrete transports such as ESP-NOW, UDP, TCP and WebSockets can therefore opt into the same security layer while higher-level application protocols remain independent of cryptography.

## 0.2.0 Development Update — Observable Callback Coverage

The `feature/observable-callback-coverage` branch targets **ESPressio Security 0.2.0**. The stable-release information below remains the historical 0.1.0 documentation until 0.2.0 is released.

For 0.2.0, ESPressio Security adds a required dependency on **ESPressio Observable >= 3.0.1 and < 4.0.0** and introduces `ITransportSecurityObserver`. `TransportSecurity` now exposes synchronous observations for material configuration changes, security-session reset/establishment, replay-protection reset, and Security failures while preserving the existing `SecurityResult` return contract.

ESPressio Event remains **optional**. ESPressio Event 5.8.0 adds `TransportSecurityEventBridge`, which binds to a specific `TransportSecurity` instance and converts those observations into asynchronous Events without making Event a Security dependency. Key material is never exposed through the observer or Event surfaces.

On ESP32/Arduino, Observable's typed observer dispatch requires RTTI. PlatformIO projects consuming Security 0.2.0 must therefore enable RTTI at the **project level** because Arduino's default `-fno-rtti` applies to the application translation unit and cannot be reliably removed by a dependency's `library.json` alone:

```ini
build_flags =
    -std=gnu++17
    -frtti

build_unflags =
    -std=gnu++11
    -fno-rtti
```

Development-branch PlatformIO dependencies are therefore:

```ini
lib_deps =
    https://github.com/Flowduino/ESPressio-Security.git#feature/observable-callback-coverage
    flowduino/ESPressio-Observable@^3.0.1
```

The 0.2.0 host-test suite includes dedicated observable lifecycle coverage. See [CHANGELOG.md](CHANGELOG.md) for the complete 0.2.0 change list.

## Latest Stable Version

ESPressio Security is currently **0.1.0**.

This is the initial release of the library. For release-by-release history, see [CHANGELOG.md](CHANGELOG.md).

## Compatibility

ESPressio Security targets **C++17** and is designed primarily for the **ESP32 family under Arduino-ESP32 / ESP-IDF** as part of the ESPressio Development Platform.

The core interfaces, envelope codec, replay protection, key-provider abstractions and transport decorator are platform-neutral and host-testable. Concrete production AEAD implementations use **mbedTLS** when the corresponding headers are available in the selected platform build.

Compatibility should be verified against the exact compiler, Arduino-ESP32/ESP-IDF version and ESP32 target used by the consuming application.

## ESPressio Development Platform

The **ESPressio Development Platform** is a collection of discrete, composable component libraries developed around a common design ethos.

The principal objectives are:

- **Light-weight** — minimise memory consumption and operational overhead without sacrificing correctness.
- **Ease of Use** — provide developer-friendly, strongly typed abstractions over lower-level facilities.
- **Object-Oriented** — a type for everything, and everything in a type.
- **SOLID** — apply SRP, OCP, LSP, ISP and DIP to the maximum extent practical within C++, Arduino, FreeRTOS and microcontroller constraints.

ESPressio Security follows these principles by placing cryptographic algorithms, key retrieval, randomness, replay tracking and concrete transport adaptation behind focused interfaces.

## License

ESPressio and its component libraries are licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE) for details.

## ESPressio Library Dependencies

ESPressio Security has **no required ESPressio dependencies** in the stable 0.1.0 release. **The 0.2.0 development branch adds ESPressio Observable >= 3.0.1 and < 4.0.0 as a required dependency**, as described in the development update above.

It is intentionally foundational and transport-neutral. Concrete communication libraries should depend optionally on Security, rather than Security depending on them:

```text
ESPressio ESP-Now  - - -> ESPressio Security
ESPressio Sockets  - - -> ESPressio Security
future transports  - - -> ESPressio Security
```

Event, Command and Timing do not need to depend directly on Security merely because their messages may be transported securely. ESPressio Event 5.8.0's Security bridge remains opt-in.

See [ESPRESSIO_DEPENDENCY_CHART.md](ESPRESSIO_DEPENDENCY_CHART.md).

## Namespace

The public API resides beneath:

```cpp
ESPressio::Security
```

Principal public types include:

- `IAeadCipher` — authenticated-encryption algorithm abstraction.
- `AeadCipherRegistry` — runtime registry/resolver for AEAD implementations.
- `IKeyProvider` — key lookup/provisioning abstraction.
- `StaticKeyProvider` — simple in-memory key provider.
- `IRandomSource` — random-byte abstraction.
- `ESP32RandomSource` — ESP32 platform random source.
- `TransportSecurity` — protects and authenticates opaque protocol payloads.
- `ReplayWindow` — per-sender/per-key/per-session sliding replay detector.
- `ITransportSecurityCarrier` — minimal concrete-transport adapter contract.
- `SecureTransportDecorator` — generic secure wrapper for a carrier.
- `ITransportSecurityObserver` — 0.2.0 synchronous observer for externally meaningful Security lifecycle changes.

## PlatformIO

For the stable 0.1.0 release:

```ini
lib_deps =
    flowduino/ESPressio-Security@^0.1.0

build_flags =
    -std=gnu++17

build_unflags =
    -std=gnu++11
```

For 0.2.0 on ESP32/Arduino, add ESPressio Observable 3.x and enable RTTI at project level:

```ini
lib_deps =
    flowduino/ESPressio-Security@^0.2.0
    flowduino/ESPressio-Observable@^3.0.1

build_flags =
    -std=gnu++17
    -frtti

build_unflags =
    -std=gnu++11
    -fno-rtti
```

To deliberately consume the current repository instead of a release:

```ini
lib_deps =
    https://github.com/Flowduino/ESPressio-Security.git
```

## Why Transport-Level Security?

Security belongs between the application protocol and concrete transport:

```text
Event / Command / Clock Sync / application protocol
                       |
                       v
              Secure Transport
                       |
          authenticate + decrypt
                       |
                       v
              Concrete Transport
        ESP-NOW / UDP / TCP / WS / ...
```

Outbound processing is the reverse. This avoids implementing different cryptographic semantics independently in ESP-NOW, TCP, UDP or each higher-level ESPressio protocol.

## Security Guarantees

When `TransportSecurityPolicy::Required` is selected and a production AEAD implementation/key source is correctly configured, ESPressio Security is designed to provide:

- **Confidentiality** — payload bytes are encrypted.
- **Integrity** — modified ciphertext or authenticated metadata is rejected.
- **Authentication** — only a holder of valid key material can generate an accepted protected packet.
- **Protocol binding** — the protocol identifier is authenticated and cannot be relabelled without invalidating the packet.
- **Replay protection** — previously authenticated sequences are rejected independently per sender, key and authenticated sender session.
- **Reboot-safe sequence restart** — a sender can start its sequence again at `1` after reboot because a fresh authenticated session/epoch ID creates a new replay domain.

No plaintext is delivered to the protocol consumer until authentication/decryption succeeds.

## AEAD Algorithm Abstraction

Encryption is deliberately represented by `IAeadCipher`. `TransportSecurity` contains no AES-, CCM-, GCM- or ChaCha-specific logic.

Algorithms are resolved through `AeadCipherRegistry`, allowing new implementations without changing the transport-security processor and allowing receivers to support multiple algorithms concurrently during migration.

## Included AEAD Implementations

When supported by the platform's mbedTLS build, Security provides:

| Algorithm | Key | Nonce | Tag | Class |
| --- | ---: | ---: | ---: | --- |
| AES-128-GCM | 128-bit | 96-bit | 128-bit | `AES128GCMCipher` |
| AES-256-GCM | 256-bit | 96-bit | 128-bit | `AES256GCMCipher` |
| AES-128-CCM | 128-bit | 96-bit | 128-bit | `AES128CCMCipher` |
| AES-256-CCM | 256-bit | 96-bit | 128-bit | `AES256CCMCipher` |
| ChaCha20-Poly1305 | 256-bit | 96-bit | 128-bit | `ChaCha20Poly1305Cipher` |

Availability macros are exposed as `ESPRESSIO_SECURITY_HAS_MBEDTLS_GCM`, `ESPRESSIO_SECURITY_HAS_MBEDTLS_CCM` and `ESPRESSIO_SECURITY_HAS_MBEDTLS_CHACHAPOLY`.

The default outbound algorithm is **AES-256-GCM**. Algorithm choice remains an application/security-policy decision; the library does not silently substitute one production algorithm for another.

## Security Envelope

Protected packets use a versioned transport-neutral envelope. Version 1 authenticates:

```text
magic
version
algorithm
flags
protocol ID
key ID
sender ID
session / epoch ID
sequence
nonce length
tag length
ciphertext length
```

The fixed header is AEAD associated authenticated data. A valid encrypted Event packet therefore cannot be relabelled as a Command packet, assigned to another sender session, or have its sequence changed without authentication failure. The envelope carries **key IDs, never keys**.

## Security Policies

`TransportSecurityPolicy` provides three explicit modes:

- `Disabled` — outbound data remains plaintext and plaintext inbound data is accepted.
- `Preferred` — security is used when the requested cipher/key is available; plaintext is accepted and outbound payloads may fall back to plaintext. This is a migration/interoperability mode.
- `Required` — protected outbound transmission fails if encryption cannot be performed, and plaintext inbound packets are rejected.

`Required` is the recommended policy whenever security is an actual requirement.

## Key Providers and Rotation

Key retrieval is abstracted through `IKeyProvider`. The initial library includes `StaticKeyProvider` for simple applications/tests.

Multiple key IDs can coexist, allowing receivers to accept an old and new key during rotation while transmitters move to a new `OutboundKeyID`.

Production systems are encouraged to implement `IKeyProvider` using an appropriate secure provisioning/storage strategy rather than hard-coding secrets into source code. `StaticKeyProvider` performs best-effort in-memory erasure on removal/destruction but cannot guarantee that no historical compiler/platform copy exists elsewhere in memory.

## Randomness, Nonces and Session IDs

`IRandomSource` abstracts cryptographic randomness. On ESP32, use `ESP32RandomSource`, which uses the ESP platform random facility.

`StandardRandomSource` exists for portable/host use. `std::random_device` quality is implementation-dependent and should not be assumed to provide production embedded cryptographic entropy on every platform.

Each protected packet carries a nonce explicitly. AEAD nonce uniqueness for a given key remains security-critical.

`TransportSecurityConfig::SessionID` defaults to zero. On the first protected transmission, `TransportSecurity` then generates a fresh non-zero 64-bit session ID from `IRandomSource`. The generated value remains stable for that `TransportSecurity` session and is exposed through `GetSessionID()` for diagnostics/identity correlation.

Applications that manage epochs externally may supply a non-zero `SessionID` explicitly. Calling `SetConfig()` resets the outbound sequence and replay state; a zero `SessionID` causes a new automatic session to be generated on the next protected send.

## Replay Protection

Each authenticated envelope contains a non-zero 64-bit session ID and sequence number. `ReplayWindow` tracks sequences independently by:

```text
sender ID + key ID + session ID
```

A sliding window permits limited legitimate reordering while rejecting duplicates and stale packets within that session. Replay state is committed **only after successful AEAD authentication and protocol validation**, so forged packets cannot poison replay state.

This permits a sender to reboot, generate a new authenticated session ID, reset its sequence to `1`, and remain acceptable to receivers that have already seen much larger sequence numbers from its previous session.

`ResetReplayProtection()` remains available for explicit administrative/session-boundary use.

## Observable Security Lifecycle (0.2.0)

`TransportSecurity` can be observed directly:

```cpp
#include <ESPressio_Security.hpp>

class SecurityObserver final :
    public ESPressio::Security::ITransportSecurityObserver {
public:
    void OnTransportSecuritySessionEstablished(uint64_t sessionID) override {
        // Record or display the authenticated session identity.
    }

    void OnTransportSecurityFailure(
        const ESPressio::Security::SecurityResult& result
    ) override {
        // Diagnostics/metrics only; ordinary return-value handling remains authoritative.
    }
};

SecurityObserver observer;
auto handle = security.RegisterObserver(&observer);
```

Available observations are:

- configuration changed;
- security session reset;
- security session established;
- replay protection reset;
- security failure.

The observation layer is intentionally passive. It does not replace the ordinary `Protect()` / `Unprotect()` result model and it never exposes key material.

## Optional ESPressio Event Bridge (0.2.0)

ESPressio Event **5.8.0+** provides the opt-in bridge:

```cpp
#include <ESPressio_TransportSecurityEventBridge.hpp>

ESPressio::Event::TransportSecurityEventBridge bridge(security);
```

This converts Security observations to asynchronous ESPressio Events while keeping the dependency direction correct: Security depends only on Observable; Event optionally adapts Security.

## Generic Transport Decoration

`SecureTransportDecorator` can wrap any `ITransportSecurityCarrier`:

```cpp
SecureTransportDecorator secure(carrier, security);
secure.Send(protocolID, payload);
```

Inbound carrier packets are authenticated/decrypted before the registered receive callback is invoked. Authentication failure, replay rejection or protocol mismatch therefore prevents plaintext delivery.

Concrete transport libraries may alternatively integrate `TransportSecurity` directly where their callback/threading model makes that more natural.

## Concurrency Model

The initial `TransportSecurity` implementation protects mutable outbound sequence/replay state and configuration transitions with a lightweight internal mutex when `<mutex>` is available.

For embedded integrations, applications should nevertheless prefer a single well-defined security ownership/execution context per security instance where practical. This keeps transport callback behavior deterministic and avoids avoidable contention.

## Testing

Host tests cover:

- envelope encode/decode;
- AES-GCM protect/unprotect where available;
- protocol binding;
- replay rejection;
- sender-session scoped replay behavior;
- automatic outbound session generation;
- tamper rejection;
- key rotation;
- policy behavior;
- transport decoration;
- Observable lifecycle notifications and observer-handle lifetime;
- compile coverage for the mbedTLS wrapper interfaces.

ESP32 CI additionally builds the production examples with the documented project-level RTTI configuration required by Observable's typed observer dispatch.

## Operational Notes

- Prefer `TransportSecurityPolicy::Required` where secure transport is actually required.
- Avoid hard-coding production keys into firmware source.
- Treat authenticated sender/session metadata as identity input, not as authorization policy by itself.
- Use a secure provisioning/storage strategy appropriate to the deployment.
- Keep production mbedTLS/Arduino-ESP32/ESP-IDF versions under update and vulnerability-management processes.
- Treat `Preferred` as a migration mode, not equivalent security to `Required`.
- Keep replay windows sized for the expected amount of legitimate packet reordering.
- Ensure ESP32/Arduino PlatformIO builds enable RTTI (`-frtti` and removal of `-fno-rtti`) when using Observable-backed Security 0.2.x.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
