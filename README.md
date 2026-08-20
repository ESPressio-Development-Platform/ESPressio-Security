# ESPressio Security

Transport-neutral authenticated encryption, authentication, replay protection and key abstraction for the Flowduino ESPressio Development Platform.

ESPressio Security protects **opaque transport payloads** without knowing whether they contain Events, Commands, clock synchronization messages, application packets, or another protocol. Concrete transports such as ESP-NOW, UDP, TCP and WebSockets can therefore opt into the same security layer while higher-level application protocols remain independent of cryptography.

## 0.2.0 Development Update — Observable Callback Coverage

The `feature/observable-callback-coverage` branch targets **ESPressio Security 0.2.0**. The stable-release information below remains the historical 0.1.0 documentation until 0.2.0 is released.

For 0.2.0, ESPressio Security adds a required dependency on **ESPressio Observable >= 3.0.1 and < 4.0.0** and introduces `ITransportSecurityObserver`. `TransportSecurity` now exposes synchronous observations for material configuration changes, security-session reset/establishment, replay-protection reset, and Security failures while preserving the existing `SecurityResult` return contract.

ESPressio Event remains **optional**. ESPressio Event 5.8.0 adds `TransportSecurityEventBridge`, which binds to a specific `TransportSecurity` instance and converts those observations into asynchronous Events without making Event a Security dependency. Key material is never exposed through the observer or Event surfaces.

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

For the 0.2.0 release generation, add ESPressio Observable 3.x as shown in the development update above.

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

A sliding window permits limited legitimate reordering while rejecting duplicates and stale packets within that session. Replay state is committed **only after successful AEAD authentication and protocol validation**, preventing unauthenticated forged high sequence numbers from advancing receiver state.

This solves the sender-reboot case cleanly:

```text
boot A: sender X / session A / sequence 1, 2, 3 ...
boot B: sender X / session B / sequence 1, 2, 3 ...
```

The restarted sequence is accepted because session B is a distinct authenticated replay domain; replaying either session's already-seen packets is still rejected.

## Observable Security Lifecycle (0.2.0)

`TransportSecurity` now accepts `ITransportSecurityObserver` registrations:

```cpp
class SecurityObserver final :
    public ESPressio::Security::ITransportSecurityObserver {
public:
    void OnTransportSecuritySessionEstablished(uint64_t sessionID) override {
        // Session lifecycle observation.
    }

    void OnTransportSecurityFailure(
        const ESPressio::Security::SecurityResult& result
    ) override {
        // Diagnostics / metrics / audit handling.
    }
};

SecurityObserver observer;
auto observerHandle = security.RegisterObserver(&observer);
```

The observer surface supplements rather than replaces `SecurityResult`. Observer exceptions are isolated from Security processing so a diagnostics consumer cannot interrupt a cryptographic state transition.

When ESPressio Event 5.8.0 is selected, `ESPressio_TransportSecurityEventBridge.hpp` converts the same observations into asynchronous Event instances without changing Security's dependency direction.

## Protecting a Payload

```cpp
#include <ESPressio_Security.hpp>

using namespace ESPressio::Security;

AES256GCMCipher aes;
AeadCipherRegistry ciphers;
StaticKeyProvider keys;
ESP32RandomSource random;

ciphers.Register(aes);
uint8_t key[32] = { /* securely provisioned bytes */ };
keys.Add(1, AeadAlgorithm::AES256GCM, key, sizeof(key));

TransportSecurityConfig config;
config.Policy = TransportSecurityPolicy::Required;
config.OutboundAlgorithm = AeadAlgorithm::AES256GCM;
config.OutboundKeyID = 1;
config.SenderID = ESP.getEfuseMac();
config.SessionID = 0; // automatically generate a fresh sender epoch

TransportSecurity security(ciphers, keys, random, config);
std::vector<uint8_t> protectedBytes;
auto result = security.Protect(42, payload, payloadLength, protectedBytes);
```

`42` is the application/transport protocol identifier cryptographically bound to the payload.

## Receiving a Protected Payload

```cpp
UnprotectedPayload opened;
auto result = security.Unprotect(42, receivedBytes, receivedSize, opened);

if (!result.Success) {
    // Drop it. It must not reach protocol/application processing.
    return;
}

// opened.Data has passed authentication, decryption,
// protocol binding and replay checks.
```

Authenticated sender, key, session and sequence metadata is available without exposing the secret key.

## Generic Secure Transport Decorator

Concrete transports can implement the intentionally small `ITransportSecurityCarrier` interface and then be decorated:

```cpp
SecureTransportDecorator secureCarrier(carrier, security);
```

The decorator calls its application receiver only with data accepted by `TransportSecurity`. This is the intended integration point for ESPressio ESP-Now, ESPressio Sockets and future transports.

See [TRANSPORT_SECURITY.md](TRANSPORT_SECURITY.md) for the wire format and downstream-integration details.

## Examples

The repository includes:

- `examples/BasicSecurePayload` — AES-256-GCM registration, key provisioning, automatic session generation, ESP32 nonce generation, protect/open flow.
- `examples/MbedTLSAlgorithms` — compile-time discovery and registration of available mbedTLS-backed AEAD implementations.

Example keys are demonstration-only. Do not copy hard-coded example key material into production firmware.

## Testing

Host-side CMake/CTest coverage uses a deterministic **test-only** AEAD implementation contained exclusively under `tests/`.

Coverage includes protect/open round trips, authenticated metadata, ciphertext/tag/header/session tampering, protocol binding, replay rejection, in-window reordering, sender reboot/session rollover, explicit and automatically generated sessions, key rotation, Required/Preferred/Disabled policy behavior, malformed envelopes, payload limits, generic decorator flow, and 0.2.0 observable lifecycle behavior.

A separate production-cipher contract target instantiates all included mbedTLS-backed cipher classes against API-compatible host stubs. GitHub Actions also compile the ESP32 examples so the actual Arduino-ESP32 mbedTLS API surface is validated in addition to host abstraction tests.

## Security Considerations

Cryptography is only one part of a secure system. Applications remain responsible for secure key provisioning, physical security, firmware trust, secure boot/flash encryption where appropriate, key rotation policy, sender identity assignment and protection of secrets outside this library.

Do not log, serialize or expose key material. ESPressio Security APIs intentionally expose key IDs rather than keys in envelope metadata/results.

`Preferred` permits plaintext and must not be used where plaintext acceptance is unacceptable. Transport authentication also does not automatically authorize *what* an authenticated device may do; Command authorization/policy remains a separate application concern.

If an application explicitly supplies session IDs rather than allowing automatic generation, it must not reuse a session ID with a restarted sequence while receivers may still retain replay state for that same sender/key/session domain.

## Future Direction

Potential extensions include secure ESP32 NVS key providers, key derivation/provider integrations, signed identity/provisioning workflows, group/per-peer key management helpers, explicit key-expiry/rotation policy, bounded/persistent replay-state strategies, hardware-backed keys, and downstream secure adapters for ESPressio ESP-Now and ESPressio Sockets.

## Contributing

Issues and contributions are welcome through the ESPressio Security GitHub repository. Security-sensitive changes should include corresponding tests and should avoid bespoke cryptographic primitives where established, reviewed platform cryptography is available.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history and notable changes.
