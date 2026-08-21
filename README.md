# ESPressio Security

Transport-neutral authenticated encryption, authentication, replay protection and key abstraction for the Flowduino ESPressio Development Platform.

ESPressio Security protects **opaque transport payloads** without knowing whether they contain Events, Commands, clock synchronization messages, application packets, or another protocol. Concrete transports such as ESP-NOW, UDP, TCP and WebSockets can therefore opt into the same security layer while higher-level application protocols remain independent of cryptography.

## Current Version — 0.3.0

Security 0.3.0 retains the Security 0.2 transport-security API and now owns the optional Event representation of its own lifecycle. Core Security remains independent of Event; Event is acquired only when the application explicitly selects the Event integration headers.

## Why transport-level security?

Security belongs between the application protocol and concrete transport:

```text
Event / Command / Clock Sync / application protocol
                       |
                       v
              TransportSecurity
                       |
          authenticate + encrypt
                       |
                       v
              Concrete Transport
        ESP-NOW / UDP / TCP / WS / ...
```

Inbound processing runs in reverse. This avoids implementing unrelated cryptographic semantics separately inside every ESP-NOW, TCP, UDP, WebSocket, or higher-level protocol implementation.

## ESPressio Development Platform

ESPressio is a collection of discrete, composable component libraries built around a common development ethos:

- **Light-weight** — minimise memory consumption and operational overhead without sacrificing correctness.
- **Ease of use** — provide developer-friendly, strongly typed abstractions over lower-level facilities.
- **Object-oriented** — a type for everything, and everything in a type.
- **SOLID** — keep cryptographic algorithms, key retrieval, randomness, replay tracking and concrete transport adaptation behind focused abstractions.

## License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).

## Namespace

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
- `ReplayWindow` — sender/key/session scoped replay detector.
- `ITransportSecurityCarrier` — minimal concrete-transport adapter contract.
- `SecureTransportDecorator` — generic secure wrapper for a carrier.
- `ITransportSecurityObserver` — synchronous Security lifecycle observation.

## Dependencies

Required:

```text
ESPressio Observable >= 3.0.1 < 4.0.0
```

Optional Event integration:

```text
ESPressio Event >= 6.0.0 < 7.0.0
```

Security remains independent of ESP-Now, Sockets, Command, Serial and Event at the core layer.

See [ESPRESSIO_DEPENDENCY_CHART.md](ESPRESSIO_DEPENDENCY_CHART.md) for the complete ecosystem graph and [TRANSPORT_SECURITY.md](TRANSPORT_SECURITY.md) for the detailed transport-security model.

## Installation

PlatformIO/Arduino-ESP32:

```ini
lib_deps =
    flowduino/ESPressio-Security@^0.3.0
    flowduino/ESPressio-Observable@^3.0.1

build_flags =
    -std=gnu++17
    -frtti

build_unflags =
    -std=gnu++11
    -fno-rtti
```

RTTI is required by Observable's typed Observer dispatch and must be enabled at the application-project level.

When selecting the optional Event integration, also add:

```ini
lib_deps =
    flowduino/ESPressio-Event@^6.0.0
```

# Security guarantees

When `TransportSecurityPolicy::Required` is selected and a production AEAD implementation/key source is configured correctly, ESPressio Security is designed to provide:

- **Confidentiality** — payload bytes are encrypted.
- **Integrity** — modified ciphertext or authenticated metadata is rejected.
- **Authentication** — only holders of valid key material can generate an accepted protected packet.
- **Protocol binding** — the protocol identifier is authenticated and cannot be relabelled without invalidating the packet.
- **Replay protection** — previously authenticated sequences are rejected independently per sender, key and authenticated session.
- **Reboot-safe sequence restart** — a sender can restart sequence numbering after reboot when it establishes a fresh authenticated session/epoch ID.

No plaintext is delivered to the protocol consumer until authentication/decryption succeeds.

# AEAD algorithm abstraction

Encryption is represented by `IAeadCipher`. `TransportSecurity` contains no AES-, CCM-, GCM- or ChaCha-specific control flow.

Algorithms are resolved through `AeadCipherRegistry`, allowing receivers to support more than one registered algorithm during migration without changing the transport-security processor.

## Included AEAD implementations

Where supported by the selected mbedTLS build:

| Algorithm | Key | Nonce | Tag | Class |
| --- | ---: | ---: | ---: | --- |
| AES-128-GCM | 128-bit | 96-bit | 128-bit | `AES128GCMCipher` |
| AES-256-GCM | 256-bit | 96-bit | 128-bit | `AES256GCMCipher` |
| AES-128-CCM | 128-bit | 96-bit | 128-bit | `AES128CCMCipher` |
| AES-256-CCM | 256-bit | 96-bit | 128-bit | `AES256CCMCipher` |
| ChaCha20-Poly1305 | 256-bit | 96-bit | 128-bit | `ChaCha20Poly1305Cipher` |

Availability macros include:

```text
ESPRESSIO_SECURITY_HAS_MBEDTLS_GCM
ESPRESSIO_SECURITY_HAS_MBEDTLS_CCM
ESPRESSIO_SECURITY_HAS_MBEDTLS_CHACHAPOLY
```

The default outbound algorithm is AES-256-GCM. Algorithm choice remains application/security-policy configuration; the library does not silently substitute a different production algorithm.

# Security envelope

Protected packets use a versioned transport-neutral envelope. The authenticated metadata includes:

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

The fixed header is AEAD associated authenticated data. An encrypted Event packet therefore cannot be relabelled as a Command packet, moved into another sender session, or have its sequence changed without failing authentication.

The envelope carries **key IDs, never keys**.

# Security policies

`TransportSecurityPolicy` provides three explicit modes:

- `Disabled` — outbound data remains plaintext and plaintext inbound data is accepted.
- `Preferred` — security is used when the requested cipher/key is available; plaintext interoperability remains possible. This is a migration mode.
- `Required` — protected outbound transmission fails if encryption cannot be performed, and plaintext inbound packets are rejected.

Use `Required` whenever secure transport is an actual security requirement.

# Key providers and key rotation

Key retrieval is abstracted by `IKeyProvider`. `StaticKeyProvider` is useful for simple applications and tests.

Multiple key IDs can coexist, allowing receivers to accept an old and new key during rotation while transmitters switch their configured outbound key ID.

Production systems should implement `IKeyProvider` using an appropriate secure provisioning/storage mechanism rather than hard-coding secrets in source code.

# Randomness, nonces and session IDs

`IRandomSource` abstracts cryptographic randomness. ESP32 applications can use `ESP32RandomSource`, which uses the ESP platform random facility.

Each protected packet carries a nonce explicitly. AEAD nonce uniqueness for a given key is security-critical.

`TransportSecurityConfig::SessionID` can be supplied explicitly. When left at zero, `TransportSecurity` generates a fresh non-zero 64-bit session ID on the first protected transmission and retains it for the Security session.

The current session can be inspected through:

```cpp
auto sessionID = security.GetSessionID();
```

Calling `SetConfig()` resets outbound sequence/replay state; a zero Session ID causes a new automatic session to be generated on the next protected send.

# Replay protection

Each authenticated envelope carries a non-zero session ID and sequence number. `ReplayWindow` tracks sequences independently by:

```text
sender ID + key ID + session ID
```

A sliding window permits limited legitimate reordering while rejecting duplicates and stale packets. Replay state is committed **only after successful AEAD authentication and protocol validation**, preventing forged packets from poisoning replay state.

Explicit administrative reset is available through:

```cpp
security.ResetReplayProtection();
```

# Protecting and unprotecting payloads

`TransportSecurity` works on opaque bytes and a protocol identifier. The normal application flow is:

```text
outbound payload
    -> Protect(...)
    -> secured envelope
    -> concrete transport

concrete transport
    -> secured envelope
    -> Unprotect(...)
    -> authenticated plaintext payload
```

The returned `SecurityResult` remains authoritative for success/failure handling; the Observer/Event layers are passive diagnostics/lifecycle surfaces and do not replace normal error handling.

# Generic transport decoration

`SecureTransportDecorator` can wrap any `ITransportSecurityCarrier`:

```cpp
SecureTransportDecorator secure(carrier, security);
secure.Send(protocolID, payload);
```

Inbound carrier packets are authenticated/decrypted before the registered receive callback is invoked. Authentication failure, replay rejection, or protocol mismatch prevents plaintext delivery.

Concrete transport libraries may alternatively integrate `TransportSecurity` directly where their threading/callback model makes that more natural.

# Observing Security lifecycle

`TransportSecurity` exposes synchronous lifecycle notifications through `ITransportSecurityObserver`:

```cpp
#include <ESPressio_Security.hpp>

class SecurityObserver final :
    public ESPressio::Security::ITransportSecurityObserver {
public:
    void OnTransportSecuritySessionEstablished(
        uint64_t sessionID
    ) override {
        // Record/display the authenticated session identity.
    }

    void OnTransportSecurityFailure(
        const ESPressio::Security::SecurityResult& result
    ) override {
        // Diagnostics/metrics; return-value handling remains authoritative.
    }
};

SecurityObserver observer;
auto handle = security.RegisterObserver(&observer);
```

Available observations cover:

- configuration changed;
- security session reset;
- security session established;
- replay-protection reset; and
- security failure.

The observation layer never exposes key material.

# Optional Event integration

Security 0.3.0 owns the Event representation of its lifecycle:

```cpp
#include <ESPressio_SecurityEvents.hpp>
#include <ESPressio_TransportSecurityEventBridge.hpp>
```

The bridge is bound to a specific `TransportSecurity` instance:

```cpp
ESPressio::Event::TransportSecurityEventBridge bridge;

if (bridge.Initialize(security)) {
    // Security lifecycle observations now also become Events.
}
```

When finished:

```cpp
bridge.Shutdown();
```

The bridge converts configuration, session, replay-protection and failure observations into asynchronous Events. Event remains an optional dependency of this integration; the ordinary Security umbrella stays Event-free.

```text
Security core
    -> Observable

Security Event integration
    - - -> Event
```

Event 6.0.0 does not depend back on Security.

# Concurrency model

`TransportSecurity` protects mutable outbound sequence/replay state and configuration transitions internally. Applications should nevertheless prefer a clear security ownership/execution context per Security instance where practical, especially in embedded transport callback paths.

# Operational guidance

- Prefer `TransportSecurityPolicy::Required` where security is genuinely required.
- Avoid hard-coding production keys in firmware source.
- Treat authenticated sender/session metadata as identity input, not authorization policy by itself.
- Use a secure provisioning/storage strategy appropriate to the deployment.
- Keep mbedTLS/Arduino-ESP32/ESP-IDF versions under normal security update processes.
- Treat `Preferred` as migration/interoperability mode, not equivalent security to `Required`.
- Size replay windows for expected legitimate packet reordering.
- Ensure RTTI is enabled when using Observable-backed Security.

# Testing

Host and ESP32 validation cover envelope encode/decode, production AEAD wrappers where available, protocol binding, replay rejection, sender-session scoped replay behavior, automatic session generation, tamper rejection, key rotation, security policy, transport decoration, and Observable/Event lifecycle integration.

# Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history and notable changes.
