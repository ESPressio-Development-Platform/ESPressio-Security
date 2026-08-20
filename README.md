# ESPressio Security

Transport-neutral authenticated encryption, authentication, replay protection and key abstraction for the Flowduino ESPressio Development Platform.

ESPressio Security protects **opaque transport payloads** without knowing whether they contain Events, Commands, clock synchronization messages, application packets, or another protocol. Concrete transports such as ESP-NOW, UDP, TCP and WebSockets can therefore opt into the same security layer while higher-level application protocols remain independent of cryptography.

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

ESPressio is designed as a modular ecosystem of independently useful libraries, with required dependencies kept explicit and optional integrations introduced only when corresponding functionality is selected.

For the Security-specific relationship, see [ESPRESSIO_DEPENDENCY_CHART.md](ESPRESSIO_DEPENDENCY_CHART.md).

### Required ESPressio dependencies

**None.**

ESPressio Security is intentionally foundational and transport-neutral. Concrete communication libraries should depend optionally on Security, rather than Security depending on them:

```text
ESPressio ESP-Now  - - -> ESPressio Security
ESPressio Sockets  - - -> ESPressio Security
future transports  - - -> ESPressio Security
```

Event, Command and Timing do not need to depend directly on Security merely because their messages may be transported securely.

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
- `ReplayWindow` — per-sender/per-key sliding replay detector.
- `ITransportSecurityCarrier` — minimal concrete-transport adapter contract.
- `SecureTransportDecorator` — generic secure wrapper for a carrier.

## PlatformIO

Add the published library with:

```ini
lib_deps =
    flowduino/ESPressio-Security@^0.1.0

build_flags =
    -std=gnu++17

build_unflags =
    -std=gnu++11
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
- **Replay protection** — previously authenticated sequences are rejected per sender/key replay window.

No plaintext is delivered to the protocol consumer until authentication/decryption succeeds.

## AEAD Algorithm Abstraction

Encryption is deliberately represented by `IAeadCipher`. `TransportSecurity` contains no AES-, CCM-, GCM- or ChaCha-specific logic.

```cpp
class IAeadCipher {
public:
    virtual AeadAlgorithm Algorithm() const noexcept = 0;
    virtual const char* Name() const noexcept = 0;
    virtual std::size_t KeySize() const noexcept = 0;
    virtual std::size_t NonceSize() const noexcept = 0;
    virtual std::size_t TagSize() const noexcept = 0;
    virtual bool Seal(...) = 0;
    virtual bool Open(...) = 0;
};
```

Algorithms are resolved through `AeadCipherRegistry`, allowing new implementations without changing the transport-security processor and allowing receivers to support multiple algorithms concurrently during migration.

## Included AEAD Implementations

When supported by the platform's mbedTLS build, 0.1.0 provides:

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
sequence
nonce length
tag length
ciphertext length
```

The protocol ID is AEAD associated data. A valid encrypted Event packet therefore cannot be relabelled as a Command packet without authentication failure. The envelope carries **key IDs, never keys**.

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

## Randomness and Nonces

`IRandomSource` abstracts nonce randomness. On ESP32, use `ESP32RandomSource`, which uses the ESP platform random facility.

`StandardRandomSource` exists for portable/host use. `std::random_device` quality is implementation-dependent and should not be assumed to provide production embedded cryptographic entropy on every platform.

Each protected packet carries its nonce explicitly. AEAD nonce uniqueness for a given key remains security-critical.

## Replay Protection

Each authenticated envelope contains a non-zero 64-bit sequence number. `ReplayWindow` tracks sequences independently by `sender ID + key ID`.

A sliding window permits limited legitimate reordering while rejecting duplicates and stale packets. Replay state is committed **only after successful AEAD authentication and protocol validation**, preventing unauthenticated forged high sequence numbers from advancing receiver state.

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

Authenticated sender, key and sequence metadata is available without exposing the secret key.

## Generic Secure Transport Decorator

Concrete transports can implement the intentionally small `ITransportSecurityCarrier` interface and then be decorated:

```cpp
SecureTransportDecorator secureCarrier(carrier, security);
```

The decorator calls its application receiver only with data accepted by `TransportSecurity`. This is the intended integration point for ESPressio ESP-Now, ESPressio Sockets and future transports.

## Examples

The repository includes:

- `examples/BasicSecurePayload` — AES-256-GCM registration, key provisioning, ESP32 nonce generation, protect/open flow.
- `examples/MbedTLSAlgorithms` — compile-time discovery and registration of available mbedTLS-backed AEAD implementations.

Example keys are demonstration-only. Do not copy hard-coded example key material into production firmware.

## Testing

Host-side CMake/CTest coverage uses a deterministic **test-only** AEAD implementation contained exclusively under `tests/`.

Coverage includes protect/open round trips, authenticated metadata, ciphertext/tag/header tampering, protocol binding, replay rejection, in-window reordering, key rotation, Required/Preferred/Disabled policy behavior, malformed envelopes, payload limits and generic decorator flow.

GitHub Actions also compiles the ESP32 examples so the actual Arduino-ESP32 mbedTLS API surface is validated in addition to host abstraction tests.

## Security Considerations

Cryptography is only one part of a secure system. Applications remain responsible for secure key provisioning, physical security, firmware trust, secure boot/flash encryption where appropriate, key rotation policy, sender identity assignment and protection of secrets outside this library.

Do not log, serialize or expose key material. ESPressio Security APIs intentionally expose key IDs rather than keys in envelope metadata/results.

`Preferred` permits plaintext and must not be used where plaintext acceptance is unacceptable. Transport authentication also does not automatically authorize *what* an authenticated device may do; Command authorization/policy remains a separate application concern.

## Future Direction

Potential extensions include secure ESP32 NVS key providers, key derivation/provider integrations, signed identity/provisioning workflows, group/per-peer key management helpers, explicit key-expiry/rotation policy, persistent replay epochs/counters, hardware-backed keys, and downstream secure adapters for ESPressio ESP-Now and ESPressio Sockets.

## Contributing

Issues and contributions are welcome through the ESPressio Security GitHub repository. Security-sensitive changes should include corresponding tests and should avoid bespoke cryptographic primitives where established, reviewed platform cryptography is available.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history and notable changes.

## License

ESPressio and its component libraries are licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE) for details.
