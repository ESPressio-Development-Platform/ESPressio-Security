# ESPressio Security

Authenticated data protection, transport security, replay protection and key abstraction for the ESPressio Development Platform.

## Current Version — 0.4.2

During the release restructuring, the optional Security Event integration is validated against ESPressio Event `main` and the current ESPressio Serializable dependency chain on `main`. The data-protection and transport-security APIs introduced through 0.4.0 are unchanged.

The active platform-abstraction tranche additionally routes hardware entropy through ESPressio-System. Cryptographic algorithms and security policy remain in this library; target-specific random-number generation belongs to the installed platform provider.

## Two security responsibilities

Security deliberately separates two related but different concerns:

```text
Data at rest                         Data in transit
-------------                        ---------------
configuration                        Event / Command / protocol payload
      |                                      |
      v                                      v
 IDataProtector                         TransportSecurity
      |                                      |
 authenticated encryption                authenticated encryption
      |                                      + replay/session/protocol binding
      v                                      |
Persistence / file / NVS                  Transport
```

Use `IDataProtector` / `DataProtector` when a value simply needs authenticated encryption. Use `TransportSecurity` when data is being exchanged over a transport and also needs sender/session/sequence/replay semantics.

# Installation

During the coordinated platform-abstraction development tranche:

```ini
lib_deps =
    https://github.com/ESPressio-Development-Platform/ESPressio-System.git#main
    https://github.com/ESPressio-Development-Platform/ESPressio-Security.git#main
```

On ESP32, the top-level application also installs the ESPressio-ESP32 System providers before Security first needs hardware entropy:

```cpp
#include <ESPressio_ESP32.hpp>

ESPressio::ESP32Platform::InstallSystemProviders();
```

During the release restructuring, consume ESPressio dependencies from their `main` branches until the new platform-wide 1.0.0 release generation is published.

The normal Security umbrella is:

```cpp
#include <ESPressio_Security.hpp>
```

# Protecting arbitrary data

A `DataProtector` composes four existing Security concepts:

- `AeadCipherRegistry` — resolves the authenticated-encryption implementation;
- `IKeyProvider` — supplies key material by key ID and algorithm;
- `IRandomSource` — generates nonces safely;
- `DataProtectionConfig` — selects the outbound algorithm/key and resource limit.

The caller does **not** generate or manage nonces.

For platform entropy, use `SystemEntropyRandomSource`. It adapts the installed `ESPressio::System::Entropy` source to Security's `IRandomSource` contract and refuses providers that do not declare themselves cryptographically suitable.

```cpp
#include <array>
#include <ESPressio_Security.hpp>

using namespace ESPressio::Security;

AES256GCMCipher aes256;
AeadCipherRegistry ciphers;
StaticKeyProvider keys;
SystemEntropyRandomSource random;

constexpr std::array<uint8_t, 32> ApplicationKey = {
    /* application-specific bytes */
};

void ConfigureSecurity() {
    ciphers.Register(aes256);
    keys.Add(1, AeadAlgorithm::AES256GCM, ApplicationKey);
}

DataProtectionConfig protectionConfig {
    AeadAlgorithm::AES256GCM,
    1,
    64u * 1024u
};

DataProtector protector(ciphers, keys, random, protectionConfig);
```

`ESP32RandomSource` remains a compatibility alias to `SystemEntropyRandomSource` during this migration; it no longer calls an ESP32 API itself.

> **Important:** a key compiled into firmware is convenient and substantially better than persisting plaintext credentials, but it can be recovered by an attacker able to extract and analyse the firmware. Production devices requiring resistance to physical extraction should provide an `IKeyProvider` backed by an appropriate provisioning or hardware-security strategy.

## Protect a string

```cpp
std::vector<uint8_t> protectedBytes;

auto result = protector.ProtectString(
    "my secret value",
    protectedBytes
);

if (!result.Success) {
    // result.Error and result.Message explain why protection failed.
}
```

Restore it later:

```cpp
std::string restored;

auto result = protector.UnprotectString(
    protectedBytes.data(),
    protectedBytes.size(),
    restored
);
```

## Bind protected data to its purpose

`DataProtectionContext` is authenticated associated data. It is not included in the protected envelope, but the same context must be supplied when unprotecting.

```cpp
const DataProtectionContext context(
    "ESPressio.WiFi.Configuration"
);

protector.ProtectString(
    "secret",
    protectedBytes,
    context
);

protector.UnprotectString(
    protectedBytes.data(),
    protectedBytes.size(),
    restored,
    context
);
```

If the bytes are later presented under a different context, authentication fails. This makes it easy for higher-level libraries to cryptographically bind a persisted blob to its intended purpose without requiring their developers to understand AEAD associated-data mechanics.

# Protected-data envelope

`DataProtector` writes a versioned `ESDP` envelope containing:

```text
magic
format version
algorithm ID
key ID
nonce length
authentication-tag length
plaintext/ciphertext length
nonce
authentication tag
ciphertext
```

The algorithm/key identity and structural header are authenticated. The envelope never contains key material.

Because modern AEAD is used, a successfully unprotected value has both confidentiality and integrity/authenticity. Modification of ciphertext, metadata, tag or authenticated context causes unprotection to fail.

# Key providers

`IKeyProvider` remains the key-management boundary. `StaticKeyProvider` is useful for tests and simple firmware and accepts `std::array` directly:

```cpp
constexpr std::array<uint8_t, 32> key = { /* ... */ };
keys.Add(7, AeadAlgorithm::AES256GCM, key);
```

The rest of the application does not change when `StaticKeyProvider` is later replaced by a provisioned, secure-element or hardware-backed provider.

# Supported AEAD implementations

Where supported by the selected mbedTLS build:

| Algorithm | Key | Nonce | Tag | Class |
| --- | ---: | ---: | ---: | --- |
| AES-128-GCM | 128-bit | 96-bit | 128-bit | `AES128GCMCipher` |
| AES-256-GCM | 256-bit | 96-bit | 128-bit | `AES256GCMCipher` |
| AES-128-CCM | 128-bit | 96-bit | 128-bit | `AES128CCMCipher` |
| AES-256-CCM | 256-bit | 96-bit | 128-bit | `AES256CCMCipher` |
| ChaCha20-Poly1305 | 256-bit | 96-bit | 128-bit | `ChaCha20Poly1305Cipher` |

The library never silently substitutes a different production algorithm when the requested one is unavailable.

# Transport security

`TransportSecurity` remains the transport-neutral protection layer for opaque Event, Command and protocol payloads. It adds authenticated protocol identity, sender/session identity, monotonically increasing sequence numbers and replay protection on top of AEAD.

Security policies remain:

- `Disabled`
- `Preferred`
- `Required`

Use `Required` whenever secure transport is a real requirement.

`SecureTransportDecorator` can wrap an `ITransportSecurityCarrier`, and `ITransportSecurityObserver` continues to expose transport-security lifecycle notifications. The optional `ESPressio_TransportSecurityEventBridge.hpp` maps those notifications into ESPressio Event without making Event a core Security dependency.

# Dependency model

Required during the platform-abstraction tranche:

```text
Security
    -> System
    -> Observable
```

Optional:

```text
Security Event integration
    - - -> Event
```

Security does not depend on Persistence, WiFi, Sockets, ESP-Now, Command or Serial. Those downstream libraries may opt into Security. Hardware entropy is supplied by System's installed platform provider rather than by Security itself.

See [ESPRESSIO_DEPENDENCY_CHART.md](ESPRESSIO_DEPENDENCY_CHART.md).

# Operational guidance

- Install a cryptographically suitable platform entropy provider before generating nonces.
- Prefer authenticated encryption (`DataProtector`) rather than unauthenticated/raw encryption.
- Never persist or transmit key material inside the protected envelope.
- Treat compile-time firmware keys as a convenience/security baseline, not as protection against firmware extraction.
- Use purpose-specific `DataProtectionContext` values for independently meaningful protected records.
- Keep platform cryptographic libraries current.
- Keep `MaximumPlaintextBytes` bounded for embedded deployments.
- Prefer provisioned/hardware-backed `IKeyProvider` implementations for higher-assurance products.

# Testing

Host tests cover generic data-protection round trips, context binding, tamper rejection, malformed envelopes, payload bounds, transport envelope behavior, replay/session handling and secure transport decoration. Platform integration tests must additionally provide an installed cryptographically suitable entropy source when nonce generation is exercised.
