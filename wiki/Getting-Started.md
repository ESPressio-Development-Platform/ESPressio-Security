# Getting Started

Include the Security umbrella:

```cpp
#include <ESPressio_Security.hpp>
```

The 1.0.0 library has two principal usage paths: protecting arbitrary data at rest and protecting opaque transport payloads in transit.

## Protecting arbitrary data

A `DataProtector` composes:

- an `AeadCipherRegistry`;
- an `IKeyProvider`;
- an `IRandomSource`;
- a `DataProtectionConfig`.

Typical setup:

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

DataProtectionConfig config {
    AeadAlgorithm::AES256GCM,
    1,
    64u * 1024u
};

DataProtector protector(ciphers, keys, random, config);
```

The caller does not generate or manage AEAD nonces.

## Platform entropy

`SystemEntropyRandomSource` adapts the installed ESPressio System entropy provider to Security's `IRandomSource` contract and requires that provider to advertise cryptographic suitability.

Install the target System providers before Security first requires hardware entropy.

## Next steps

- [Protecting Data](Protecting-Data)
- [Protection Contexts and Envelopes](Protection-Contexts-and-Envelopes)
- [Transport Security](Transport-Security)
- [Operational Guidance](Operational-Guidance)