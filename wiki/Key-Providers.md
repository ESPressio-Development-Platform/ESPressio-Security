# Key Providers

`IKeyProvider` is the key-management boundary for ESPressio Security 1.0.0. Cryptographic consumers request key material by key identity and algorithm without knowing how that material is stored or provisioned.

## Static keys

`StaticKeyProvider` is useful for tests, demonstrations, and simple firmware:

```cpp
constexpr std::array<uint8_t, 32> key = {
    /* application-specific bytes */
};

StaticKeyProvider keys;
keys.Add(7, AeadAlgorithm::AES256GCM, key);
```

The rest of the application can continue using `IKeyProvider` if `StaticKeyProvider` is later replaced.

## Production key storage

A compile-time firmware key raises the baseline above plaintext persisted credentials, but it is not protection against an attacker who can extract and analyse the firmware.

Higher-assurance products should provide an `IKeyProvider` backed by an appropriate strategy such as provisioning, secure storage, a secure element, or hardware-backed key facilities.

## Extension path

To add another key source, see [Implementing Key Providers](Implementing-Key-Providers).