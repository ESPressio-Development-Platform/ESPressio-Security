# Implementing Key Providers

Implement `IKeyProvider` when key material comes from a source other than `StaticKeyProvider`.

Typical implementations might adapt provisioned flash storage, a secure element, a hardware-backed key service, or another application-controlled key vault.

## Contract responsibilities

A provider must resolve the requested key identity and algorithm deterministically, return only compatible key material, report missing/unavailable keys explicitly, and keep native storage or hardware APIs below the interface boundary.

## Lifetime and exposure

Avoid unnecessary copies of key material and keep temporary key buffers alive only as long as required by the cryptographic operation. Do not log keys or place them in serialized protection envelopes.

## Rotation

The protected envelope carries a key ID, allowing a provider to retain older keys for decryption while selecting a newer configured key for newly protected data. Rotation policy belongs to the application/provider rather than being hidden inside the cryptographic primitive.

## Testing

Test valid lookup, missing key, wrong algorithm, multiple key IDs, old-key decryption during rotation, unavailable hardware/provider state, and secure cleanup appropriate to the implementation.