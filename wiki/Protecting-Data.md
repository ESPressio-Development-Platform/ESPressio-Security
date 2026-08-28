# Protecting Data

`DataProtector` provides authenticated encryption for arbitrary data without requiring callers to manage nonces or envelope structure.

## Protect a string

```cpp
std::vector<uint8_t> protectedBytes;

auto result = protector.ProtectString(
    "my secret value",
    protectedBytes
);

if (!result.Success) {
    // Inspect result.Error and result.Message.
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

## What protection means

The protected representation uses authenticated encryption. A successful unprotect operation therefore establishes both confidentiality and integrity/authenticity under the configured key and algorithm.

Modification of ciphertext, authenticated metadata, authentication tag, or supplied protection context causes authentication to fail.

## Resource bounds

`DataProtectionConfig` includes a maximum plaintext size. Keep this bounded appropriately for embedded systems rather than accepting unbounded hostile or corrupted inputs.

See [Memory and Resource Limits](Memory-and-Resource-Limits).

## Purpose binding

For independently meaningful records, supply a `DataProtectionContext` so ciphertext cannot be validly replayed under an unrelated purpose. See [Protection Contexts and Envelopes](Protection-Contexts-and-Envelopes).