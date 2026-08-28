# Protection Contexts and Envelopes

`DataProtectionContext` supplies authenticated associated data. The context is not stored inside the protected envelope, but the same context must be supplied when the data is unprotected.

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

If the protected bytes are presented under a different context, authentication fails. This binds a protected record cryptographically to its intended purpose.

## ESDP envelope

`DataProtector` writes a versioned `ESDP` envelope containing structural metadata together with the nonce, authentication tag, and ciphertext.

Conceptually:

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

The algorithm/key identity and structural header are authenticated. Key material is never placed in the envelope.

## Design implication

Higher-level ESPressio libraries can use purpose-specific contexts without learning the mechanics of AEAD associated data. Prefer stable, domain-specific context strings for persisted formats so unrelated protected records cannot be substituted for one another.