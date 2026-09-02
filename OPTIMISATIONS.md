# ESPressio Security Optimisation Log

This file records Security optimisations chronologically. Version numbers are intentionally unchanged during this coordinated development round.

## 2026-08-27 — Externalise eligible protection scratch (#23)

Phase 10 of the coordinated System memory-policy programme moved eligible non-secret DataProtector scratch to `ESPressio-System` `MemoryPolicy::ExternalPreferred` storage.

### Changes
- data-protection nonce scratch now uses external-preferred System memory;
- AEAD additional-authenticated-data scratch now uses external-preferred System memory;
- the previous standalone serialized header vector and subsequent `aad = header` copy were removed;
- the serialized header is built directly as the prefix of the AAD buffer and copied only once into the final protected envelope;
- unprotect AAD scratch likewise uses external-preferred storage;
- the public `IAeadCipher` `std::vector` output contract remains unchanged;
- key material remains on its existing controlled allocation path and is securely erased after cipher use.

### Dependency policy
`library.json` resolves ESPressio-System directly from `feature/1-system-memory-policy` for the coordinated working-branch validation round. No release version number changed.

Commits:
- `51706d4` — `optimise(#23): externalise non-secret protection scratch and remove header copy`
- `ccdebf8` — `chore(#23): consume System memory policy working branch`
