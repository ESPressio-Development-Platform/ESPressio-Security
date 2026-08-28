# Implementing AEAD Ciphers

New authenticated-encryption implementations integrate through `IAeadCipher` and are registered with `AeadCipherRegistry`.

## Contract goals

An implementation must preserve the algorithm identity, required key length, nonce expectations, authentication-tag semantics, encryption/decryption result reporting, and authenticated associated data supplied by Security.

Do not silently fall back to another algorithm when the requested implementation is unavailable.

## Registry integration

The registry resolves a concrete cipher by `AeadAlgorithm`. Registration should therefore be explicit and deterministic.

## Target libraries

The 1.0.0 baseline includes mbedTLS-backed implementations for supported AES-GCM, AES-CCM and ChaCha20-Poly1305 configurations. Another backend may implement the same ESPressio contract without changing `DataProtector` or transport consumers.

## Testing

Include known-answer or compatibility vectors where applicable, round-trip coverage, wrong-key rejection, modified-ciphertext rejection, modified-tag rejection, associated-data mismatch, malformed lengths, unsupported algorithm behaviour, and boundary payload sizes.