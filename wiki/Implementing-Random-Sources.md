# Implementing Random Sources

Implement `IRandomSource` only when Security cannot use the normal `SystemEntropyRandomSource` path directly—for example in specialised hardware integration or deterministic test infrastructure.

## Production requirements

A production source used for AEAD nonces must derive bytes from a cryptographically appropriate source. Do not adapt a general-purpose pseudo-random generator merely because it has a convenient API.

Target-specific entropy should normally be implemented beneath ESPressio System and consumed through `SystemEntropyRandomSource`, preserving the platform abstraction boundary.

## Failure semantics

Entropy failure must be explicit. Security must not continue by fabricating predictable nonce bytes or reusing a previous nonce.

## Testing

Tests should cover successful fills across requested sizes, provider failure, cryptographic-suitability gating where System entropy is involved, and the absence of partial-success ambiguity.