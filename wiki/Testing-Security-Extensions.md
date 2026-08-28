# Testing Security Extensions

Security tests must cover both successful cryptographic behaviour and explicit failure behaviour.

## Data-protection coverage

Include round trips, context binding, tamper rejection, malformed envelopes, unknown keys/algorithms, payload bounds, nonce-generation failure, and resource-limit boundaries.

## Transport-security coverage

Include sender/session binding, sequence progression, replay rejection, protocol mismatch, authentication failure, policy handling, and secure-carrier errors.

## Extension-specific coverage

For custom ciphers, key providers, entropy sources, or carriers, add tests at the interface boundary as well as integration tests with `DataProtector` or `TransportSecurity`.

## Never weaken tests for portability

A platform-specific backend may have different availability or native error codes, but it must satisfy the same ESPressio security semantics. Unsupported production algorithms should be reported as unavailable rather than replaced silently.