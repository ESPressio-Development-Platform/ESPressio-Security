# Memory and Resource Limits

Security operations process attacker-controlled or persistence-controlled byte sequences and must remain bounded on embedded targets.

## Plaintext bound

`DataProtectionConfig` carries `MaximumPlaintextBytes`. Configure this to the largest payload the application genuinely needs rather than an arbitrarily large value.

The bound protects both memory consumption and parsing/decryption work from malformed or hostile envelopes.

## Transient buffers

The 1.0.0 baseline integrates with ESPressio System memory policy so Security's transient work buffers can follow the platform's configured memory-placement strategy rather than forcing all temporary cryptographic storage into one memory class.

Security semantics must remain identical regardless of where a provider places eligible transient storage.

## Sensitive data lifetime

Minimise the lifetime of plaintext and key-bearing buffers. Platform or extension implementations should avoid unnecessary copies and should use deterministic ownership so temporary material is released promptly.

Memory optimisation must never weaken authentication, replay protection, key separation, or algorithm-selection rules.