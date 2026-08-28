# Operational Guidance

For production deployments:

- install a cryptographically suitable platform entropy provider before nonce generation;
- use authenticated encryption through `DataProtector` rather than unauthenticated/raw encryption;
- never persist or transmit key material inside protected envelopes;
- use purpose-specific `DataProtectionContext` values for independently meaningful records;
- keep `MaximumPlaintextBytes` bounded;
- keep the target cryptographic implementation current;
- prefer provisioned or hardware-backed `IKeyProvider` implementations when the threat model includes firmware extraction;
- use transport policy `Required` when secure communication is a real requirement;
- treat replay/session state as part of the security boundary rather than optional metadata.

## Firmware-embedded keys

A key compiled into firmware can protect persisted values from casual plaintext disclosure but is recoverable by an attacker capable of extracting and analysing firmware. Choose the key-provider strategy according to the actual physical and operational threat model.

## Failure handling

Authentication failures, malformed envelopes, unknown algorithms/keys, replay rejection, entropy failure, and policy failure should be treated as explicit security outcomes. Do not automatically reinterpret them as plaintext or insecure traffic.