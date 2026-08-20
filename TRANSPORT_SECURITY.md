# ESPressio Transport Security

This document describes the transport-neutral security layer introduced by ESPressio Security 0.1.0.

## Placement

Security is applied after a higher-level protocol has produced its transport payload and before a concrete transport sends it:

```text
Event / Command / Clock Sync / application protocol
                         |
                         v
                 TransportSecurity
                         |
                         v
                  secured envelope
                         |
                         v
             ESP-NOW / UDP / TCP / ...
```

On receive, the order is reversed. Authentication, decryption, protocol binding and replay validation complete before plaintext is handed upward.

## Version 1 Envelope

The fixed 44-byte header is encoded in little-endian form and contains:

```text
uint32 magic           "ESPS"
uint8  version         1
uint8  algorithm       AeadAlgorithm
uint8  flags           reserved
uint8  protocol        application/transport protocol identifier
uint32 keyId
uint64 senderId
uint64 sessionId
uint64 sequence
uint8  nonceLength
uint8  tagLength
uint16 reserved
uint32 ciphertextLength
```

The complete fixed header is supplied to AEAD as associated authenticated data. It is followed by:

```text
nonce
ciphertext
authentication tag
```

The secret key itself is never encoded in the packet.

## Sender Session / Epoch Identity

`sessionId` separates replay state between sender lifetimes. By default `TransportSecurityConfig::SessionID` is zero; the first protected transmission then generates a fresh non-zero 64-bit session ID from the configured `IRandomSource`.

A sender may therefore reboot and restart its sequence number at `1` without being confused with the previous boot:

```text
sender 0x10, session A, sequence 1
sender 0x10, session A, sequence 2

<sender reboots>

sender 0x10, session B, sequence 1
```

Both sequence `1` packets are valid because they belong to different authenticated sessions. Replaying either packet within its own session remains invalid.

Applications that own session identity externally may set a non-zero `TransportSecurityConfig::SessionID`. `SetConfig()` resets the outbound sequence and replay window; setting `SessionID` back to zero causes a fresh automatic session to be generated on the next protected send.

The session ID is not a secret. Its security role comes from being authenticated as AEAD associated data.

## Algorithm Resolution

`AeadCipherRegistry` maps `AeadAlgorithm` to `IAeadCipher` instances. A transmitter selects `TransportSecurityConfig::OutboundAlgorithm`; a receiver resolves the algorithm carried in each authenticated envelope.

This permits controlled algorithm migration without changing the concrete transport or higher-level protocol.

## Key Resolution

`IKeyProvider` resolves `keyId + algorithm` to key material. Receivers can retain multiple key IDs during rotation while transmitters select one outbound key ID.

The included `StaticKeyProvider` is suitable for examples and simple deployments. Production applications can provide secure-storage-backed implementations without changing `TransportSecurity`.

## Security Policies

- `Disabled`: plaintext send/receive.
- `Preferred`: protect when possible, but permit plaintext interoperability.
- `Required`: refuse unprotected outbound operation and reject inbound plaintext.

Do not use `Preferred` where plaintext acceptance violates the security model.

## Replay Protection

Authenticated sender ID, key ID, session ID and 64-bit sequence are used by `ReplayWindow`.

Replay state is committed only after successful AEAD authentication and protocol validation, preventing unauthenticated packets from advancing the replay window. The default window is 64 packets and permits limited legitimate out-of-order delivery while rejecting duplicates and stale sequences within each sender/key/session domain.

## Concrete Transport Integration

A concrete library can expose or adapt its send/receive surface to `ITransportSecurityCarrier`:

```cpp
class Adapter : public Security::ITransportSecurityCarrier {
public:
    bool Send(uint8_t protocol, const uint8_t* data, std::size_t size) override;
    void SetReceiver(Receiver receiver) override;
};
```

It can then use:

```cpp
Security::SecureTransportDecorator secured(adapter, transportSecurity);
```

Higher-level protocol code consumes the decorator's authenticated receiver rather than the raw carrier receiver.

## Failure Handling

A packet is not delivered upward when any of the following occurs:

- malformed envelope;
- unsupported envelope version;
- unavailable algorithm;
- unavailable/wrong-length key;
- invalid zero session/sequence identifier;
- AEAD authentication failure;
- protocol mismatch;
- replay/stale sequence;
- Required-policy plaintext rejection;
- configured payload limit violation.

`SecurityResult` communicates the reason without exposing secret material.

## Key / Nonce / Session Operational Rules

- Never log or serialize key bytes.
- Provision production keys outside source control.
- Rotate keys according to application risk and lifetime.
- Ensure the configured random source is appropriate for cryptographic nonce and automatic session-ID generation.
- Treat sender IDs as stable security identities for replay-domain separation, not merely display labels.
- Do not deliberately reuse the same explicit session ID after resetting its sequence unless receiver replay state has also been safely reset or expired by application policy.
- Consider secure boot, flash encryption and protected key storage as complementary platform controls.

## Downstream Direction

The intended next integrations are optional wrappers in ESPressio ESP-Now and ESPressio Sockets. Event, Command and Timing should remain unaware of the cryptographic implementation; they should simply receive authenticated plaintext from the secured transport boundary.
