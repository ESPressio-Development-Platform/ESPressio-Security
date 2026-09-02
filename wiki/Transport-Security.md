# Transport Security

`TransportSecurity` is ESPressio Security's transport-neutral protection layer for opaque Event, Command, State, and protocol payloads.

It adds more than encryption. The protected transport envelope binds protocol identity, sender/session identity, monotonically increasing sequence information, and replay protection on top of authenticated encryption.

## Security policy

Transport integrations can operate under the policies documented in [Security Policies](Security-Policies).

For traffic that is required to be confidential and authenticated, use `Required` rather than relying on opportunistic protection.

## Carrier integration

`SecureTransportDecorator` can wrap an `ITransportSecurityCarrier`, allowing a transport library to remain responsible for its own delivery mechanics while Security owns the cryptographic envelope and replay/session semantics.

`ITransportSecurityObserver` exposes security lifecycle notifications. Optional Event integration can translate those observations into ESPressio Event without making Event a required Security dependency.

## Replay protection

Receiving a cryptographically valid packet is not sufficient if an attacker can replay an earlier valid packet. Transport Security maintains sequence/session state to reject replayed traffic according to the protocol contract.

Transport authors should continue with [Integrating Secure Transports](Integrating-Secure-Transports).