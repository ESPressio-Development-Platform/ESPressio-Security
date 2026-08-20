# ESPressio Library Dependency Chart

ESPressio Security is a foundational, transport-neutral library.

## ESPressio Security 0.1.0

**Required ESPressio dependencies: none.**

Security owns authenticated encryption, key lookup, security envelopes, replay protection and transport-security policy. It deliberately does not depend on concrete communication libraries.

The intended opt-in dependency direction is:

```text
ESPressio ESP-Now  - - -> ESPressio Security
ESPressio Sockets  - - -> ESPressio Security
future transports  - - -> ESPressio Security
```

Higher-level protocols remain independent of cryptography:

```text
Event / Command / Clock Synchronization / application protocol
                         |
                         v
                Secure transport adapter
                         |
                         v
                 ESPressio Security
                         |
                         v
                concrete transport
```

Security therefore sits beside other foundational ESPressio facilities rather than beneath Event, Command, ESP-Now, or Sockets as a mandatory dependency.

## Architectural rule

Security is applied at the transport boundary. A received protected packet is authenticated and decrypted before its plaintext is delivered to the protocol consumer. Packets failing authentication, policy, protocol binding, envelope validation or replay checks are discarded before application processing.
