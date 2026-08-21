# ESPressio Security

Transport-neutral authenticated encryption, authentication, replay protection, and security policy for the Flowduino ESPressio Development Platform.

## Current Version — 0.3.0

Security 0.3.0 owns the optional Event representation of its own transport-security lifecycle. The Security core remains independent of ESPressio Event; Event is acquired only when the application explicitly selects the Security Event integration.

## Core dependency

```text
Security 0.3.0
    -> Observable >= 3.0.1 < 4.0.0
```

Security remains independent of ESP-Now, Sockets, Command, Serial, and Event at the core layer.

## Optional Event integration

Security 0.3.0 provides:

```cpp
#include <ESPressio_SecurityEvents.hpp>
#include <ESPressio_TransportSecurityEventBridge.hpp>
```

The integration requires:

```text
ESPressio Event >= 6.0.0 < 7.0.0
```

and converts `ITransportSecurityObserver` notifications into asynchronous Event types for configuration, session, replay-protection, and failure lifecycle changes.

The public header and class names remain unchanged from their previous location in ESPressio Event; ownership now matches the Security domain.

## Dependency direction

```text
Security core
    -> Observable

Security Event integration
    - - -> Event
```

Event 6.0.0 does not depend back on Security. The standard `ESPressio_Security.hpp` umbrella does not include the Event integration.

## Final coordinated generation

```text
Observable    3.0.1
Serializable  0.10.2
Units         0.2.3
Timing        2.2.4
Threads       3.1.4
Command       0.4.0
Security      0.3.0
Event         6.0.0
Sockets       0.6.0
ESP-Now       0.6.0
Serial        0.6.0
```

See [TRANSPORT_SECURITY.md](TRANSPORT_SECURITY.md) for the transport-security model, [ESPRESSIO_DEPENDENCY_CHART.md](ESPRESSIO_DEPENDENCY_CHART.md) for dependency relationships, and [CHANGELOG.md](CHANGELOG.md) for release history.

## License

Apache License 2.0. See [LICENSE](LICENSE).
