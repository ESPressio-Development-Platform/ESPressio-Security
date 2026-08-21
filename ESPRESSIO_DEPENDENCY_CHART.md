# ESPressio Dependency Chart — Security 0.3.0

![ESPressio Library Dependency Chart](ESPRESSIO_DEPENDENCY_CHART.svg)

## Security 0.3.0

```text
Security 0.3.0
    -> Observable >= 3.0.1 < 4.0.0
    - - -> Event >= 6.0.0 < 7.0.0
            Security Event types / TransportSecurityEventBridge only
```

The Event relationship is opt-in. Core Security remains Event-free and transport-neutral.

## Final coordinated ecosystem

```text
Observable 3.0.1
Serializable 0.10.2
Units 0.2.3
Timing 2.2.4
Threads 3.1.4
Command 0.4.0
Security 0.3.0
Event 6.0.0
Sockets 0.6.0
ESP-Now 0.6.0
Serial 0.6.0
```

Security owns its Security-specific Event bridge. Event 6.0.0 does not depend back on Security, so no reciprocal edge remains.
