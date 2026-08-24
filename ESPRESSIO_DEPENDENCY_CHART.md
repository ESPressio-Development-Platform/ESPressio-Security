# ESPressio Dependency Chart — Security 0.4.2

![ESPressio Library Dependency Chart](ESPRESSIO_DEPENDENCY_CHART.svg)

Arrows point from a consuming library to the ESPressio library it consumes. Solid arrows are required dependencies; dashed arrows are opt-in integrations.

## Security 0.4.2

```text
Security 0.4.2
    -> Observable >= 3.0.2 < 4.0.0

Security Event integration
    - - -> Event >= 6.0.3 < 7.0.0
```

`IDataProtector` / `DataProtector` introduces no additional required dependency. It deliberately reuses Security-owned AEAD, key-provider and random-source abstractions.

## Serializable 0.11.3 cascade generation

```text
Observable    3.0.2
Serializable  0.11.3
Units         0.2.7
Timing        2.2.8
Threads       3.1.7
Event         6.0.3
Command       1.0.3
Security      0.4.2
```

## Downstream cascade

After Security 0.4.2, libraries with Security integrations can consume the completed Event fan-out generation without introducing reverse dependencies:

```text
Persistence
    - - -> Serializable >= 0.11.3 < 1.0.0
    - - -> Security >= 0.4.2 < 1.0.0

Sockets
    - - -> Event >= 6.0.3 < 7.0.0
    - - -> Command >= 1.0.3 < 2.0.0
    - - -> Security >= 0.4.2 < 1.0.0

ESP-Now
    - - -> Event >= 6.0.3 < 7.0.0
    - - -> Command >= 1.0.3 < 2.0.0
    - - -> Security >= 0.4.2 < 1.0.0
```

Security itself remains independent of Serializable, Persistence, WiFi, Sockets, ESP-Now, Command and Serial.

## Dependency-direction invariants

- Security owns cryptographic policy and implementation abstractions.
- Serializable may opt into Security; Security must not depend back on Serializable.
- Persistence may consume protected Serializable APIs; Security must not depend on Persistence.
- WiFi may use lower-order capabilities, but Security must remain unaware of WiFi.
- Serial remains terminal/downstream; no upstream ESPressio library should depend on Serial.
