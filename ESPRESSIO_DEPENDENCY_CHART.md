# ESPressio Dependency Chart — Security 0.4.2 / Current Released Generation

![ESPressio Library Dependency Chart](ESPRESSIO_DEPENDENCY_CHART.svg)

## Security dependency position

```text
Security 0.4.2
    -> Observable >= 3.0.2 < 4.0.0

Security Event integration
    - - -> Event >= 6.0.3 < 7.0.0
```

`IDataProtector` / `DataProtector` introduces no additional required dependency. Security remains independent of Serializable, Persistence, WiFi, Sockets, ESP-Now, Command and Serial.

## Current released generation

```text
Observable    3.0.2
Serializable  0.11.3
Units         0.2.7
Timing        2.2.8
Threads       3.1.7
Event         6.0.3
Command       1.0.3
Security      0.4.2
Persistence   0.3.2
Sockets       0.7.3
ESP-Now       0.8.3
WiFi          0.2.0
Serial        0.8.1
```

## Downstream Security integrations

```text
Persistence
    - - -> Serializable >= 0.11.3 < 1.0.0
            protected persistence reaches Security through Serializable's protection API

Sockets
    - - -> Security >= 0.4.2 < 1.0.0

ESP-Now
    - - -> Security >= 0.4.2 < 1.0.0

WiFi
    - - -> Security >= 0.4.2 < 1.0.0

Serial
    - - -> Security >= 0.4.2 < 1.0.0
```

Security owns cryptographic policy and implementation abstractions. Serializable may opt into Security; Security must not depend back on Serializable. Serial remains terminal/downstream; ESPressio Tree remains standalone.
