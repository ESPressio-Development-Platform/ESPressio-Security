# ESPressio Dependency Chart — Security 0.4.2 / Current Released Generation

![ESPressio Library Dependency Chart](ESPRESSIO_DEPENDENCY_CHART.svg)

## Security dependency position

```text
Security 0.4.2
    -> Observable main

Security Event integration
    - - -> Event main
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
    - - -> Serializable main
            protected persistence reaches Security through Serializable's protection API

Sockets
    - - -> Security main

ESP-Now
    - - -> Security main

WiFi
    - - -> Security main

Serial
    - - -> Security main
```

Security owns cryptographic policy and implementation abstractions. Serializable may opt into Security; Security must not depend back on Serializable. Serial remains terminal/downstream; ESPressio Tree remains standalone.
