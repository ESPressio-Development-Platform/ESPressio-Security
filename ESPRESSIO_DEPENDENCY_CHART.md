# ESPressio Dependency Chart — Security / Current Released Generation

![ESPressio Library Dependency Chart](ESPRESSIO_DEPENDENCY_CHART.svg)

## Security dependency position

```text
Security
    -> Observable main

Security Event integration
    - - -> Event main
```

`IDataProtector` / `DataProtector` introduces no additional required dependency. Security remains independent of Serializable, Persistence, WiFi, Sockets, ESP-Now, Command and Serial.

## Current released generation

```text
Observable
Serializable
Units
Timing
Threads
Event
Command
Security
Persistence
Sockets
ESP-Now
WiFi
Serial
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
