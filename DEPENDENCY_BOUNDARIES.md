# ESPressio Security Dependency Boundaries

ESPressio Security owns Security-specific lifecycle semantics and their optional Event representation.

The core Security mechanism depends on ESPressio Observable (`>=3.0.2 <4.0.0`) and remains independent of ESPressio Event. `TransportSecurityEventBridge` and the Security Event family are optional integration headers owned by Security and may depend on Event only when explicitly selected.

Security 0.4.2 validates that optional integration against released ESPressio Event 6.0.3 and its released Serializable 0.11.3 cascade generation.

The normal Security umbrella must remain free of Event includes. Security remains independent of Serializable, Persistence, WiFi, Sockets, ESP-Now, Command and Serial.
