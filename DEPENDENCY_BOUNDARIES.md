# ESPressio Security Dependency Boundaries

ESPressio Security owns Security-specific lifecycle semantics and their optional Event representation.

The core Security mechanism depends on Observable and remains independent of ESPressio Event. `TransportSecurityEventBridge` and the Security Event family are optional integration headers owned by Security and may depend on Event only when explicitly selected.

The normal Security umbrella must remain free of Event includes.
