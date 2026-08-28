# Random Sources and Entropy

Security obtains nonce material through `IRandomSource` rather than directly from a target SDK.

For normal platform integration, `SystemEntropyRandomSource` adapts the installed ESPressio System entropy capability to the Security interface.

## Cryptographic suitability

Security does not merely require arbitrary pseudo-random bytes. The installed System entropy provider must declare itself suitable for cryptographic use before `SystemEntropyRandomSource` accepts it.

This keeps target-specific random-number generation outside the Security library while retaining an explicit security requirement at the boundary.

## Startup ordering

Install the target's ESPressio System providers before Security first needs to generate a nonce.

## Custom sources

A test harness, hardware security module, or specialised platform can provide another `IRandomSource` implementation. See [Implementing Random Sources](Implementing-Random-Sources).