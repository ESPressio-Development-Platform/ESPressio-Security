# Security Policies

Transport integrations use one of three explicit policies:

| Policy | Behaviour |
| --- | --- |
| `Disabled` | Security is not applied. |
| `Preferred` | Secure transport is used when the integration can establish it, but insecure operation remains permitted by policy. |
| `Required` | Traffic must satisfy the secure transport contract; insecure fallback is not acceptable. |

## Choosing a policy

Use `Required` whenever confidentiality, authenticity, replay resistance, or protocol binding is a real requirement of the application.

`Preferred` is suitable only when the product explicitly accepts communication that may remain unprotected under some conditions.

`Disabled` should be an intentional application or testing choice, not an accidental result of missing configuration.

## Integration rule

Transport libraries should surface policy failure clearly. They must not silently downgrade `Required` traffic to insecure delivery.