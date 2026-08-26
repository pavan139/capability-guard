# Host policy boundary

The trusted host chooses exact resource IDs, scopes, and budgets when calling `Authority.issue`. `Operation.from_dict` accepts only fields belonging to an allowlisted note operation. These notes are not a policy loader or a source of permissions for model text.

A request shape suitable for validation is:

```json
{"kind":"note:append","resource":"lab/public","text":"bounded text"}
```

The bearer credential and a fresh 128-bit nonce are supplied separately. Issuer keys, bearer values, and local databases do not belong in this directory.
