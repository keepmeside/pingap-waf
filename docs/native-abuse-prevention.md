# Native abuse prevention and administration

Implementation follows the approved six-phase plan. No website is protected merely by creating a profile: attach a supported policy to a domain and check the applied version. Production deployment is separate.

## Policy writes and errors

Policy entries use `category:profile`; the complete PUT body must contain the matching category. Editors preserve all existing configuration fields, and reject a conflicting category rather than silently replacing it. The API also rejects missing/mismatched categories before any version is created.

A successful save means the projection reports `applied`. Validation/conflict/unavailable errors retain the HTTP status and provide readable text. Only HTTP401 clears the session; permission errors do not. After a network timeout the result is uncertain: reload policies/config versions and activity to reconcile before retrying; do not blindly repeat a write.

Container runtime uses a read-only root and writable `/tmp` tmpfs for candidate validation. Test harnesses own an isolated configuration, control-plane database, network and ports; they never read deployment secrets or alter existing containers.

Config PUT uses a finite20-second request timeout: the existing10-second reload verification window plus one ordinary10-second network/validation allowance. On timeout it reads config versions once, invalidates resource/version queries, and reports an unconfirmed outcome; it never retries PUT automatically or claims success from the timeout.

Login initialization checks the server's account capability list before fetching legacy raw configuration. Viewers initialize the normal console without that privileged read. Raw configuration cached by an earlier account is cleared when permission is absent or the account check fails; 401/503 errors still propagate normally. Server RBAC is unchanged.

On logout or acceptance of a new login token, clear authenticated query data and legacy raw-config state. A role change in the same SPA must not reuse an administrator's cached capabilities or configuration. Browser verification uses a private work copy and run-specific artifacts so its dependency installation cannot replace a concurrent frontend build's node_modules. Text failure artifacts redact ephemeral canary passwords.

Pending raw-config reads are scoped to the login token that started them: a response from a logged-out or replaced session cannot repopulate raw configuration or full-config text after clearing the cache.

A delayed401 from a replaced session is still returned as an error to its caller, but cannot clear the newer login token. Current-session401 behavior remains unchanged.
