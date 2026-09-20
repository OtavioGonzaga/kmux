# Security

kmux reduces which configured SSH identities a child process can discover and request signatures from. It is not a key store or a replacement for upstream-agent, host, or account security.

## Current Guarantees

- Private keys remain in the upstream agent. Configuration contains public fingerprints, local metadata, and socket paths only.
- `REQUEST_IDENTITIES` responses expose only authorized public-key blobs.
- `SIGN_REQUEST` is reauthorized against the allowed public key before forwarding.
- A key known to configuration but hidden by the selection cannot be used through the proxy.
- Mutable agent operations are blocked. Unknown, malformed, and unsupported operations fail closed.
- Only a valid `session-bind@openssh.com` request is forwarded; other extensions are rejected.
- Each downstream proxy connection opens its own upstream connection.
- The per-execution proxy socket is created in a private runtime directory, passed to the child as `SSH_AUTH_SOCK`, and removed during cleanup.
- Shutdown closes active downstream and upstream connections before removing the socket.
- Agent comments are untrusted input. kmux stores imported comments as local display and filter metadata; do not treat them as authorization data.
- Logging should not include private-key material, credentials, or sensitive command arguments.

## What kmux Does Not Protect

kmux does not prove that the upstream agent, child process, local machine, socket directory, or remote host is trustworthy. A selected child can ask the authorized upstream agent to sign for the selected public identity. kmux does not restrict what a remote service does after authentication, protect commands from shell injection, synchronize vault metadata, or guarantee SSH forwarding support from every upstream agent.

Validate agent forwarding, permissions, and remote access policies independently before production use.
