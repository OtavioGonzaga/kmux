# Upstream Agents

An upstream agent is an existing process that implements the SSH Agent protocol
on a Unix socket and owns the private keys. kmux records its socket path,
retrieves public identities when importing, and forwards authorized signing
requests. It does not store or export private keys.

## Register A Socket

```bash
kmux agent add primary --socket /run/user/1000/ssh-agent.sock
```

The path must be absolute. `kmux agent remove primary` refuses to remove an
agent referenced by configured keys.

## OpenSSH Agent

OpenSSH commonly exposes its current socket in `SSH_AUTH_SOCK`:

```bash
printf '%s\n' "$SSH_AUTH_SOCK"
kmux agent add openssh --socket "$SSH_AUTH_SOCK"
kmux import agent openssh --scope work
```

Check that the variable is set in the shell that started the agent. A socket can
disappear after logout or an agent restart; update the configured path if it
changes.

## Bitwarden Example

Bitwarden can be used when it exposes a compatible Unix socket:

```bash
kmux agent add bitwarden --socket /run/user/1000/bitwarden-ssh-agent.sock
kmux import agent bitwarden --scope personal
```

The socket location and forwarding support depend on the upstream application.
Validate behavior in your environment. kmux does not implement Bitwarden folder
synchronization or vault metadata integration.
