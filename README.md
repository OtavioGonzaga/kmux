# kmux

`kmux` runs one command with a filtered view of an existing SSH agent. It never reads, exports, or persists private keys.

## Status

The project is Linux-only and pre-release. Validate its behavior with your upstream agent before relying on it for production access.

## Configuration

Use `--config`, `KMUX_CONFIG`, or `$XDG_CONFIG_HOME/kmux/config.yaml`. YAML, JSON, and TOML use the same schema.

```yaml
version: 1
agents:
  primary:
    type: unix
    socket: /run/user/1000/ssh-agent.sock
keys:
  company-production:
    fingerprint: "SHA256:replace-with-public-fingerprint"
    agent: primary
    scopes: [company/production]
```

## Commands

```bash
kmux --config config.yaml config check
kmux --config config.yaml doctor
kmux --config config.yaml keys
kmux --config config.yaml scopes
kmux --config config.yaml import agent primary --format yaml
kmux --config config.yaml exec company/production -- ssh deploy@example.com
```

`exec` creates a temporary Unix socket, passes it to the child only through `SSH_AUTH_SOCK`, and removes it after the child exits. A parent scope matches keys declared in that scope and descendant scopes; a child scope does not implicitly select ancestor keys.

## Security

- Private keys stay in the upstream agent.
- Only selected public-key blobs are listed and authorized for signing.
- Mutable and unknown agent operations fail closed.
- Each downstream connection receives a distinct upstream connection.
- `session-bind@openssh.com` is forwarded on that connection; unsupported extensions are rejected.

## Limitations

Agent forwarding and `session-bind` require upstream-agent support. Bitwarden and other upstream integrations must be validated manually before production use.
