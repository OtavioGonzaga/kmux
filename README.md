# kmux

`kmux` runs one command with a filtered view of an existing SSH agent. It never reads, exports, or persists private keys.

## Installation

### Cargo

```bash
cargo install ssh-kmux
kmux --version
```

### Debian/Ubuntu

Download the architecture-appropriate `.deb` from the GitHub Release, then install it:

```bash
sudo dpkg -i kmux_<version>_amd64.deb
```

### Direct Download

GitHub Releases provide `kmux-linux-x86_64.tar.gz` and `kmux-linux-aarch64.tar.gz`.

```bash
curl -LO https://github.com/OtavioGonzaga/kmux/releases/latest/download/kmux-linux-x86_64.tar.gz
tar -xzf kmux-linux-x86_64.tar.gz
./kmux --version
```

## Status

The project is Linux-only and pre-release. Validate its behavior with your upstream agent before relying on it for production access.

## Configuration

Use `--config`, `KMUX_CONFIG`, or one of `$XDG_CONFIG_HOME/kmux/config.yaml`, `config.yml`, `config.json`, or `config.toml`. YAML, JSON, and TOML use the same schema. Configuration files are limited to 1 MiB; YAML accepts anchors and aliases, but rejects duplicate keys and multiple documents.

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
kmux --config config.yaml import agent primary --scope company/production --format yaml
kmux --config config.yaml exec company/production -- ssh deploy@example.com
```

`scopes` lists configured scopes and their derived ancestors, in sorted order. `import agent` emits a configuration snippet only; it derives readable, deterministic aliases from public agent comments and never changes the configuration file.

`exec` creates a private, per-execution temporary directory for its Unix socket, passes it to the child only through `SSH_AUTH_SOCK`, and removes it after the child exits. A parent scope matches keys declared in that scope and descendant scopes; a child scope does not implicitly select ancestor keys. When more than one key matches, `kmux` selects through the controlling terminal when one is available (including when command output is piped); otherwise it reports the candidate list. The child exit code is preserved.

## Security

- Private keys stay in the upstream agent.
- Only selected public-key blobs are listed and authorized for signing.
- Mutable and unknown agent operations fail closed.
- Each downstream connection receives a distinct upstream connection.
- `session-bind@openssh.com` is forwarded on that connection; unsupported extensions are rejected.
- Shutting down the proxy closes active downstream and upstream connections before removing its socket.

## Limitations

Agent forwarding and `session-bind` require upstream-agent support. The automated OpenSSH coverage verifies `ssh-add -L` and `ssh-add -T`; full `ssh -A` forwarding remains a manual integration check. To verify it against a host that accepts forwarding, run `kmux exec <scope> -- ssh -A <host> ssh-add -L` and confirm only the selected public key is listed. Bitwarden and other upstream integrations must be validated manually before production use.

## License

MIT
