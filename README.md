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

TOML is the recommended configuration format. Use `--config`, `KMUX_CONFIG`, or one of `$XDG_CONFIG_HOME/kmux/config.toml`, `config.yaml`, `config.yml`, or `config.json`. TOML, YAML, YML, and JSON use the same schema. Configuration files are limited to 1 MiB; YAML accepts anchors and aliases, but rejects duplicate keys and multiple documents.

```toml
version = 1

[agents.primary]
type = "unix"
socket = "/run/user/1000/ssh-agent.sock"

[keys.company-production]
fingerprint = "SHA256:replace-with-public-fingerprint"
agent = "primary"
scopes = ["company/production"]
```

## Commands

```bash
kmux --config config.toml config check
kmux --config config.toml doctor
kmux --config config.toml keys
kmux --config config.toml scopes
kmux init
kmux agent add primary --socket /run/user/1000/ssh-agent.sock
kmux key add company-production --agent primary --fingerprint SHA256:replace-with-public-fingerprint --scope company/production
kmux --config config.toml import agent primary --scope company/production
kmux --config config.toml -s company/production ssh deploy@example.com
```

`scopes` lists configured scopes and their derived ancestors, in sorted order. `import agent` imports public identities into the configuration by default, skipping fingerprints that are already present. It stores the public agent comment as local key metadata for display and `--comment` filtering. Use `--dry-run` to preview changes without writing, or `--stdout` to emit a TOML/YAML/JSON configuration snippet without writing. Aliases are derived deterministically from public agent comments.

`kmux init` creates a minimal TOML configuration by default and is idempotent when a supported configuration already exists. `agent add` and `key add` validate the complete configuration before replacing it atomically. Run `key add ALIAS` without data flags to choose a configured agent and public identity interactively; supplying any key data flag requires both `--agent` and `--fingerprint` and never prompts.

`kmux [FILTERS] [--] COMMAND...` creates a private, per-execution temporary directory for its Unix socket, passes it to the child only through `SSH_AUTH_SOCK`, and removes it after the child exits. The `--` separator is optional. Without filters, it considers every configured key. A parent scope matches keys declared in that scope and descendant scopes; a child scope does not implicitly select ancestor keys. When more than one key matches, `kmux` selects through the controlling terminal when one is available (including when command output is piped); otherwise it reports the candidate list. The child exit code is preserved. `kmux exec -s company/production [--] COMMAND...` remains available as the explicit form.

## Security

- Private keys stay in the upstream agent.
- Only selected public-key blobs are listed and authorized for signing.
- Mutable and unknown agent operations fail closed.
- Each downstream connection receives a distinct upstream connection.
- `session-bind@openssh.com` is forwarded on that connection; unsupported extensions are rejected.
- Shutting down the proxy closes active downstream and upstream connections before removing its socket.

## Limitations

Agent forwarding and `session-bind` require upstream-agent support. The automated OpenSSH coverage verifies `ssh-add -L` and `ssh-add -T`; full `ssh -A` forwarding remains a manual integration check. To verify it against a host that accepts forwarding, run `kmux -s <scope> -- ssh -A <host> ssh-add -L` and confirm only the selected public key is listed. Bitwarden and other upstream integrations must be validated manually before production use.

## License

MIT
