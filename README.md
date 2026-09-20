# kmux

`kmux` runs a command with a filtered view of an existing SSH agent. It is useful when an upstream agent exposes many SSH identities and clients such as OpenSSH try more identities than a remote server permits.

`kmux` never reads, exports, or stores private keys. It proxies the SSH Agent protocol and presents only selected configured public identities to the child process.

## Quick Start

```bash
# Install the crate named ssh-kmux; its executable is named kmux.
cargo install ssh-kmux --locked

# Create ~/.config/kmux/config.toml.
kmux init

# Register the Unix socket supplied by an existing SSH agent.
kmux agent add bitwarden --socket /run/user/1000/bitwarden-ssh-agent.sock

# Import that agent's public identities and classify them for selection.
kmux import agent bitwarden --scope personal

# Inspect the local catalog before using it.
kmux keys

# Run OpenSSH with only identities in the personal scope exposed.
kmux --scope personal -- ssh user@example.com
```

The upstream agent can be Bitwarden, `ssh-agent`, or another compatible Unix-socket agent. See the [getting started guide](docs/getting-started.md) for an explained workflow.

## Installation

- [Cargo, Debian/Ubuntu, tarball, and source installation](docs/installation.md)
- [Latest GitHub Release](https://github.com/OtavioGonzaga/kmux/releases/latest)
- [Rust API on docs.rs](https://docs.rs/ssh-kmux)

The package is `ssh-kmux`, the binary is `kmux`, and the minimum supported Rust version is 1.89. Linux is the supported platform.

## Basic Usage

```bash
# Validate the discovered configuration and upstream agents.
kmux doctor

# List configured keys locally; this never contacts an agent.
kmux keys --scope company --tag environment=production

# List scopes, including derived ancestors.
kmux scopes

# Filter command execution by scope, local comment, and tags.
kmux --scope company --comment aws --tag environment=production -- ssh deploy@example.com

# The explicit form is useful when a wrapper needs an unambiguous subcommand.
kmux exec --key github-personal -- git fetch
```

Filters are combined with AND. A parent scope matches keys in descendant scopes. See [selection](docs/selection.md) and the complete [CLI reference](docs/cli.md).

## Configuration

TOML is the recommended configuration format:

```toml
version = 1

[agents.primary]
type = "unix"
socket = "/run/user/1000/ssh-agent.sock"

[keys.company-production]
fingerprint = "SHA256:replace-with-a-public-key-fingerprint"
agent = "primary"
scopes = ["company/production"]
comment = "AWS production"

[keys.company-production.tags]
provider = "aws"
environment = "production"
```

The [configuration reference](docs/configuration.md) documents discovery, validation, YAML and JSON support, and every field.

## Security Model

- Private keys stay in the upstream agent; only public identities are stored in configuration.
- The proxy lists only selected public-key blobs and reauthorizes signing requests for them.
- Mutable, malformed, unknown, and unsupported protocol operations fail closed.
- Each downstream connection receives a separate upstream connection and a private runtime socket.

Read [security](docs/security.md) before relying on kmux for production access.

## Compatibility And Limitations

kmux supports Unix-socket upstream agents on Linux. Agent forwarding and `session-bind@openssh.com` require upstream-agent support. Automated OpenSSH coverage verifies `ssh-add -L` and `ssh-add -T`; validate full `ssh -A` forwarding against your own host before production use. kmux does not synchronize Bitwarden folders, integrate with a vault CLI, or manage private keys.

## Documentation

- [Getting started](docs/getting-started.md)
- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [CLI reference](docs/cli.md)
- [Selection](docs/selection.md)
- [Upstream agents](docs/agents.md)
- [Security](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Releasing](docs/releasing.md)

## License

MIT. See [LICENSE](LICENSE).
