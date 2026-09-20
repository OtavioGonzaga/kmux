# Getting Started

This tutorial configures kmux around an SSH agent that already holds the private keys. It uses Bitwarden as an example only; any compatible Unix-socket SSH agent works.

## 1. Install kmux

Install with Cargo, a release asset, or from source as described in [installation](installation.md). Confirm the binary is available:

```bash
kmux --version
```

## 2. Create Configuration

Create the default TOML configuration at `~/.config/kmux/config.toml`:

```bash
kmux init
```

Use `kmux init --format yaml` or `--format json` only when a different format is needed. TOML is recommended for hand-edited configuration.

## 3. Add An Upstream Agent

An upstream agent owns private keys and accepts SSH Agent protocol requests on a Unix socket. Register its socket with a local name:

```bash
kmux agent add bitwarden \
  --socket /run/user/1000/bitwarden-ssh-agent.sock
```

The socket path must be absolute. `kmux` stores the path; it does not start the agent or copy keys from it. See [agents](agents.md) to use `SSH_AUTH_SOCK` with OpenSSH's agent.

## 4. Import Public Identities

Ask the upstream agent for its public identities and write them to local configuration:

```bash
kmux import agent bitwarden --scope personal
```

`--scope personal` classifies every imported key. Existing fingerprints are skipped. Import is the easiest way to start; `kmux key add` is available for manually managed public identities.

Preview an import without changing a file:

```bash
kmux import agent bitwarden --scope personal --dry-run
```

## 5. Inspect The Catalog

Keys and scopes come from local configuration. These commands do not contact the agent:

```bash
kmux keys
kmux keys --scope personal
kmux scopes
```

## 6. Run A Filtered Command

Run a child process through a temporary filtered agent:

```bash
kmux --scope personal -- ssh user@example.com
```

Only matching configured public identities are advertised to `ssh`. To use a particular alias instead, run:

```bash
kmux --key github-personal -- git fetch
```

If several keys match, kmux prompts on the controlling terminal. Add filters to narrow the result, or use a terminal to choose. [Selection](selection.md) explains the matching rules.

## Next Steps

- Read [configuration](configuration.md) before editing the file directly.
- Use [CLI reference](cli.md) for all commands.
- Run `kmux doctor` when the agent or configuration is not working as expected.
