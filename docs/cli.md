# CLI Reference

Run `kmux --help` or `kmux COMMAND --help` for the authoritative argument
syntax. This reference explains when to use each command.

## Execution

```bash
kmux [FILTERS] [--] COMMAND...
kmux exec [FILTERS] -- COMMAND...
```

Both forms resolve configured keys, create a private filtered agent for the
child, set its `SSH_AUTH_SOCK`, and preserve the child exit code. `--` is
optional in the root form, but useful to separate child arguments beginning with
`-`. Root filters cannot precede subcommands other than direct execution; use
`kmux exec` for an explicit form.

```bash
kmux --scope production -- ssh deploy@example.com
kmux exec --key github-personal -- git fetch
kmux --tag environment=staging -- rsync -av ./ site:/srv/site/
```

Filters are `--scope`, `--comment`, `--key`, `--fingerprint`, repeatable
`--tag KEY=VALUE`, and `--agent`. See [selection](selection.md).

## Initialize

```bash
kmux init [--format toml|yaml|json] [--force]
```

Creates a minimal configuration. TOML is the default. Existing valid discovered
configuration makes this command a no-op; `--force` replaces it.

## Agents

```bash
kmux agent add NAME --socket /absolute/path/to/agent.sock
kmux agent remove NAME
```

`add` records a Unix-socket upstream agent. `remove` refuses when configured
keys still reference the agent.

## Keys

```bash
kmux key add ALIAS [--agent NAME --fingerprint SHA256:...] \
  [--comment TEXT] [--scope SCOPE]... [--tag KEY=VALUE]...
kmux key remove ALIAS [--yes]
kmux keys [FILTERS]
```

Run `key add ALIAS` with no key data flags to interactively choose an available
public identity. When any key data flag is supplied, both `--agent` and
`--fingerprint` are required and no prompt is shown. `key remove` asks for
confirmation unless `--yes` is supplied.

`kmux keys` lists alias, fingerprint, agent, and comma-separated scopes from
local configuration. It accepts the execution filters, does not contact an
upstream agent, and reports an unknown `--agent` name as an error.

## Import

```bash
kmux import agent NAME [--scope SCOPE]... [--tag KEY=VALUE]...
  [--dry-run | --stdout [--format toml|yaml|json]]
```

Imports public identities from a configured agent. Existing fingerprints are
skipped and aliases are derived deterministically from public comments. Imported
comments become local metadata for display and `--comment`; they are not
dynamically queried later. `--dry-run` previews mutations without writing.
`--stdout` renders a configuration snippet, and `--format` is valid only with
`--stdout`.

## Inspect And Diagnose

```bash
kmux scopes
kmux doctor
kmux config check
```

`scopes` lists sorted configured scopes and their ancestors. Keys without scopes
are omitted. `doctor` checks configuration and configured agents. `config check`
loads and validates the configuration, printing `configuration is valid` on
success.

## Configuration Path

Every command except `init` can use `--config PATH` to select a document
directly. Without it, use `KMUX_CONFIG` or normal XDG discovery as described in
[configuration](configuration.md).
