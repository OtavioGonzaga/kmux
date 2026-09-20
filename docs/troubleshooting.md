# Troubleshooting

Start with the configuration and agent diagnostics:

```bash
kmux config check
kmux doctor
kmux keys
```

## Too Many Authentication Failures

The remote server may reject a client before it reaches the intended key. Select
one identity or a narrow scope:

```bash
kmux --key deploy-production -- ssh deploy@example.com
kmux --scope production -- ssh deploy@example.com
```

## No Configured Identities Match

Inspect local entries and filters:

```bash
kmux keys
kmux keys --scope production
kmux scopes
```

Import the current public identities if the desired key is absent:
`kmux import agent NAME --scope SCOPE`.

## Multiple Identities Match

Explicit filters authorize every available matching identity from one upstream
agent, so several matches are not an error for commands such as:

```bash
kmux --scope personal -- git fetch
```

Add `--select` and run from a terminal to choose a subset. Without filters,
several candidates require a terminal for interactive selection; otherwise add
`--key`, `--agent`, `--tag`, `--comment`, or a narrower `--scope`.

## Matches Span Multiple Upstream Agents

A filtered command can delegate identities from only one upstream agent. If kmux
reports `matched identities span multiple upstream agents`, constrain the set
explicitly:

```bash
kmux --scope personal --agent bitwarden -- git fetch
```

Alternatively, run with `--select` from a terminal to choose an agent and then
an identity subset.

## Agent Socket Unavailable

Confirm the configured absolute path exists and the process can access it. For
OpenSSH, compare it with `printf '%s\n' "$SSH_AUTH_SOCK"`. Then update the agent
with the new socket if necessary. `kmux keys` remains available because it reads
only configuration.

## Unknown Agent

`--agent NAME` and commands that name an agent require a configured name. List
the configuration or add it first:

```bash
kmux agent add NAME --socket /absolute/path/to/agent.sock
```

## Ambiguous Configuration Files

Discovery errors when several `config.toml`, `config.yaml`, `config.yml`, or
`config.json` files exist. Remove or rename unused files, or pass
`--config /path/to/config.toml`.

## Invalid Fingerprint

Fingerprints must use canonical `SHA256:` form. Prefer `kmux import agent NAME`,
which reads public identities directly, instead of transcribing a fingerprint.

## SSH_AUTH_SOCK And Non-Interactive Commands

kmux sets `SSH_AUTH_SOCK` only for its child process. Do not export the
temporary socket yourself. In CI or pipelines, provide filters that resolve to
one upstream agent; they may authorize multiple matching keys. Do not use
`--select` in a non-interactive environment, and add filters when unfiltered
execution would require a selection.
