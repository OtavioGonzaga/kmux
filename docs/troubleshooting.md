# Troubleshooting

Start with the configuration and agent diagnostics:

```bash
kmux config check
kmux doctor
kmux keys
```

## Too Many Authentication Failures

The remote server may reject a client before it reaches the intended key. Select one identity or a narrow scope:

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

Import the current public identities if the desired key is absent: `kmux import agent NAME --scope SCOPE`.

## Multiple Identities Match

Run from a terminal to use the chooser, or add `--key`, `--agent`, `--tag`, `--comment`, or a narrower `--scope`. Non-interactive commands cannot choose among several candidates.

## Agent Socket Unavailable

Confirm the configured absolute path exists and the process can access it. For OpenSSH, compare it with `printf '%s\n' "$SSH_AUTH_SOCK"`. Then update the agent with the new socket if necessary. `kmux keys` remains available because it reads only configuration.

## Unknown Agent

`--agent NAME` and commands that name an agent require a configured name. List the configuration or add it first:

```bash
kmux agent add NAME --socket /absolute/path/to/agent.sock
```

## Ambiguous Configuration Files

Discovery errors when several `config.toml`, `config.yaml`, `config.yml`, or `config.json` files exist. Remove or rename unused files, or pass `--config /path/to/config.toml`.

## Invalid Fingerprint

Fingerprints must use canonical `SHA256:` form. Prefer `kmux import agent NAME`, which reads public identities directly, instead of transcribing a fingerprint.

## SSH_AUTH_SOCK And Non-Interactive Commands

kmux sets `SSH_AUTH_SOCK` only for its child process. Do not export the temporary socket yourself. In CI or pipelines, provide filters that resolve to exactly one key; otherwise selection fails rather than guessing.
