# Configuration

kmux uses one configuration document with schema `version = 1`. TOML is the recommended format; YAML (`.yaml` or `.yml`) and JSON use the same schema.

## Location And Discovery

kmux uses the first explicit source in this order:

1. `--config PATH`
2. `KMUX_CONFIG`
3. `$XDG_CONFIG_HOME/kmux/`
4. `$HOME/.config/kmux/`

At a discovered directory it considers `config.toml`, `config.yaml`, `config.yml`, and `config.json`. No format wins over another: multiple existing candidates are an error. Use `--config` to select one explicitly. Input and serialized output are limited to 1 MiB.

## TOML Schema

```toml
# Current kmux configuration schema version.
version = 1

# An upstream SSH agent identified locally as bitwarden.
[agents.bitwarden]
type = "unix"

# Absolute Unix socket exposed by that agent.
socket = "/run/user/1000/bitwarden-ssh-agent.sock"

# A public SSH identity known to kmux.
[keys.aws-production]

# Canonical SHA-256 fingerprint of the public key.
fingerprint = "SHA256:replace-with-a-public-key-fingerprint"

# The configured upstream agent that will sign for this key.
agent = "bitwarden"

# Optional hierarchical scopes. Parent filters match descendants.
scopes = ["hogix/production"]

# Optional local text used by --comment. It is not an agent query.
comment = "AWS production"

# Optional metadata matched by repeated --tag key=value filters.
[keys.aws-production.tags]
provider = "aws"
environment = "production"

# A key may omit scopes and remain selectable by alias or the chooser.
[keys.github-personal]
fingerprint = "SHA256:replace-with-another-public-key-fingerprint"
agent = "bitwarden"
```

Agent names, aliases, scope segments, and tag keys and values are validated. Names and scope segments are normalized to lowercase. Agent sockets must be absolute. Keys must reference configured agents, and aliases and fingerprints must be unique. Use `kmux config check` after manual edits.

## Managing Configuration

`kmux init` creates a minimal document and is idempotent when a supported configuration already exists. `agent add`, `agent remove`, `key add`, `key remove`, and `import agent` validate the complete document before atomically replacing it. Writes use private file permissions.

YAML supports bounded anchors and aliases, but rejects duplicate keys, merge keys, and multiple documents. Choose TOML unless interoperability requires YAML or JSON.
