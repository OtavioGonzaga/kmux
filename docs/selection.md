# Selection

kmux selects configured keys before starting a filtered proxy. The same filters are available for command execution and `kmux keys`; key listing uses only local configuration and never contacts an upstream agent.

## Filters

| Filter | Meaning |
| --- | --- |
| `-s`, `--scope SCOPE` | Match a scope and its descendants. |
| `-c`, `--comment TEXT` | Case-insensitive substring in persisted local key metadata. |
| `-k`, `--key ALIAS` | Match a configured key alias. |
| `-f`, `--fingerprint PREFIX` | Match a public-key fingerprint prefix. |
| `-t`, `--tag KEY=VALUE` | Match local tag metadata; repeat to require several tags. |
| `--agent NAME` | Restrict results to a configured upstream agent. |

All filters use AND semantics. `--agent` must name an agent in configuration; an unknown name is an error. A configured agent with no matching keys is a successful empty `kmux keys` result.

## Scope Hierarchy

Scopes are slash-separated paths. A parent filter includes descendants:

```text
--scope company        matches company, company/staging, company/production
--scope company/prod   does not match a key scoped only to company
```

Keys without a scope are valid. They are visible in `kmux keys`, selectable by alias, and considered by an unfiltered interactive selection, but do not appear in `kmux scopes`.

## Execution Outcomes

After filters are applied:

| Matches | Result |
| --- | --- |
| 0 | Error; no filtered proxy is started. |
| 1 | Selected automatically. |
| Many with a controlling terminal | An interactive chooser is shown. |
| Many without a controlling terminal | Error listing ambiguous candidates. |

For example:

```bash
kmux --scope hogix --comment aws --tag environment=production -- ssh deploy@example.com
kmux keys --scope hogix --tag environment=production
```
