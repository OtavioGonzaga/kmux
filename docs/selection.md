# Selection

kmux selects configured keys before starting a filtered proxy. The same filters
are available for command execution and `kmux keys`; key listing uses only local
configuration and never contacts an upstream agent.

## Filters

| Filter                       | Meaning                                                     |
| ---------------------------- | ----------------------------------------------------------- |
| `-s`, `--scope SCOPE`        | Match a scope and its descendants.                          |
| `-c`, `--comment TEXT`       | Case-insensitive substring in persisted local key metadata. |
| `-k`, `--key ALIAS`          | Match a configured key alias.                               |
| `-f`, `--fingerprint PREFIX` | Match a public-key fingerprint prefix.                      |
| `-t`, `--tag KEY=VALUE`      | Match local tag metadata; repeat to require several tags.   |
| `--agent NAME`               | Restrict results to a configured upstream agent.            |

All filters use AND semantics. `--agent` must name an agent in configuration; an
unknown name is an error. A configured agent with no matching keys is a
successful empty `kmux keys` result.

## Scope Hierarchy

Scopes are slash-separated paths. A parent filter includes descendants:

```text
--scope company        matches company, company/staging, company/production
--scope company/prod   does not match a key scoped only to company
```

Keys without a scope are valid. They are visible in `kmux keys`, selectable by
alias, and considered by an unfiltered interactive selection, but do not appear
in `kmux scopes`.

## Execution Outcomes

Filters define the set of identities a child process may use. kmux supports one
upstream agent per execution, but that agent may provide multiple authorized
identities.

### Explicit Filters

When at least one filter is supplied, kmux resolves the matching configured
identities before contacting the upstream agent:

| Matches and options                  | Result                                             |
| ------------------------------------ | -------------------------------------------------- |
| 0                                    | Error; no filtered proxy is started.               |
| One agent, without `--select`        | All matching available identities are authorized.  |
| One agent, with `--select` and a TTY | Choose an identity subset with `MultiSelect`.      |
| Multiple agents, without `--select`  | Error; add `--agent` to select one upstream agent. |
| Multiple agents, with `--select`/TTY | Choose an upstream agent, then an identity subset. |
| Selection required without a TTY     | Error; no child process is started.                |

For example, this authorizes every available configured identity in the
`personal` scope from one upstream agent without prompting:

```bash
kmux --scope personal -- ssh deploy@example.com
```

Add `--select` when a temporary subset is wanted:

```bash
kmux --scope personal --select -- ssh deploy@example.com
```

### No Filters

Unfiltered execution never implicitly delegates every configured identity:

| Candidates                          | Result                                             |
| ----------------------------------- | -------------------------------------------------- |
| 0                                   | Error; no filtered proxy is started.               |
| 1                                   | Authorized automatically.                          |
| Many with a controlling terminal    | Choose an upstream agent if needed, then a subset. |
| Many without a controlling terminal | Error; add filters or run interactively.           |

`--select` follows the same interactive policy. `MultiSelect` starts with no
identities selected; confirming an empty selection or cancelling returns an
error and does not start the child process.

For example:

```bash
kmux --scope hogix --comment aws --tag environment=production -- ssh deploy@example.com
kmux keys --scope hogix --tag environment=production
```
