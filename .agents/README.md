# Agent Workspace

This directory serves as the centralized knowledge and tools base for the AI agents that assist with this project. The goal is to maintain an organized, consistent layout that is agnostic to any AI tool or provider.

## Directory Summary

| Directory    | Description                                      | Versioned |
| :----------- | :----------------------------------------------- | :-------: |
| `memory/`    | Persistent and strategic project knowledge       |    ✅     |
| `prompts/`   | Optimized and reusable prompts for agents        |    ✅     |
| `artifacts/` | Temporary (ephemeral) work files                 |    ❌     |

---

## Details

### `memory/` (Versioned)

Stores long-term knowledge. Documentation that does not change frequently but is crucial for agents to understand the domain or architecture context.

### `prompts/` (Versioned)

Optimized and tested prompts that ensure agents follow the project's style and rules when performing specific tasks, promoting consistency and efficiency.

### `artifacts/` (Not Versioned)

A temporary workspace for all files generated or used during task execution. It includes temporary plans, quick notes, drafts, debugging logs, and any interim reports. It must not be versioned.

---

> **Important note:** Only `memory/`, `prompts/`, and this file (`README.md`) should be committed to version control (Git). The `artifacts/` folder is ephemeral and configured to be ignored.

## How to Contribute

- **Add a Prompt:** Create a file in `prompts/` with a clear description at the top
- **Add Knowledge:** Create a Markdown file in `memory/` with domain context

## Versioning Criteria

### Version (.agents/memory/ and .agents/prompts/)

- Knowledge that is reusable by multiple agents
- Instructions that evolve with the project
- Documentation that changes infrequently

### ❌ Do Not Version (.agents/artifacts/)

- Execution reports (task outputs)
- Intermediate or debugging logs
- Scratch/temporary files
- Task-specific plans

**Example:** An agent performs test coverage analysis → saves the report in `artifacts/`,
but if it discovers a new testing pattern → documents it in `memory/`.
