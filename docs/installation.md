# Installation

kmux is supported on Linux. The package name is `ssh-kmux`; the installed
executable is `kmux`. Building from source requires Rust 1.89 or newer.

## Cargo

```bash
cargo install ssh-kmux
```

For reproducible dependency resolution, use the lockfile published with the
crate:

```bash
cargo install ssh-kmux --locked
```

Update by rerunning the same command. Uninstall with `cargo uninstall ssh-kmux`.

## Debian Or Ubuntu

Download the matching `.deb` from the
[latest GitHub Release](https://github.com/OtavioGonzaga/kmux/releases/latest).
Releases provide `amd64` and `arm64` packages.

```bash
sudo dpkg -i kmux_<version>_amd64.deb
```

Replace `amd64` with `arm64` on 64-bit ARM systems. Upgrade by installing a
newer package. Remove it with `sudo dpkg -r kmux`.

## Tarball

Stable tarball asset names support direct latest-release downloads:

```bash
curl -LO https://github.com/OtavioGonzaga/kmux/releases/latest/download/kmux-linux-x86_64.tar.gz
curl -LO https://github.com/OtavioGonzaga/kmux/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf kmux-linux-x86_64.tar.gz
install -Dm755 kmux ~/.local/bin/kmux
```

Use `kmux-linux-aarch64.tar.gz` on 64-bit ARM. Ensure `~/.local/bin` is in
`PATH`, for example by starting a new shell after your distribution's normal
profile setup. Replace the tarball with a newer release to update; remove
`~/.local/bin/kmux` to uninstall.

## Build From Source

```bash
git clone https://github.com/OtavioGonzaga/kmux.git
cd kmux
cargo build --release --locked
./target/release/kmux --version
install -Dm755 target/release/kmux ~/.local/bin/kmux
```

Use `git pull` followed by the build command to update a source checkout. Remove
the installed binary and checkout when they are no longer needed.

## Shell Completion

Shell completion lets your shell suggest kmux commands, options, and supported
values when you press Tab. kmux does not install or enable completion by itself:
it prints a shell-specific script to standard output, and you choose whether to
use it only in the current terminal or every time you open that shell.

First, identify the shell running in your terminal:

```bash
echo "$SHELL"
```

The result commonly ends in `bash`, `zsh`, or `fish`. Use the matching section
below. If you are unsure, start with the current-session command. Close and
reopen the terminal to undo a current-session change.

### Bash

To enable completion in the current Bash session, run:

```bash
source <(kmux completions bash)
```

`source` reads the generated script into the current shell. Now type `kmux`,
press Tab, and press Tab again if your shell does not show suggestions
immediately.

To enable it whenever Bash starts, add the same command to `~/.bashrc`:

```bash
printf '%s\n' 'source <(kmux completions bash)' >> ~/.bashrc
```

Open a new terminal, or reload that file in the current terminal:

```bash
source ~/.bashrc
```

### Zsh

To try completion in the current Zsh session, run:

```bash
autoload -Uz compinit
compinit
source <(kmux completions zsh)
```

For persistent completion, save the generated function in a directory that Zsh
searches for completion functions. `fpath` is Zsh's list of those directories.
The following setup creates a user-owned directory, then writes the generated
function into it:

```bash
mkdir -p ~/.local/share/zsh/site-functions
kmux completions zsh > ~/.local/share/zsh/site-functions/_kmux
```

Add these lines to `~/.zshrc` if they are not already present:

```zsh
fpath=(~/.local/share/zsh/site-functions $fpath)
autoload -Uz compinit
compinit
```

Start a new Zsh session after saving the file. Do not add a second `compinit`
block if your existing `~/.zshrc` already initializes completions; add only the
`fpath` line before it instead.

### Fish

Fish automatically loads files from its completions directory. Create that
directory if needed, then write kmux's generated script there:

```bash
mkdir -p ~/.config/fish/completions
kmux completions fish > ~/.config/fish/completions/kmux.fish
```

Open a new Fish session, or run `source ~/.config/fish/completions/kmux.fish` in
the current one.

### Elvish And PowerShell

Generate scripts for these shells with:

```bash
kmux completions elvish
kmux completions powershell
```

The commands print the script rather than installing it. Consult your shell's
documentation for its per-user profile or completion directory, then redirect
the output to the location it documents.
