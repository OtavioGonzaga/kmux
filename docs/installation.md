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
