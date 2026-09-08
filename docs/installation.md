# Installation

## Scope

Build and install WirePup on Linux, select the executable used by your shell
and sudo, update existing files, and activate Bash completion.

**Out of scope:** packet analysis and network changes. Continue with
[first use](../README.md#first-use) or a [usage scenario](usage-scenarios.md).

## Prerequisites

Use Go 1.25 or newer, GNU Make, Bash 4 or newer and GNU coreutils. Git is
needed to obtain the checkout. The minimum Go version is recorded in
[go.mod](../go.mod); dependencies may raise it in a later update.
The executable builds with `CGO_ENABLED=0`, without libpcap or other C libraries.
Runtime temporary-address operations use `ip` from iproute2. Live capture and
host changes require Linux and the [documented privileges](safety.md#4-linux-capabilities).

On Debian 13, enable `trixie-backports` using the
[Debian instructions](https://backports.debian.org/Instructions/) before the
package command below. If it is already enabled, use that entry instead of
adding a duplicate source.

```bash
sudo apt update
sudo apt install git make bash coreutils iproute2
sudo apt install -t trixie-backports golang-go
go version
```

Check that `go version` reports 1.25 or newer. Alternatively, follow the
[official Go installation instructions](https://go.dev/doc/install).
Select that toolchain on PATH before building. A C compiler is needed only
for the optional race tests; Python 3 is needed for the documented PTY tests.

## Get and build the source

If you do not already have a checkout:

```bash
git clone https://github.com/jeonghanlee/wirepup.git
cd wirepup
```

Run all Make commands below from that repository directory as your normal
user. Do not run `sudo make`.

```bash
make help
make build
bin/wirepup version
```

The build produces `bin/wirepup`; a successful version command prints its
build identity. `make help.detail` lists every public target.
See [build settings](../CONTRIBUTING.md#build-settings) for tool and output overrides.

## Install for your user

The default prefix is `$HOME/.local`. No sudo is needed when that directory
is writable.

```bash
make install.dry-run
make install
export PATH="$HOME/.local/bin:$PATH"
make install.check
```

The executable is `$HOME/.local/bin/wirepup`; completion is
`$HOME/.local/share/bash-completion/completions/wirepup`.
The export affects this shell. Add it to your own shell configuration if
you want it in future sessions; installation edits no startup files.

## Install for sudo and all users

For `/usr/local/bin/wirepup` and system completion:

```bash
make install.dry-run INSTALL_LOCATION=/usr/local
make install INSTALL_LOCATION=/usr/local
export PATH="/usr/local/bin:$PATH"
make install.check INSTALL_LOCATION=/usr/local
sudo wirepup version
```

Only the protected file copy uses sudo, which may ask for your password.
Build, version and completion checks run as your normal user.
Completion is installed at
`/usr/local/share/bash-completion/completions/wirepup`.

## Updates and replacement

Repeat the same preview, install and check commands with the same
`INSTALL_LOCATION`. A custom prefix installs both
`<prefix>/bin/wirepup` and
`<prefix>/share/bash-completion/completions/wirepup`.

For each existing destination, installation asks
`Replace this file? [y/N]`. Enter, `n` or EOF cancels with a nonzero exit
status. Both answers are collected before copying either file, so declining
either preserves both. Without a terminal, replacement is refused.

For automation, explicitly approve replacement with `INSTALL_FORCE=1`,
for example:

```bash
make install INSTALL_LOCATION=/usr/local INSTALL_FORCE=1
```

A new destination needs no replacement confirmation. Files are copied one at
a time: a later copy failure can leave the executable updated and completion
unchanged. Correct the reported failure, repeat installation and run
`install.check` with the same prefix.

## Verify the selected command

`install.check` checks the executable, version, active PATH and completion
registration. It fails if another executable takes precedence or completion
is missing or invalid. Its output provides the PATH and completion
activation commands.

`sudo wirepup version` separately checks sudo's command lookup.
If sudo does not search `/usr/local/bin`, use the full path:

```bash
sudo /usr/local/bin/wirepup version
```

An older user installation can still precede the system one in your shell.
Set `PATH` to the intended prefix and repeat the matching
`make install.check INSTALL_LOCATION=/usr/local`.

## Bash completion

For a user installation, activate completion in the current Bash shell:

```bash
source "$HOME/.local/share/bash-completion/completions/wirepup"
```

For a system installation:

```bash
source /usr/local/share/bash-completion/completions/wirepup
```

For a custom prefix, source its
`share/bash-completion/completions/wirepup` file.
Explicit sourcing works without the optional `bash-completion` package.
For automatic loading, install that package and start a new Bash shell with
its integration enabled. Standard user and system data directories are
discovered; for custom prefixes or an overridden `XDG_DATA_HOME`,
explicit sourcing remains reliable. Re-source after updating a completion
already loaded in your shell.

Tab extends the common prefix. If it makes no further change, press Tab
again to list remaining candidates. Try the
[completion examples](usage-scenarios.md#complete-commands-in-bash).
Completion reads the installed CLI's help, local interface names and file
names; it does not capture traffic, look up PVs or change network settings.

## Installation safeguards

Both destinations must be regular files or new paths; symlinks are refused.
Build output must not refer to either installed file. Completion syntax,
registration and the registered function are checked in a fresh Bash before
installation and again on the staged copy, as the invoking user.

For protected destinations, parent directories must be root-owned, traversable
by the invoking user, free of symlinks and not writable by group or others.
The executable is root-owned with mode `0755`, completion with mode `0644`.
Protected copies use system tools; a custom `INSTALL` command applies only to
writable destinations.

Each protected copy must match the SHA-256 digest of the snapshot verified
before sudo. An incomplete or changed copy does not replace the destination.
The snapshot is created beside the resolved build output, whose directory
must be writable by the invoking user. A `noexec` setting on `TMPDIR`
therefore does not prevent installation. The protected copy checks execution
permission on the staged executable and refuses a `noexec` destination while
preserving the existing file.
