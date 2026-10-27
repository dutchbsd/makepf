# MakePF

## Synopsis

MakePF compiles zone-based firewall configuration into native OpenBSD PF rules.
Zones name the networks; policies and rules describe which connections may pass
between them. The generated ruleset can be reviewed with standard PF tools.

MakePF targets **OpenBSD 7.9** and requires **Python 3.11 or later**. It uses only
the Python standard library. Checking and compiling run without root privileges.
On the OpenBSD router, `reload` validates, loads and saves the ruleset for reboot.
Interface setup and other network services remain OpenBSD tasks.

## Install

Install the system command to manage PF on an OpenBSD 7.9 router. Python and Git
are packages, separate from OpenBSD base. The following steps require an account
with administrative access through `doas`.

### Install prerequisites

```sh
doas pkg_add python%3.13 git
```

### Get the source

Clone the repository and enter its directory:

```sh
git clone https://github.com/dutchbsd/makepf.git
cd makepf
```

### Build and install

From the cloned `makepf` directory, build the executable archive and install it
as the root-owned system command:

```sh
/usr/local/bin/python3.13 tools/build.py
doas install -o root -g bin -m 755 dist/makepf /usr/local/bin/makepf
makepf --version
```

**Example output**

```text
MakePF 1.0.0
```

The archive uses the Python interpreter that built it. Keep that interpreter
installed; no third-party Python libraries or build tools are required.

### Optional personal installation

For unprivileged checks and compilation, install MakePF with pipx:

```sh
doas pkg_add py3-pipx
pipx ensurepath
```

Open a new terminal, then install MakePF as the regular user:

```sh
pipx install --python /usr/local/bin/python3.13 makepf
```

A personal installation can check and compile configurations alongside the
system installation. The `doas` rules below select the root-owned system command
for reloads. Do not run a personal Python environment as root.

## First configuration

Continue from the cloned `makepf` directory. On a new installation, copy the
dual-stack example into the default configuration directory:

```sh
doas install -d -o root -g wheel -m 755 /etc/makepf
doas install -o root -g wheel -m 644 examples/dual-stack/* /etc/makepf/
```

Edit the interface names and network prefixes for the router:

```sh
doas vi /etc/makepf/interfaces
```

Review `policy`, `rules`, `nat`, `forwards` and `settings` in the same directory.
The [router walkthrough](https://github.com/dutchbsd/makepf/blob/master/docs/router.md)
explains the network prerequisites and the purpose of each file. Keep the
configuration root-owned and unwritable by other users.

### Enable administrative reloads

Edit `/etc/doas.conf` with your existing administrator access:

```sh
doas vi /etc/doas.conf
```

Add these rules after any broader rules for `wheel`:

```text
permit persist :wheel as root cmd makepf args reload
permit persist :wheel as root cmd makepf args reload --adopt
```

These command-specific rules use OpenBSD's system search path. This lets
`doas makepf reload` use `/usr/local/bin/makepf` even when a personal installation
comes first in the user's `PATH`. See [`doas.conf(5)`](https://man.openbsd.org/OpenBSD-7.9/doas.conf.5).

### Check and load

Check the configuration as the regular user:

```sh
makepf check
```

On OpenBSD, this also checks the generated rules with native `pfctl`. To inspect
the rules before loading them, run `makepf compile | less`.

The first reload replaces the existing `/etc/pf.conf`. Review the policy and
retain console access before adopting it:

```sh
doas makepf reload --adopt
```

MakePF retains the previous file as `/etc/pf.conf.makepf.bak`. Once `/etc/pf.conf`
is managed by MakePF, the normal workflow is:

```sh
makepf check
doas makepf reload
```

`reload` always repeats validation before changing PF. It preserves existing
states and does not enable PF or configure interfaces. See the
[configuration reference](https://github.com/dutchbsd/makepf/blob/master/docs/configuration.md#commands)
for reload failure handling and optional directory arguments.

## Configuration example

In the `policy` file, this permits connections initiated from the local network
to the external network and drops other connections:

```text
# SOURCE  DESTINATION  FAMILY  ACTION
loc       net          both    ACCEPT
all       all          both    DROP
```

In the `rules` file, this permits SSH from the local network to the firewall:

```text
# ACTION  SOURCE  DESTINATION  FAMILY  PROTOCOL  SERVICE
ACCEPT    loc     fw           both    tcp       22
```

`fw` names the firewall zone. Replies to permitted connections are stateful;
reverse rules are unnecessary for replies. Columns use spaces for alignment;
see [editing configuration files](https://github.com/dutchbsd/makepf/blob/master/docs/configuration.md#file-format).

## Documentation

- [Configuration reference](https://github.com/dutchbsd/makepf/blob/master/docs/configuration.md): files, selectors and ordering.
- [Router walkthrough](https://github.com/dutchbsd/makepf/blob/master/docs/router.md): reference IPv4 routers and a dual-stack
  configuration, including differences from the source guides.
- [Architecture](https://github.com/dutchbsd/makepf/blob/master/docs/architecture.md): packet model and compiler boundaries.
- [Contributing](https://github.com/dutchbsd/makepf/blob/master/CONTRIBUTING.md): development, formatting and verification.

MakePF's configuration is inspired by Shorewall's separation of zones, policies
and exceptions. It is an independent language, not a Shorewall-compatible
implementation. PF is the only output target. Interface setup, DHCP, DNS,
router advertisements and prefix acquisition remain separate OpenBSD tasks.

## License

Copyright © 2026 [DutchBSD B.V.](https://www.dutchbsd.com/). Distributed under the
[BSD 2-Clause License](https://github.com/dutchbsd/makepf/blob/master/LICENSE).
