# Configuration reference

## Synopsis

MakePF reads `/etc/makepf` by default. `zones`, `interfaces` and `policy` define
the network and its defaults. Optional files add exceptions, translation, address
groups and link services.

## File format

Files are plain UTF-8 text. Whitespace separates columns, blank lines are ignored,
and `#` starts a comment. Use spaces to align values with their column headings.
The editor indentation default is four spaces; use additional spaces as needed
for each column. Both tabs and spaces are accepted by the parser, but a tab-width
setting alone does not align fields.

In Vim, use:

```vim
:setlocal expandtab tabstop=4 shiftwidth=4 softtabstop=4
```

Repository defaults are recorded in `.editorconfig`. See
[Contributing](../CONTRIBUTING.md) for the editing conventions.

Unknown visible entries in the directory are rejected to catch misspelled file
names. Hidden entries are ignored. Keep notes and unrelated files outside the
configuration directory.

Checking and compiling accept configuration files that are symbolic links to
regular files. A dangling link is an error, including for an optional file.
Output must remain outside the configuration directory and cannot replace the
resolved target of any input. Administrative reloads require trusted, root-owned
configuration; see the reload requirements below.

There is no shell expansion, executable configuration, interpolation or raw PF
injection. Identifiers and values are case-sensitive. Use the documented action
and family names exactly.

## Zones and interfaces

`zones` has two columns:

```text
# NAME  TYPE
fw      firewall
net     dual
loc     dual
```

Declare exactly one `firewall` zone. Network zone types are `ipv4`, `ipv6` and
`dual`. The firewall zone has no interface binding and represents the host itself.
`all` is reserved for matching declared zones.

Zone and group names start with a lowercase letter, followed by lowercase
letters, digits or underscores, with at most 16 characters in total.

`interfaces` binds a network zone and its prefixes:

```text
# ZONE  INTERFACE  IPV4_PREFIX     IPV6_PREFIX
net     vio0       any             any
loc     vio1       192.168.1.0/24  2001:db8:100:1::/64
```

Use `-` for a family absent from an `ipv4` or `ipv6` zone. Inside prefixes must be
explicit CIDRs and must not overlap other inside zones. Each network zone has
one concrete interface; an interface cannot belong to two zones. Use a name
ending in a digit, such as `em0` or `vio0`. Interface groups such as `egress`
and wildcards such as `any` are not supported as bindings.

Inside prefixes must be routed unicast networks. Prefixes overlapping these
non-routed ranges are rejected:

- IPv4: `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4` and
  `255.255.255.255/32`.
- IPv6: `::/128`, `::1/128`, `fe80::/10` and `ff00::/8`.

Use explicit link-service settings for discovery and other link-local control
traffic. Ordinary link-local management rules and routed multicast are outside
this language. Private inside networks remain valid; these mandatory exclusions
are separate from the optional martian lists in the examples.

The external catchall uses `any`, with at most one catchall per family. For
destination matching it means addresses outside the declared inside networks and
non-routed special ranges. It does not grant access to inside zones or the
firewall. Dynamic router addresses are represented with PF interface
expressions rather than discovered during compilation. MakePF does not assign
these addresses or create routes.

## Policy and rule ordering

`policy` defines defaults for connections initiated between zones:

```text
# SOURCE  DESTINATION  FAMILY  ACTION  [LOG]
loc       net          both    ACCEPT
fw        net          both    ACCEPT
all       all          both    DROP    log
```

Families are `inet` (IPv4), `inet6` (IPv6) and `both`. Actions are `ACCEPT`,
`DROP` (silent block) and `REJECT` (PF return response where applicable). An
optional final `log` enables PF logging; `-` or an omitted value disables it.

Policies use zone names or `all` and are evaluated in file order. Put specific
entries before general ones. End with an explicit default deny. A family-neutral
PF block remains in the generated ruleset, including for unsupported families.

`rules` contains ordered exceptions:

```text
# ACTION  SOURCE  DESTINATION  FAMILY  PROTOCOL  SERVICE  [LOG]
ACCEPT    loc     fw           both    tcp       22
ACCEPT    loc     fw           both    udp       53
ACCEPT    loc     fw           both    tcp       53
ACCEPT    loc     fw           inet6   icmp6     128
```

Protocols are `any`, `tcp`, `udp`, `icmp` and `icmp6`. TCP and UDP services are
numeric destination ports, comma-separated lists, inclusive colon ranges such
as `8000:8010`, or `-` for any port. ICMP services are a single numeric message
type or `-`; `icmp` requires `inet`, and `icmp6` requires `inet6`. Protocol `any`
requires service `-`. Named services and arbitrary protocol strings are not
accepted.

Explicit rules run before forwarding permissions, followed by policy fallback.
Within a phase the first match decides. Stateful replies do not need a reverse
permission. A new connection initiated in the opposite direction does.

Explicit numeric ICMP types other than echo request (`8` for IPv4, `128` for
IPv6) are emitted without state. These permissions cover that message only;
they do not create a general reverse permission. Related replies and errors
normally follow the state of the connection that caused them.

Explicit link-service declarations run before application rules and source
guards. They are separate permissions: for example, an enabled DHCP server can
answer DHCP even when ordinary access to the firewall is denied.

## Address selectors and groups

`rules` entries can narrow a zone to an address, CIDR or named group:

```text
ACCEPT  loc:192.168.1.10  fw                     inet   tcp  22
ACCEPT  net               loc:2001:db8:100:1::2  inet6  tcp  80,443
DROP    net:@blocked      all                    inet   any  -       log
```

An address-qualified selector still belongs to its zone. It cannot bypass the
zone's interface or network boundary. IPv6 colons remain part of the address
after the first separator. A family-specific address or group requires a matching
family; use `inet`, rather than `both`, for an IPv4-only address restriction.

`groups` names literal addresses and networks in one family:

```text
# NAME   FAMILY  ADDRESSES
blocked  inet    198.51.100.0/24,203.0.113.9
```

Separate addresses with commas and no spaces. Group names are referenced with
`@` inside a zone selector. Groups cannot include other groups or hostnames.

Selectors are intersected with their zone. In a catchall zone, members belonging
to an inside zone or a non-routed control range are excluded. A shared
address list can describe external filtering without matching inside traffic. A
named catchall selector with no remaining addresses is rejected.
Documentation addresses in these examples must be replaced for a real network.

## IPv4 NAT and forwarding

`nat` enables source NAT to the current external interface address:

```text
# SOURCE  DESTINATION  FAMILY
loc       net          inet
```

NAT does not permit traffic by itself. A rule or policy must allow the connection.
The destination must be the external catchall zone. NAT is IPv4-only; routed
IPv6 uses normal policy without translation.

An explicit IPv4 ICMP response/error permission cannot cross a declared NAT
pair, because those numeric message permissions are stateless. Use normal
stateful connection permissions for related replies and errors, and
`icmp-errors yes` for firewall-local errors.

`forwards` publishes a service on the incoming interface's IPv4 address:

```text
# SOURCE  DESTINATION  FAMILY  PROTOCOL  PUBLIC_PORT  TARGET       TARGET_PORT  [LOG]
net       loc          inet    tcp       443          192.168.1.2  8443         log
```

Source may be narrowed with an address selector. Destination is an inside zone;
target must be a literal IPv4 host inside it. Protocol is `tcp` or `udp`, and
both ports are single numbers. Use separate entries for additional ports.
Overlapping public endpoints are rejected.

Filtering sees the translated target address and target port. An explicit rule
denying `net` to `loc:192.168.1.2` on TCP port `8443` overrides this forward.
Forward permissions apply only to traffic redirected by that entry. They do not
allow direct outside packets to the target. Hairpin forwarding is not supported.

For an IPv6 server, add a normal address-restricted IPv6 rule to its routed
address. IPv6 NAT, address-family translation and IPv6 port redirection are not
part of this language.

## Settings and link services

`settings` contains a key and value per line:

| Setting | Value | Effect |
| --- | --- | --- |
| `loopback` | `yes` or `no` | Skip `lo0` filtering; default `yes`. |
| `normalize` | `yes` or `no` | Enable the documented PF normalization baseline; default `no`. |
| `mss` | Integer, 536 to 65535 | Set the inbound TCP maximum MSS; no override by default. |
| `loginterface` | Zone | Collect PF interface statistics on the zone's interface. |
| `dhcp-client` | Zone | Allow the router's IPv4 DHCP client exchanges on this interface. |
| `dhcp-server` | Zone | Allow IPv4 DHCP requests and router replies on this interface. |
| `ipv6-neighbor` | Zone | Allow IPv6 neighbor discovery and link multicast membership control. |
| `ipv6-router` | Zone | Neighbor control plus incoming router solicitation and outgoing advertisements. |
| `ipv6-client` | Zone | Neighbor control plus trusted incoming advertisements and outgoing solicitations. |
| `icmp-errors` | `yes` or `no` | Permit firewall-local ICMP error messages; default `no`. |

Repeat zone-valued service settings for each participating zone. Control
permissions are omitted unless declared. Choose only one IPv6 role per zone:
neighbor, router or client. Router and DHCP-server roles require an inside zone;
client roles require the corresponding external catchall. `ipv6-router` never
permits incoming router advertisements; enable `ipv6-client` only on an interface
where the upstream is trusted for that role.

The service settings grant only fixed control exchanges, including unspecified
source addresses needed for initial DHCP and IPv6 discovery. They do not start
daemons, configure prefixes, open DNS, allow SSH, or grant general ICMP access.
Forwarded ICMP errors associated with allowed connections use PF state tracking.
Link-local and multicast traffic is not routed between zones.

DHCP settings add UDP allowances to PF; they do not turn DHCP services on or off.
OpenBSD's native DHCP daemons use BPF for parts of their exchanges, which can
operate independently of PF's IP-layer rules. Configure daemon interface bindings
separately; see [`dhcpd(8)`](https://man.openbsd.org/OpenBSD-7.9/dhcpd.8) and
[`dhcpleased(8)`](https://man.openbsd.org/OpenBSD-7.9/dhcpleased.8).

Source validation is always enabled. There is no option to bypass the declared
inside prefixes. Inspect generated PF text when choosing normalization or MSS
settings; an MSS value suitable for one uplink is not necessarily suitable for
another.

## Commands

After [installing MakePF](../README.md#install), the usual workflow is:

```sh
makepf check
doas makepf reload
```

All commands use `/etc/makepf` unless a directory argument selects another
configuration. The current working directory does not affect this default.

### Check

`check` parses and validates the configuration without writing output. On
OpenBSD, it also runs `pfctl -nf` against the generated ruleset. This syntax
check runs without root privileges and does not load rules. On other systems,
`check` performs portable configuration validation only.

To check an example from the cloned source directory:

```sh
makepf check examples/dual-stack
```

The optional `--pf` flag remains available to require native checking explicitly;
it reports an error on systems other than OpenBSD. It is unnecessary for the
normal OpenBSD workflow.

### Compile

`compile` writes PF text to standard output unless `-o` selects a file:

```sh
makepf compile
makepf compile -o /tmp/makepf.pf
makepf compile examples/dual-stack -o /tmp/makepf-example.pf
```

Diagnostics go to standard error. Failed compilation returns nonzero and leaves
an existing output file intact. New output files are private to their owner;
symbolic-link outputs are rejected. Output cannot be placed inside the
configuration directory or replace any resolved configuration input. Compilation
does not load rules.

### Reload

`reload` requires OpenBSD, root privileges and a root-owned installation. The
[one-time `doas` setup](../README.md#enable-administrative-reloads) makes the bare
command select the system installation when a personal version also exists.
The configuration directory, input files and their parent directories must be
root-owned and unwritable by group or other users. Directories must be real
directories, without symbolic links in their paths. A root-owned input file may
be a direct symbolic link to a protected regular file; chained links are not
accepted for reloads.

A reload compiles a private candidate and checks that exact ruleset with
`pfctl -nf`. A failed compilation or syntax check leaves `/etc/pf.conf` and the
active rules unchanged. It does not depend on a previous `check` invocation.

MakePF manages `/etc/pf.conf`. To replace an existing file that MakePF does not
manage, explicitly adopt it on first use:

```sh
doas makepf reload --adopt
```

Subsequent reloads use:

```sh
doas makepf reload
```

After validation, the previous different on-disk ruleset is backed up to
`/etc/pf.conf.makepf.bak`. This is a single previous copy. Reloading identical
output retains the existing backup. The checked ruleset atomically replaces
`/etc/pf.conf` with mode `600` and is loaded into PF. Do not edit the generated
file; edit the files in `/etc/makepf` instead.

If loading fails, MakePF restores the previous saved file and returns an error.
If no saved file existed, it removes the new file instead. The saved file and
the active kernel rules cannot be updated as one transaction across a crash or
interruption. Inspect both if a reload is interrupted; the command reports that
inspection is needed.

Reloads preserve existing PF states, do not enable or disable PF and do not
change interfaces, routes or other services. Existing connections can remain
permitted after a policy change; test new connections when verifying a deny.
MakePF does not flush states or provide timed connectivity rollback. Retain
console access when changing remote management policy.
