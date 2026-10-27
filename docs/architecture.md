# Architecture

## Synopsis

MakePF is a configuration compiler for OpenBSD PF. It reads a directory of
whitespace-separated files, validates the complete configuration, and renders a
standalone ruleset. It does not inspect routes to infer policy. Checking and
compilation are unprivileged; the OpenBSD-only `reload` command loads and saves
the ruleset as root.

The implementation has five parts:

- `model.py` holds immutable records for zones, selectors, policies and rules.
- `config.py` parses input with file and line locations and validates references,
  address families, network boundaries and supported combinations.
- `render.py` lowers the validated model to PF text.
- `cli.py` handles commands, diagnostics and output.
- `pf.py` performs native syntax checks and privileged ruleset reloads.

## Packet model

A network zone binds one interface to its permitted IPv4 and IPv6 source
networks. The external zone is the catchall beyond the explicitly declared
inside networks. The firewall zone represents the router itself.

Filtering first handles explicitly enabled link services and rejects invalid
source addresses. Firewall-local decisions are separate from transit decisions.
An external destination selector excludes the declared inside networks; it is
never an unrestricted substitute for every destination.

Transit permissions use paired ingress and egress rules with interface-bound
states. Egress rules also identify the receiving interface. This prevents an
ingress permission from creating a floating state that bypasses the destination
zone's restrictions. Replies use the corresponding states.

IPv4 redirection happens before filtering. Explicit rules therefore see the
translated address and port. Forwarding entries grant access only to traffic
marked by their redirection, after explicit rules and before policy fallback.
Direct packets to the internal target require a separate permission.

IPv6 neighbor discovery, router advertisements and DHCP have explicit service
declarations because their multicast, broadcast or unspecified addresses do not
fit ordinary application traffic. These declarations permit fixed control
exchanges, not general access to the firewall. Link-local and multicast traffic
is not forwarded between zones.

## Administrative boundary

The configuration directory defaults to `/etc/makepf`, independent of the
working directory. `check` invokes native `pfctl -nf` automatically on OpenBSD;
on other build hosts it performs portable configuration validation.

A root-owned system installation handles `doas makepf reload`. A personal pipx
installation can coexist for unprivileged commands. Command-specific `doas`
rules select the system search path for reloads, excluding user-owned command
directories.

Reloads use fixed system paths and require root-owned configuration that other
users cannot modify. They validate a private candidate before changing either
PF or `/etc/pf.conf`. Adoption of an existing unmanaged PF configuration is
explicit. Reloads are serialized and retain one previous on-disk ruleset.
A failed load restores the previous saved file. File replacement and kernel
loading are separate operations: interruption or power loss can leave the saved
and active rulesets different. Normal reloads preserve states and leave PF
enablement, interface configuration and network services to OpenBSD.

## Output and errors

Rendering is deterministic: it adds no timestamps or machine-specific discovery
results. PF resolves dynamic interface address expressions on the OpenBSD host.
Invalid configuration produces a diagnostic before any ruleset is written.
Replacing an output file happens only after successful compilation.

Portable tests check parsing, validation and generated rules. Native OpenBSD
checks cover PF syntax; packet tests cover behavior. Neither text fixtures nor
`pfctl -nf` alone establish that a traffic policy works.

The authoritative PF semantics are documented in
[`pf.conf(5)`](https://man.openbsd.org/OpenBSD-7.9/pf.conf.5).
