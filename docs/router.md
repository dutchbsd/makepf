# Build a router with MakePF

## Synopsis

MakePF replaces the PF configuration step and handles checked ruleset reloads.
Interface addresses, routes, forwarding, DHCP, DNS and router advertisements
remain OpenBSD settings and services.

The examples cover two reference setups and a more restrictive dual-stack router:

| Directory | Network and policy |
| --- | --- |
| `examples/handbook` | One IPv4 LAN with outbound NAT and router-hosted services. |
| `examples/faq` | Two IPv4 inside networks, outbound NAT and web port forwarding. |
| `examples/dual-stack` | Two inside networks, IPv4 NAT and native IPv6 routing, with explicit router services and inside-network isolation. |

The first two follow the firewall behavior of the
[OpenBSD Handbook router guide](https://www.openbsdhandbook.com/router-firewall/)
and the [official PF router example](https://www.openbsd.org/faq/pf/example1.html).
Their trusted inside networks can reach router services broadly. The FAQ example
also permits traffic between its inside networks. These are example policies,
not permissions that MakePF adds implicitly.

## Prepare OpenBSD

Install the root-owned MakePF command and configure `doas` using the
[installation steps](../README.md#install) and
[administrative reload rules](../README.md#enable-administrative-reloads).
Follow the selected guide for interface setup, IPv4 forwarding, DHCP and DNS.
Replace example interface names and addresses with the router's values. A
wireless zone can also use a wired interface connected to an access point;
MakePF does not configure wireless hardware.

For dual stack, obtain a routed IPv6 prefix with a separate `/64` for each inside
network, configure the addresses and upstream route, and enable IPv6 forwarding.
Configure [`rad(8)`](https://man.openbsd.org/rad.8) on the inside
interfaces for SLAAC. Its `rad.conf` interface declarations and the MakePF
`ipv6-router` declarations must describe the same interfaces.

The dual-stack example uses documentation prefixes. Replace them before use.
It assumes an externally configured IPv6 route; it does not acquire a prefix
from an ISP. Prefix delegation and renumbering remain the responsibility of the
OpenBSD network configuration. Update MakePF's inside prefixes when they change.

## Review the firewall configuration

Run these steps from the cloned source directory obtained in the README. On a
new installation, choose one example profile and copy it into `/etc/makepf`.
The following uses the dual-stack profile:

```sh
doas install -d -o root -g wheel -m 755 /etc/makepf
doas install -o root -g wheel -m 644 examples/dual-stack/* /etc/makepf/
```

For an IPv4 reference setup, use `examples/handbook/*` or `examples/faq/*` instead.
Keep profiles in separate configuration directories; copying one over another
can retain unwanted files from the previous profile.

Edit `/etc/makepf/interfaces` with the router's interface names and prefixes:

```sh
doas vi /etc/makepf/interfaces
```

Review the remaining configuration files before loading them:

1. `policy`: decide which zones may initiate connections.
2. `rules`: grant individual services or restrict specific addresses.
3. `nat` and `forwards`: choose IPv4 translation and published services.
4. `settings`: enable only the link services used on each interface.

The optional `groups` file keeps address lists out of individual rules. The
IPv4 examples include the reference guides' martian filtering, which assumes a
public WAN. Adapt that list for private or laboratory upstream networks; otherwise
it can block the upstream router or DHCP server.

For example, allowing SSH from the trusted LAN to the router is one rule:

```text
# ACTION  SOURCE  DESTINATION  FAMILY  PROTOCOL  SERVICE
ACCEPT    loc     fw           both    tcp       22
```

Publishing a different IPv4 web server changes the target in the two `forwards`
rows. IPv6 hosts use their routed addresses: allow an IPv6 service with a normal
rule rather than an IPv4-style port forward.

The dual-stack example intentionally blocks `wifi` to `loc`. To permit initiated
connections in that direction, add this policy before the final deny:

```text
# SOURCE  DESTINATION  FAMILY  ACTION
wifi      loc          both    ACCEPT
```

Replies are stateful; a reverse policy is needed only for connections initiated
in the opposite direction.

## Check and load

Check the edited configuration from any working directory:

```sh
makepf check
```

On OpenBSD, this validates both the configuration and native PF syntax without
root privileges. Inspect the generated rules if needed:

```sh
makepf compile | less
```

Confirm that the interface names, networks and permissions match the router.
The first reload replaces the active firewall configuration and `/etc/pf.conf`.
Use a local console or retain console access in case the new policy blocks
remote access. Explicitly adopt an existing PF configuration on first use:

```sh
doas makepf reload --adopt
```

MakePF checks a private candidate, keeps the previous file in
`/etc/pf.conf.makepf.bak` and loads the checked ruleset. It also saves the rules
in `/etc/pf.conf` for reboot. PF must already be enabled as part of the OpenBSD
setup; MakePF does not enable it or change interfaces and services.

After editing a managed configuration, use:

```sh
makepf check
doas makepf reload
```

Every reload repeats validation. A rejected candidate leaves the current
configuration in place. See the [reload reference](configuration.md#commands)
for backup and failure handling.

Reloading rules does not revoke existing PF states. Test new connections after
a policy change. If existing sessions must be revoked, manage the relevant
states deliberately with [`pfctl(8)`](https://man.openbsd.org/pfctl.8);
MakePF never removes them.

## Verify the result

Test from clients on each network, not just from the router:

- Obtain an IPv4 DHCP lease, default route and DNS settings; resolve a name using
  the router's resolver over both UDP and TCP.
- Initiate IPv4 and IPv6 TCP/UDP connections outside and confirm replies. IPv4
  should show NAT; native IPv6 must retain the client's address.
- Confirm that unsolicited outside connections fail. In the FAQ case, only the
  configured IPv4 web forwards should reach the selected target.
- Check inside-network isolation and router management access against the chosen
  policy. Test the denied direction as well as the allowed one.
- With IPv6, check SLAAC, neighbor discovery and a transfer across a smaller-MTU
  path. A successful ping alone does not test path-MTU handling.
- Inspect PF rules and states and check application behavior after a reload and
  after changing a dynamic WAN address.

## Common changes

| Change | MakePF edit |
| --- | --- |
| Rename a network interface | One row in `interfaces`; other files retain the zone name. |
| Allow a TCP service to the router | Add one row to `rules`. |
| Permit Wi-Fi to initiate LAN connections | Add one row to `policy`. |
| Move the published IPv4 HTTP/HTTPS server | Change the target in two `forwards` rows. Update the IPv6 address rule separately if publishing IPv6 too. |

When changing a subnet, update the relevant OpenBSD service configuration as
well as MakePF's prefixes and address-qualified rules.
