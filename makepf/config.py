"""Read and validate the non-executable MakePF configuration language."""

import ipaddress
from pathlib import Path
import re

from .model import Config, ConfigError, Forward, Group, Interface, Location, Nat, Policy, RESERVED, Rule, Selector, Zone, subtract_networks

FILES = {'zones', 'interfaces', 'policy', 'rules', 'groups', 'nat', 'forwards', 'settings'}
FAMILIES = {'inet': ('inet',), 'inet6': ('inet6',), 'both': ('inet', 'inet6')}
ZONE_SETTINGS = {'dhcp-client', 'dhcp-server', 'ipv6-neighbor', 'ipv6-router', 'ipv6-client', 'loginterface'}
BOOL_SETTINGS = {'loopback', 'normalize', 'icmp-errors'}


def fail(where, message):
    raise ConfigError(f'{where}: {message}')


def name(value, where):
    if not re.fullmatch(r'[a-z][a-z0-9_]{0,15}', value, re.ASCII) or value == 'all':
        fail(where, f'invalid name {value!r}; use 1–16 lowercase letters, digits or underscores, starting with a letter; all is reserved')
    return value


def address(value, family, where):
    try:
        if '%' in value:
            raise ValueError('scoped addresses are not supported')
        parsed = ipaddress.ip_network(value, strict=True) if '/' in value else ipaddress.ip_address(value)
    except ValueError as error:
        fail(where, f'invalid address {value!r}: {error}')
    if parsed.version != (4 if family == 'inet' else 6):
        fail(where, f'{value!r} does not belong to {family}')
    return str(parsed)


def family(value, where):
    if value not in FAMILIES:
        fail(where, f'unknown family {value!r}; use inet, inet6 or both')
    return value


def action(value, where):
    if value not in {'ACCEPT', 'DROP', 'REJECT'}:
        fail(where, f'unknown action {value!r}; use ACCEPT, DROP or REJECT')
    return value


def port(value, where):
    if not re.fullmatch(r'[0-9]{1,5}', value, re.ASCII) or not 1 <= int(value) <= 65535:
        fail(where, f'invalid port {value!r}; use a number from 1 to 65535')
    return str(int(value))


def service(value, protocol, where):
    if value == '-':
        return value
    if protocol in ('tcp', 'udp'):
        result = []
        for item in value.split(','):
            bounds = item.split(':')
            if len(bounds) not in (1, 2):
                fail(where, f'invalid port range {item!r}; use first:last')
            bounds = [port(bound, where) for bound in bounds]
            if len(bounds) == 2 and int(bounds[0]) > int(bounds[1]):
                fail(where, f'reversed port range {item!r}')
            result.append(':'.join(bounds))
        return ','.join(result)
    if protocol in ('icmp', 'icmp6'):
        if not re.fullmatch(r'[0-9]{1,3}', value, re.ASCII) or int(value) > 255:
            fail(where, 'ICMP service must be one numeric type from 0 to 255 or -')
        return str(int(value))
    fail(where, 'protocol any requires service -')


def rows(directory, filename, columns, logged=False):
    path = directory / filename
    if not path.exists():
        if path.is_symlink():
            raise ConfigError(f'{filename}: configuration symbolic link has no target')
        if filename in ('zones', 'interfaces', 'policy'):
            raise ConfigError(f'{filename}: required configuration file is missing')
        return
    if not path.is_file():
        raise ConfigError(f'{filename}: expected a regular configuration file')
    for number, raw in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        values = raw.split('#', 1)[0].split()
        if not values:
            continue
        where, log = Location(filename, number), False
        if logged and len(values) == columns + 1:
            flag = values.pop()
            if flag not in ('log', '-'):
                fail(where, 'logging column must be log or -')
            log = flag == 'log'
        if len(values) != columns:
            fail(where, f'expected {columns} columns' + (' and optional logging column' if logged else '') + f', got {len(values)}')
        yield values, log, where


def load_config(directory):
    directory = Path(directory)
    if not directory.is_dir():
        raise ConfigError(f'{directory}: expected a configuration directory')
    unexpected = sorted(p.name for p in directory.iterdir() if not p.name.startswith('.') and p.name not in FILES)
    if unexpected:
        raise ConfigError(f'{directory}: unknown configuration entry {unexpected[0]!r}; expected ' + ', '.join(sorted(FILES)))
    zones, interfaces, groups, settings = {}, {}, {}, {}
    for (key, kind), _, where in rows(directory, 'zones', 2):
        name(key, where)
        if kind not in ('firewall', 'ipv4', 'ipv6', 'dual'):
            fail(where, f'unknown zone type {kind!r}')
        if key in zones:
            fail(where, f'zone {key!r} is already defined at {zones[key].location}')
        zones[key] = Zone(key, kind, where)
    if sum(z.kind == 'firewall' for z in zones.values()) != 1:
        raise ConfigError('zones: define exactly one zone of type firewall')

    def zone(key, where, wildcard=False):
        if key not in zones and not (wildcard and key == 'all'):
            fail(where, f'unknown zone {key!r}; declare it in zones')
        return key

    seen = set()
    for (key, interface, v4, v6), _, where in rows(directory, 'interfaces', 4):
        zone(key, where)
        if zones[key].kind == 'firewall':
            fail(where, 'the firewall zone cannot have an interface binding')
        if key in interfaces:
            fail(where, f'zone {key!r} already has an interface')
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,13}[0-9]', interface, re.ASCII) or re.fullmatch(r'lo[0-9]+', interface):
            fail(where, f'invalid network interface {interface!r}; use one concrete interface ending in a digit, not a group or wildcard')
        if interface in seen:
            fail(where, f'interface {interface!r} is already bound to a zone')
        networks = []
        for value, selected in ((v4, 'inet'), (v6, 'inet6')):
            enabled = selected in zones[key].families
            if (value != '-') != enabled:
                fail(where, f'{key!r} requires ' + (f'a {selected} prefix or any' if enabled else f'- for absent {selected}'))
            if value not in ('-', 'any'):
                if '/' not in value:
                    fail(where, f'interface network {value!r} must be a CIDR prefix')
                value = address(value, selected, where)
                if ipaddress.ip_network(value).prefixlen == 0:
                    fail(where, 'use any for a catchall zone instead of a /0 prefix')
                if any(ipaddress.ip_network(value).overlaps(ipaddress.ip_network(reserved)) for reserved in RESERVED[selected]):
                    fail(where, 'zone prefixes must be routed unicast networks; use settings for link-local control traffic')
            networks.append(None if value == '-' else value)
        interfaces[key] = Interface(key, interface, *networks, where)
        seen.add(interface)
    for key, value in zones.items():
        if value.kind != 'firewall' and key not in interfaces:
            fail(value.location, f'zone {key!r} needs an interface binding')
    for selected in ('inet', 'inet6'):
        catchall = [i for i in interfaces.values() if i.network(selected) == 'any']
        if len(catchall) > 1:
            fail(catchall[1].location, f'only one catchall zone is allowed for {selected}')
        explicit = [i for i in interfaces.values() if i.network(selected) not in (None, 'any')]
        for index, left in enumerate(explicit):
            for right in explicit[index + 1:]:
                if ipaddress.ip_network(left.network(selected)).overlaps(ipaddress.ip_network(right.network(selected))):
                    fail(right.location, f'{selected} prefix overlaps zone {left.zone!r} at {left.location}')

    for (key, selected, members), _, where in rows(directory, 'groups', 3):
        name(key, where)
        if selected not in ('inet', 'inet6'):
            fail(where, 'an address group requires inet or inet6')
        if key in groups:
            fail(where, f'address group {key!r} is already defined')
        groups[key] = Group(key, selected, tuple(dict.fromkeys(address(m, selected, where) for m in members.split(','))), where)

    def common(source, destination, selected, where):
        requested = FAMILIES[family(selected, where)]
        sources = zones.values() if source == 'all' else (zones[source],)
        destinations = zones.values() if destination == 'all' else (zones[destination],)
        supported = {f for s in sources for d in destinations for f in requested if f in s.families and f in d.families}
        if not supported:
            fail(where, 'source and destination have no common address family for this row')
        return supported

    def selector(value, selected, where):
        key, separator, restriction = value.partition(':')
        zone(key, where, wildcard=True)
        if not separator:
            return Selector(key)
        if not restriction:
            fail(where, 'an address selector needs a literal address/prefix or @group')
        if selected == 'both':
            fail(where, 'address-qualified selectors require inet or inet6, not both')
        if restriction.startswith('@'):
            group = groups.get(restriction[1:])
            if group is None:
                fail(where, f'unknown address group {restriction!r}; declare it in groups')
            if group.family != selected:
                fail(where, f'group {group.name!r} belongs to {group.family}, not {selected}')
            members = group.networks
        else:
            restriction = address(restriction, selected, where)
            members = (restriction,)
        if key in interfaces and (network := interfaces[key].network(selected)) not in (None, 'any'):
            if any(not ipaddress.ip_network(m).subnet_of(ipaddress.ip_network(network)) for m in members):
                fail(where, f'address selector is outside zone {key!r} prefix {network}')
        if key in interfaces and interfaces[key].network(selected) == 'any':
            excluded = list(RESERVED[selected])
            excluded.extend(i.network(selected) for i in interfaces.values() if i.network(selected) not in (None, 'any'))
            if not subtract_networks(members, excluded):
                fail(where, f'address selector has no addresses in catchall zone {key!r}')
        return Selector(key, restriction)

    policies, policy_keys = [], set()
    for (source, destination, selected, verdict), log, where in rows(directory, 'policy', 4, logged=True):
        zone(source, where, True)
        zone(destination, where, True)
        common(source, destination, selected, where)
        key = source, destination, selected
        if key in policy_keys:
            fail(where, 'duplicate policy for the same source, destination and family')
        policies.append(Policy(source, destination, selected, action(verdict, where), log, where))
        policy_keys.add(key)
    rules = []
    for (verdict, source, destination, selected, protocol, requested_service), log, where in rows(directory, 'rules', 6, logged=True):
        family(selected, where)
        src, dst = selector(source, selected, where), selector(destination, selected, where)
        common(src.zone, dst.zone, selected, where)
        if protocol not in ('any', 'tcp', 'udp', 'icmp', 'icmp6'):
            fail(where, f'unsupported protocol {protocol!r}; use any, tcp, udp, icmp or icmp6')
        if (protocol == 'icmp' and selected != 'inet') or (protocol == 'icmp6' and selected != 'inet6'):
            fail(where, f'{protocol} requires ' + ('inet' if protocol == 'icmp' else 'inet6'))
        rules.append(Rule(action(verdict, where), src, dst, selected, protocol, service(requested_service, protocol, where), log, where))
    nat, nat_keys = [], set()
    for (source, destination, selected), _, where in rows(directory, 'nat', 3):
        zone(source, where)
        zone(destination, where)
        if selected != 'inet':
            fail(where, 'NAT is IPv4 only; use inet (IPv6 is routed without NAT)')
        common(source, destination, selected, where)
        if source not in interfaces or interfaces[source].ipv4 in (None, 'any'):
            fail(where, 'NAT source must be a zone with an explicit IPv4 prefix')
        if source == destination or destination not in interfaces or interfaces[destination].ipv4 != 'any':
            fail(where, 'NAT destination must be a different IPv4 catchall zone')
        if (source, destination) in nat_keys:
            fail(where, 'duplicate NAT declaration')
        nat.append(Nat(source, destination, selected, where))
        nat_keys.add((source, destination))
    for rule in rules:
        if rule.action != 'ACCEPT' or rule.protocol != 'icmp' or rule.service in ('-', '8'):
            continue
        if any(rule.source.zone in ('all', item.source) and rule.destination.zone in ('all', item.destination) for item in nat):
            fail(rule.location, 'explicit ICMP response/error rules cannot use NAT; related replies and errors already follow states; use icmp-errors for firewall errors')
    forwards, forward_keys = [], set()
    for (source, destination, selected, protocol, public_port, target, target_port), log, where in rows(directory, 'forwards', 7, logged=True):
        if selected != 'inet' or protocol not in ('tcp', 'udp'):
            fail(where, 'port forwards require inet and tcp or udp')
        src = selector(source, selected, where)
        zone(destination, where)
        if src.zone not in interfaces or interfaces[src.zone].ipv4 != 'any':
            fail(where, 'port-forward source must be an IPv4 catchall zone')
        if destination not in interfaces or interfaces[destination].ipv4 in (None, 'any'):
            fail(where, 'port-forward destination must have an explicit IPv4 prefix')
        target = address(target, 'inet', where)
        if '/' in target:
            fail(where, 'port-forward target must be one IPv4 host address')
        target_network = ipaddress.ip_network(interfaces[destination].ipv4)
        target_address = ipaddress.ip_address(target)
        if target_address not in target_network:
            fail(where, 'port-forward target is outside the destination zone')
        if target_network.prefixlen < 31 and target_address in (target_network.network_address, target_network.broadcast_address):
            fail(where, 'port-forward target must be a host, not the subnet or broadcast address')
        public_port, target_port = port(public_port, where), port(target_port, where)
        key = src.zone, protocol, public_port
        if key in forward_keys:
            fail(where, 'overlapping forwards for the same source zone, protocol and public port')
        forwards.append(Forward(src, destination, selected, protocol, public_port, target, target_port, log, where))
        forward_keys.add(key)
    for (key, value), _, where in rows(directory, 'settings', 2):
        if key in BOOL_SETTINGS:
            if value not in ('yes', 'no'):
                fail(where, f'{key} requires yes or no')
        elif key == 'mss':
            if not re.fullmatch(r'[0-9]{1,5}', value, re.ASCII) or not 536 <= int(value) <= 65535:
                fail(where, 'mss requires a number from 536 to 65535')
            value = str(int(value))
        elif key in ZONE_SETTINGS:
            zone(value, where)
            if value not in interfaces:
                fail(where, f'{key} requires a network zone')
            binding = interfaces[value]
            if key.startswith('dhcp-') and binding.ipv4 is None:
                fail(where, f'{key} requires an IPv4-capable zone')
            if key.startswith('ipv6-') and binding.ipv6 is None:
                fail(where, f'{key} requires an IPv6-capable zone')
            if key == 'dhcp-server' and binding.ipv4 == 'any':
                fail(where, 'dhcp-server requires an explicit inside IPv4 prefix')
            if key == 'dhcp-client' and binding.ipv4 != 'any':
                fail(where, 'dhcp-client requires an IPv4 catchall zone')
            if key == 'ipv6-router' and binding.ipv6 == 'any':
                fail(where, 'ipv6-router requires an explicit inside IPv6 prefix')
            if key == 'ipv6-client' and binding.ipv6 != 'any':
                fail(where, 'ipv6-client requires an IPv6 catchall zone')
        else:
            fail(where, f'unknown setting {key!r}')
        if key in settings and (key not in ZONE_SETTINGS or key == 'loginterface' or value in settings[key]):
            fail(where, f'duplicate setting {key!r}')
        if key.startswith('ipv6-'):
            for other in ('ipv6-neighbor', 'ipv6-router', 'ipv6-client'):
                if value in settings.get(other, ()):
                    fail(where, f'zone {value!r} already has {other}; choose one IPv6 control role')
        settings.setdefault(key, []).append(value)
    return Config(zones, interfaces, groups, tuple(policies), tuple(rules), tuple(nat), tuple(forwards), {key: tuple(values) for key, values in settings.items()})
