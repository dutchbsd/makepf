"""Validated configuration records shared by the parser and PF renderer."""

from dataclasses import dataclass
from ipaddress import ip_network


RESERVED = {
    "inet": ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"),
    "inet6": ("::/128", "::1/128", "fe80::/10", "ff00::/8"),
}


def subtract_networks(networks, exclusions):
    """Return the portions of networks outside the excluded address ranges."""
    remaining = [ip_network(network) for network in networks]
    for value in exclusions:
        excluded = ip_network(value)
        result = []
        for network in remaining:
            if network.subnet_of(excluded):
                continue
            if excluded.subnet_of(network):
                result.extend(network.address_exclude(excluded))
            else:
                result.append(network)
        remaining = result
    return remaining


class ConfigError(ValueError):
    """An input or output error suitable for a command-line diagnostic."""


@dataclass(frozen=True)
class Location:
    file: str
    line: int

    def __str__(self):
        return f"{self.file}:{self.line}"


@dataclass(frozen=True)
class Zone:
    name: str
    kind: str
    location: Location

    @property
    def families(self):
        return {"ipv4": ("inet",), "ipv6": ("inet6",),
                "dual": ("inet", "inet6"), "firewall": ("inet", "inet6")}[self.kind]


@dataclass(frozen=True)
class Interface:
    zone: str
    name: str
    ipv4: str | None
    ipv6: str | None
    location: Location

    def network(self, family):
        return self.ipv4 if family == "inet" else self.ipv6


@dataclass(frozen=True)
class Selector:
    zone: str
    address: str = "any"


@dataclass(frozen=True)
class Group:
    name: str
    family: str
    networks: tuple[str, ...]
    location: Location


@dataclass(frozen=True)
class Policy:
    source: str
    destination: str
    family: str
    action: str
    log: bool
    location: Location


@dataclass(frozen=True)
class Rule:
    action: str
    source: Selector
    destination: Selector
    family: str
    protocol: str
    service: str
    log: bool
    location: Location


@dataclass(frozen=True)
class Nat:
    source: str
    destination: str
    family: str
    location: Location


@dataclass(frozen=True)
class Forward:
    source: Selector
    destination: str
    family: str
    protocol: str
    public_port: str
    target: str
    target_port: str
    log: bool
    location: Location


@dataclass(frozen=True)
class Config:
    zones: dict[str, Zone]
    interfaces: dict[str, Interface]
    groups: dict[str, Group]
    policies: tuple[Policy, ...]
    rules: tuple[Rule, ...]
    nat: tuple[Nat, ...]
    forwards: tuple[Forward, ...]
    settings: dict[str, tuple[str, ...]]

    @property
    def firewall(self):
        return next(zone.name for zone in self.zones.values() if zone.kind == "firewall")
