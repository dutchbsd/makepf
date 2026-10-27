"""Configuration contracts exercised through complete configuration directories."""

from pathlib import Path
import tempfile
import unittest

from makepf.config import load_config
from makepf.model import ConfigError


PROJECT = Path(__file__).resolve().parents[1]
BASE = {
    "zones": "fw firewall\nnet dual\nloc dual\nwifi dual\n",
    "interfaces": (
        "net vio0 any any\n"
        "loc vio1 192.168.1.0/24 2001:db8:1::/64\n"
        "wifi vio2 192.168.2.0/24 2001:db8:2::/64\n"
    ),
    "policy": "loc net both ACCEPT\nall all both DROP\n",
}


class ConfigurationTests(unittest.TestCase):
    def load(self, changes=None, missing=()):
        files = BASE | (changes or {})
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for filename, content in files.items():
                if filename not in missing:
                    (directory / filename).write_text(content, encoding="utf-8")
            return load_config(directory)

    def assert_invalid(self, changes, message, missing=()):
        with self.assertRaisesRegex(ConfigError, message):
            self.load(changes, missing)

    def test_reference_examples_are_complete_valid_inputs(self):
        for example in ("handbook", "faq", "dual-stack"):
            with self.subTest(example=example):
                config = load_config(PROJECT / "examples" / example)
                self.assertEqual(config.firewall, "fw")
                self.assertTrue(config.nat)
        dual = load_config(PROJECT / "examples" / "dual-stack")
        self.assertEqual(dual.settings["ipv6-router"], ("loc", "wifi"))
        self.assertTrue(any(rule.family == "inet6" for rule in dual.rules))

    def test_optional_files_can_be_absent(self):
        config = self.load()
        self.assertEqual(config.rules, ())
        self.assertEqual(config.forwards, ())
        self.assertEqual(config.settings, {})

    def test_dangling_optional_symlink_does_not_silently_remove_denials(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for filename, content in BASE.items():
                (directory / filename).write_text(content, encoding="utf-8")
            (directory / "rules").symlink_to(directory / "missing-denials")
            with self.assertRaisesRegex(ConfigError, "rules:.*symbolic link"):
                load_config(directory)

    def test_comments_locations_and_transport_services(self):
        config = self.load({
            "rules": (
                "# Allow management from the trusted network.\n\n"
                "  ACCEPT\tloc fw both tcp 0022,8000:8002 log # explicit log\n"
            ),
        })
        rule = config.rules[0]
        self.assertEqual(rule.service, "22,8000:8002")
        self.assertTrue(rule.log)
        self.assertEqual(str(rule.location), "rules:3")

    def test_zone_prefixes_cannot_be_nonrouted_control_networks(self):
        for v4, v6 in (("127.0.0.0/8", "2001:db8:1::/64"), ("192.168.1.0/24", "fe80::/64"),
                       ("224.0.0.0/4", "2001:db8:1::/64"), ("192.168.1.0/24", "ff02::/16")):
            with self.subTest(v4=v4, v6=v6):
                self.assert_invalid({"interfaces": f"net vio0 any any\nloc vio1 {v4} {v6}\nwifi vio2 192.168.2.0/24 2001:db8:2::/64\n"}, "routed unicast")

    def test_interface_groups_and_wildcards_cannot_widen_a_zone_binding(self):
        for interface in ("egress", "all", "any", "wlan", "em"):
            with self.subTest(interface=interface):
                self.assert_invalid({"interfaces": BASE["interfaces"].replace("net vio0", "net " + interface)}, "concrete interface")

    def test_explicit_icmp_responses_do_not_silently_bypass_nat(self):
        self.assert_invalid({"nat": "loc net inet\n", "rules": "ACCEPT loc net inet icmp 0\n"}, "ICMP response/error rules cannot use NAT")
        self.load({"nat": "loc net inet\n", "rules": "ACCEPT loc net inet icmp 8\n"})

    def test_forward_target_cannot_be_subnet_or_broadcast(self):
        for target in ("192.168.1.0", "192.168.1.255"):
            with self.subTest(target=target):
                self.assert_invalid({"forwards": f"net loc inet tcp 80 {target} 80\n"}, "subnet or broadcast")

    def test_catchall_selector_cannot_silently_disappear(self):
        self.assert_invalid({"rules": "DROP loc net:192.168.1.10 inet tcp 443 log\n"}, "no addresses in catchall")
        self.assert_invalid({"groups": "inside inet 192.168.1.0/24,192.168.2.0/24\n",
                             "rules": "DROP loc net:@inside inet any -\n"}, "no addresses in catchall")
        config = self.load({"groups": "mixed inet 192.168.1.0/24,198.18.0.0/15\n",
                            "rules": "DROP net:@mixed all inet any -\n"})
        self.assertEqual(config.rules[0].source.address, "@mixed")

    def test_ipv6_selectors_preserve_address_colons(self):
        config = self.load({
            "groups": "admins inet6 2001:db8:1::10,2001:db8:1::11\n",
            "rules": (
                "ACCEPT loc:@admins fw inet6 tcp 22\n"
                "ACCEPT net loc:2001:db8:1::2 inet6 tcp 443\n"
            ),
        })
        self.assertEqual(config.rules[0].source.address, "@admins")
        self.assertEqual(config.rules[1].destination.address, "2001:db8:1::2")

    def test_both_uses_available_common_families(self):
        changes = {
            "zones": "fw firewall\nnet dual\nloc ipv4\nwifi ipv6\n",
            "interfaces": (
                "net vio0 any any\nloc vio1 192.168.1.0/24 -\n"
                "wifi vio2 - 2001:db8:2::/64\n"
            ),
            "policy": "loc net both ACCEPT\nwifi net both ACCEPT\nall all both DROP\n",
            "rules": "ACCEPT all fw both tcp 22\n",
        }
        self.assertEqual(len(self.load(changes).policies), 3)
        changes["rules"] = "ACCEPT loc wifi both tcp 22\n"
        self.assert_invalid(changes, "rules:1:.*no common address family")

    def test_unknown_references_and_column_errors_have_locations(self):
        cases = (
            ({"rules": "# Comment\nACCEPT typo fw both tcp 22\n"}, "rules:2:.*unknown zone"),
            ({"rules": "ACCEPT loc:@missing fw inet tcp 22\n"}, "rules:1:.*unknown address group"),
            ({"rules": "ACCEPT loc fw both tcp\n"}, "rules:1:.*expected 6 columns"),
            ({"policy": "loc net both ACCEPT\nloc net both DROP\n"}, "policy:2:.*duplicate policy"),
            ({"rules": "ACCEPT loc fw both tcp 22 verbose\n"}, "rules:1:.*logging column"),
        )
        for changes, message in cases:
            with self.subTest(changes=changes):
                self.assert_invalid(changes, message)

    def test_names_and_interfaces_cannot_be_pf_expressions(self):
        cases = (
            {"zones": "fw firewall\nall dual\n"},
            {"zones": BASE["zones"] + "fw firewall\n"},
            {"zones": BASE["zones"].replace("net dual", "Net dual")},
            {"interfaces": BASE["interfaces"].replace("vio0", "(egress)")},
            {"interfaces": BASE["interfaces"].replace("vio0", "lo0")},
            {"interfaces": BASE["interfaces"].replace("vio2", "vio1")},
            {"groups": "all inet 203.0.113.1\n"},
            {"groups": "blocked inet (self)\n"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assert_invalid(changes, "zones:|interfaces:|groups:")

    def test_networks_are_unambiguous_and_match_declared_families(self):
        cases = (
            (BASE["interfaces"].replace("192.168.2.0/24", "192.168.1.128/25"), "overlaps zone"),
            (BASE["interfaces"].replace("2001:db8:2::/64", "2001:db8:1::/65"), "overlaps zone"),
            (BASE["interfaces"].replace("192.168.2.0/24", "any"), "only one catchall"),
            (BASE["interfaces"].replace("192.168.1.0/24", "192.168.1.2/24"), "invalid address"),
            (BASE["interfaces"].replace("192.168.1.0/24", "0.0.0.0/0"), "use any"),
            (BASE["interfaces"].replace("2001:db8:1::/64", "-"), "requires.*inet6"),
        )
        for interfaces, message in cases:
            with self.subTest(interfaces=interfaces):
                self.assert_invalid({"interfaces": interfaces}, "interfaces:.*" + message)

    def test_address_qualifiers_cannot_escape_the_zone_or_family(self):
        cases = (
            {"rules": "ACCEPT loc:192.168.2.2 fw inet tcp 22\n"},
            {"rules": "ACCEPT loc:192.168.1.2 fw both tcp 22\n"},
            {"rules": "ACCEPT loc:2001:db8:1::2 fw inet tcp 22\n"},
            {"rules": "ACCEPT loc:fe80::1%vio1 fw inet6 tcp 22\n"},
            {"groups": "admins inet 192.168.1.10\n", "rules": "ACCEPT loc:@admins fw inet6 tcp 22\n"},
            {"groups": "admins inet 192.168.1.10,192.168.2.10\n", "rules": "ACCEPT loc:@admins fw inet tcp 22\n"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assert_invalid(changes, "rules:1:")

    def test_malformed_protocols_and_services_are_rejected(self):
        requests = (
            "both tcp ssh", "both tcp 0", "both tcp 65536", "both tcp 90:80",
            "both tcp 22,", "both any 22", "both esp -", "inet6 icmp 8",
            "inet icmp6 128", "inet6 icmp6 256", "both tcp $(id)",
        )
        for request in requests:
            with self.subTest(request=request):
                self.assert_invalid({"rules": f"ACCEPT loc fw {request}\n"}, "rules:1:")

    def test_nat_requires_an_explicit_inside_and_ipv4_catchall(self):
        for nat in ("loc net inet6", "fw net inet", "loc wifi inet", "net loc inet", "loc net inet\nloc net inet"):
            with self.subTest(nat=nat):
                self.assert_invalid({"nat": nat + "\n"}, "nat:")
        self.assertEqual(len(self.load({"nat": "loc net inet\nwifi net inet\n"}).nat), 2)

    def test_forwards_require_bounded_ipv4_host_targets_and_ports(self):
        entries = (
            "net loc inet6 tcp 443 2001:db8:1::2 443",
            "loc wifi inet tcp 443 192.168.2.2 443",
            "net net inet tcp 443 203.0.113.2 443",
            "net loc inet tcp 443 192.168.2.2 443",
            "net loc inet tcp 443 192.168.1.2/32 443",
            "net loc inet tcp 80,443 192.168.1.2 443",
            "net loc inet tcp 443 192.168.1.2 0",
        )
        for entry in entries:
            with self.subTest(entry=entry):
                self.assert_invalid({"forwards": entry + "\n"}, "forwards:1:")
        self.assert_invalid({"forwards": (
            "net:203.0.113.1 loc inet tcp 443 192.168.1.2 443\n"
            "net:203.0.113.2 loc inet tcp 443 192.168.1.3 443\n"
        )}, "forwards:2:.*overlapping forwards")

    def test_link_services_do_not_silently_choose_an_inappropriate_role(self):
        settings = (
            "dhcp-client loc", "dhcp-server net", "ipv6-router net", "ipv6-client loc",
            "ipv6-neighbor loc\nipv6-router loc", "dhcp-server fw", "normalize maybe",
            "normalize yes\nnormalize no", "mss 128", "unknown yes",
        )
        for setting in settings:
            with self.subTest(setting=setting):
                self.assert_invalid({"settings": setting + "\n"}, "settings:")

    def test_file_namespace_catches_typos_but_ignores_hidden_notes(self):
        self.assert_invalid({"ruels": "ACCEPT net fw both any -\n"}, "unknown configuration entry 'ruels'")
        self.assertEqual(self.load({".notes": "not configuration"}).firewall, "fw")
        self.assert_invalid({}, "policy: required configuration file", missing=("policy",))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "file"
            path.write_text("not a directory", encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "expected a configuration directory"):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
