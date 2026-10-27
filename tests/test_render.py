"""Security properties of the PF lowering, independent of config parsing."""

from dataclasses import replace
import unittest

from makepf.model import Config, Forward, Group, Interface, Location, Nat, Policy, Rule, Selector, Zone
from makepf.render import render


LOC = Location("rules", 1)


def fixture(**changes):
    config = Config(
        zones={name: Zone(name, kind, LOC) for name, kind in
               (("fw", "firewall"), ("net", "dual"), ("loc", "dual"), ("dmz", "dual"))},
        interfaces={
            "vio0": Interface("net", "vio0", "any", "any", LOC),
            "vio1": Interface("loc", "vio1", "192.0.2.0/24", "2001:db8:1::/64", LOC),
            "vio2": Interface("dmz", "vio2", "198.51.100.0/24", "2001:db8:2::/64", LOC),
        },
        groups={},
        policies=(Policy("loc", "net", "both", "ACCEPT", False, LOC),
                  Policy("all", "all", "both", "DROP", False, LOC)),
        rules=(), nat=(Nat("loc", "net", "inet", LOC),), forwards=(), settings={},
    )
    return replace(config, **changes)


class RenderTests(unittest.TestCase):
    def test_interface_bound_pair_checks_routed_output(self):
        text = render(fixture())
        self.assertIn("set state-policy if-bound", text)
        self.assertIn("pass in quick on vio1 inet from <mp_loc_4> to <mp_net_4> keep state (if-bound)", text)
        self.assertIn("pass out quick on vio0 inet from <mp_loc_4> to <mp_net_4> received-on vio1 nat-to (vio0) keep state (if-bound)", text)
        self.assertIn("pass out quick on vio0 inet6 from <mp_loc_6> to <mp_net_6> received-on vio1 keep state (if-bound)", text)
        self.assertNotIn("floating", text)
        self.assertNotIn("match out", text)

    def test_catchall_excludes_internal_and_link_local_destinations(self):
        text = render(fixture())
        line = next(line for line in text.splitlines() if line.startswith("table <mp_net_6>"))
        self.assertIn("!2001:db8:1::/64", line)
        self.assertIn("!2001:db8:2::/64", line)
        self.assertIn("!fe80::/10", line)
        self.assertIn("!ff00::/8", line)
        self.assertIn("block in quick on vio0 inet6 from ! <mp_net_6> to any", text)
        self.assertIn("block in quick on vio1 inet from ! <mp_loc_4> to any", text)

    def test_firewall_membership_is_dynamic_and_local_origin_is_explicit(self):
        rules = (
            Rule("ACCEPT", Selector("loc"), Selector("fw", "192.0.2.1"), "inet", "tcp", "22", False, LOC),
            Rule("ACCEPT", Selector("fw"), Selector("net"), "both", "udp", "53", False, LOC),
        )
        text = render(fixture(rules=rules))
        self.assertIn('anchor "makepf_local" in to (self) {', text)
        self.assertIn("pass in quick on vio1 inet proto tcp from <mp_loc_4> to 192.0.2.1/32 port 22", text)
        self.assertIn('anchor "makepf_origin" out from (self) ! received-on any {', text)
        self.assertIn("pass out quick on vio0 inet proto udp from any to <mp_net_4> port 53", text)
        self.assertLess(text.index('anchor "makepf_local"'), text.index("# Forwarded traffic"))

    def test_selector_cannot_expand_access_outside_its_zone(self):
        rule = Rule("ACCEPT", Selector("loc", "0.0.0.0/0"), Selector("net", "0.0.0.0/0"),
                    "inet", "tcp", "443", False, LOC)
        text = render(fixture(rules=(rule,)))
        accepted = [line for line in text.splitlines() if line.startswith("pass in quick on vio1 inet proto tcp")]
        self.assertEqual(len(accepted), 1)
        self.assertIn("from 192.0.2.0/24", accepted[0])
        self.assertNotIn("to 0.0.0.0/0", accepted[0])

    def test_redirect_permission_requires_translation_tag(self):
        forward = Forward(Selector("net"), "dmz", "inet", "tcp", "80", "198.51.100.10", "8080", True, LOC)
        denied = Rule("DROP", Selector("net"), Selector("dmz"), "inet", "tcp", "8080", True, LOC)
        text = render(fixture(forwards=(forward,), rules=(denied,)))
        self.assertIn("to (vio0) port 80 tag mp_rdr_1 rdr-to 198.51.100.10 port 8080", text)
        self.assertIn("pass in log quick on vio0 inet proto tcp from <mp_net_4> to 198.51.100.10/32 port 8080 tagged mp_rdr_1 keep state (if-bound)", text)
        self.assertIn("pass out log quick on vio2 inet proto tcp from <mp_net_4> to 198.51.100.10/32 port 8080 received-on vio0 tagged mp_rdr_1 keep state (if-bound)", text)
        self.assertLess(text.index("block drop in log quick on vio0 inet proto tcp"),
                        text.index("pass in log quick on vio0 inet proto tcp"))

    def test_router_advertisement_roles_and_icmp_errors_are_local(self):
        text = render(fixture(settings={"ipv6-router": ("loc",), "ipv6-client": ("net",), "icmp-errors": ("yes",)}))
        lines = text.splitlines()
        self.assertTrue(any(line.startswith("pass in quick on vio0") and "icmp6-type 134" in line for line in lines))
        self.assertFalse(any(line.startswith("pass in quick on vio1") and "icmp6-type 134" in line for line in lines))
        self.assertTrue(any(line.startswith("pass out quick on vio1") and "icmp6-type 134" in line and "! received-on any" in line for line in lines))
        for line in lines:
            if "icmp6-type { 1, 2, 3, 4 }" in line:
                self.assertIn("no state", line)
                self.assertTrue("to (self)" in line or "! received-on any" in line)

    def test_groups_are_intersected_and_output_is_repeatable(self):
        group = Group("clients", "inet", ("192.0.2.15/32", "203.0.113.10/32"), LOC)
        rule = Rule("ACCEPT", Selector("loc", "@clients"), Selector("net"), "inet", "udp", "53", False, LOC)
        config = fixture(groups={"clients": group}, rules=(rule,))
        text = render(config)
        self.assertIn("from 192.0.2.15/32 to <mp_net_4> port 53", text)
        self.assertNotIn("203.0.113.10", text)
        self.assertEqual(text, render(config))

    def test_explicit_icmp_replies_are_stateless(self):
        rules = (Rule("ACCEPT", Selector("net"), Selector("fw"), "inet6", "icmp6", "129", False, LOC),)
        text = render(fixture(rules=rules))
        self.assertIn("icmp6-type 129 no state", text)
        self.assertNotIn("icmp6-type 129 keep state", text)

    def test_only_redundant_unlogged_final_drop_is_omitted(self):
        final = Policy("all", "all", "both", "DROP", True, LOC)
        logged = render(fixture(policies=(final,)))
        self.assertIn("block drop in log quick on vio0", logged)
        default = render(fixture(policies=(replace(final, log=False),)))
        self.assertNotIn("block drop in quick on vio0", default)


if __name__ == "__main__":
    unittest.main()
