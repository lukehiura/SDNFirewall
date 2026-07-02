#!/usr/bin/python
# CS 6250 Fall 2025- SDN Firewall Project with POX
# build gibson-29

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.revent import *
from pox.lib.addresses import EthAddr

# You may use this space before the firewall_policy_processing function to add any extra function that you 
# may need to complete your firewall implementation.  No additional functions "should" be required to complete
# this assignment.


def firewall_policy_processing(policies):
    rules = []

    for policy in policies:
        rule = of.ofp_flow_mod()

        has_ip_match = any(policy[field] != '-' for field in (
            'ip-src', 'ip-dst', 'ipprotocol', 'port-src', 'port-dst'
        ))

        if has_ip_match:
            rule.match.dl_type = 0x0800  # IPv4

        if policy['mac-src'] != '-':
            rule.match.dl_src = EthAddr(policy['mac-src'])

        if policy['mac-dst'] != '-':
            rule.match.dl_dst = EthAddr(policy['mac-dst'])

        if policy['ip-src'] != '-':
            rule.match.nw_src = policy['ip-src']

        if policy['ip-dst'] != '-':
            rule.match.nw_dst = policy['ip-dst']

        if policy['ipprotocol'] != '-':
            rule.match.nw_proto = int(policy['ipprotocol'])

        if policy['port-src'] != '-':
            rule.match.tp_src = int(policy['port-src'])

        if policy['port-dst'] != '-':
            rule.match.tp_dst = int(policy['port-dst'])

        if policy['action'] == 'Allow':
            rule.priority = 20000
            rule.actions.append(
                of.ofp_action_output(port=of.OFPP_NORMAL)
            )
        else:
            rule.priority = 10000

        print('Added Rule ', policy['rulenum'], ': ', policy['comment'])
        rules.append(rule)

    return rules
