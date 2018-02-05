# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pox.core import core
from pprint import pprint
# IPAddr is only IPv4 address!!!
from pox.lib.addresses import EthAddr, IPAddr
import pox.openflow.libopenflow_01 as of
import csv
import datetime

log = core.getLogger()


class Firewall (object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.mac_to_port = {}
        log.debug('MAC table setup')
        log.debug('Parsing firewall rules')
        self.firewall = read_firewall_rules()

    def allowed_by_firewall(self, layers234_data):
        for rule in self.firewall:
            blocked = False
            layer = '2' # for logging, default to layer 2
            if l2_rule(rule) and match_mac(rule, layers234_data):
                blocked = True
            elif l34_rule(rule) and match_ip(rule, layers234_data) and match_dst_port(rule, layers234_data):
                blocked = True
                layer = '3'
                if len(rule) > 3:
                    try:
                        int(rule[3])
                        layer = '4'
                    except ValueError:
                        log.debug('Cannot parse port in rule ===> it is a layer 3 rule')

            if blocked:
                log.debug(
                        '==============(Rule matched) \n %s Layer %s \n ===> Dropping packet %s', yellow(str(rule)), blue(layer), underline(yellow(str(layers234_data))))
                return False

        log.debug(
            '%s %s',
            yellow('Matched NO rules, allowing by default:'),
            green(str(layers234_data)))
        return True

    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def act_like_switch(self, packet, packet_in, layers234_data):
        log.debug("packet_in.in_port " + str(packet_in.in_port))

        self.mac_to_port[str(packet.src)] = packet_in.in_port

        # Firewall functionality (start)
        if not self.allowed_by_firewall(layers234_data):
            log.warning("Ignoring packet blocked by firewall")
            return
        # Firewall functionality (end)

        if str(packet.dst) in self.mac_to_port:

            ### Timestamps for Debugging    ###
            time = datetime.datetime.now().strftime('%H:%M:%S')
            log.debug("%s: Installing flow... %s-%i => %s-%i" % (time,
                                                                 packet.src,
                                                                 packet_in.in_port,
                                                                 packet.dst,
                                                                 self.mac_to_port[str(packet.dst)]))

            msg = of.ofp_flow_mod()  # Start Modifying the flow
            msg.match = of.ofp_match.from_packet(packet)
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.actions.append(of.ofp_action_output(
                port=self.mac_to_port[str(packet.dst)]))
            msg.buffer_id = packet_in.buffer_id

            self.connection.send(msg)  # Set the modification

        else:
            # Flood the packet out everything but the input port
            log.debug(underline(green('Flood')))
            self.resend_packet(packet_in, of.OFPP_ALL)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        packet_in = event.ofp

        self.act_like_switch(packet, packet_in, get_layers_234_data(packet))


def launch():
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Firewall(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)


# ==================================
# Firewall helpers (start)
# ==================================


def read_firewall_rules():
    # array of rules
    firewall = []
    with open('pox/misc/firewall.csv', 'rb') as csvfile:
        log.debug(yellow('Added firewall rules:'))
        for rule in csv.reader(csvfile, delimiter=','):
            if len(rule) == 0:
                continue
            if rule[0] == 'mac':
                if rule[1] != '*':
                    # Parse the MAC address in the rule in to an EthAddr object
                    rule[1] = EthAddr(rule[1])
                if rule[2] != '*':
                    # Parse the MAC address in the rule in to an EthAddr object
                    rule[2] = EthAddr(rule[2])
            elif rule[0] == 'ip':
                if rule[1] != '*':
                    # Parse the IP address in the rule in to an IPAddr object
                    rule[1] = IPAddr(rule[1])
                if rule[2] != '*':
                    # Parse the IP address in the rule in to an IPAddr object
                    rule[2] = IPAddr(rule[2])
            else:
                log.debug(
                    yellow(
                        'Skipping wrongly formatted rule:' +
                        ','.join(rule)))
                continue
            log.debug(blue(str(rule)))
            firewall.append(rule)
    return firewall


def get_layers_234_data(packet):
    layers234_data = {}
    layer2 = packet
    if hasattr(layer2, 'src'):
        # Collect source MAC address
        layers234_data['src_mac'] = layer2.src
    if hasattr(layer2, 'dst'):
        # Collect destination MAC address
        layers234_data['dst_mac'] = layer2.dst
    if hasattr(layer2, 'next'):
        layer3 = layer2.next
        if hasattr(layer3, 'srcip'):
            if isinstance(layer3.srcip, IPAddr):
                # Collect source IP address
                layers234_data['src_ip'] = layer3.srcip
        if hasattr(layer3, 'dstip'):
            if isinstance(layer3.dstip, IPAddr):
                # Collect destination IP address
                layers234_data['dst_ip'] = layer3.dstip
        if hasattr(layer3, 'next'):
            layer4 = layer3.next
            if hasattr(layer4, 'dstport'):
                # Collect destination port
                layers234_data['dst_port'] = layer4.dstport
    return layers234_data


def l2_rule(rule):
    # rule is a layer 2 rule
    return rule[0] == 'mac'


def l34_rule(rule):
    # rule is either a layer 3 or layer 4 rule
    return rule[0] == 'ip'


def match_mac(rule, layers234_data):
    # Check whether object is a string first because it can be an EthAddr object
    if (isinstance(rule[1], str) and rule[1] ==
            '*') or (isinstance(rule[2], str) and rule[2] == '*'):
        return True

    if 'src_mac' in layers234_data and 'dst_mac' in layers234_data:
        return (rule[1] == layers234_data['src_mac'] and rule[2] == layers234_data['dst_mac']) or (
            rule[2] == layers234_data['src_mac'] and rule[1] == layers234_data['dst_mac'])
    return False


def match_ip(rule, layers234_data):
    # Check whether object is a string first because it can be an IPAddr object
    if (isinstance(rule[1], str) and rule[1] ==
            '*') or (isinstance(rule[2], str) and rule[2] == '*'):
        return True

    if 'src_ip' in layers234_data and 'dst_ip' in layers234_data:
        return (rule[1] == layers234_data['src_ip'] and rule[2] == layers234_data['dst_ip']) or (
            rule[2] == layers234_data['src_ip'] and rule[1] == layers234_data['dst_ip'])
    return False


def match_dst_port(rule, layers234_data):
    if len(rule) <= 3:
        # In case the port is not specified in the rule
        return True

    if rule[3] == '*' or rule[3] == '':
        return True

    if 'dst_port' in layers234_data:
        return rule[3] == str(layers234_data['dst_port'])
    return False

# ==================================
# Firewall helpers (end)
# ==================================
# ==================================
# Helpers (start)
# ==================================


def blue(msg):
    return '\033[94m' + msg + '\033[0m'


def green(msg):
    return '\033[92m' + msg + '\033[0m'


def yellow(msg):
    return '\033[93m' + msg + '\033[0m'


def underline(msg):
    return '\033[4m' + msg + '\033[0m'


def inspect_object(obj):
    """
    For inspecting packet object
    """
    pprint(vars(obj))

# ==================================
# Helpers (end)
# ==================================
