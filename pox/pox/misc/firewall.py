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
# IPAddr is IPv4 address, fucking docs !!!
from pox.lib.addresses import EthAddr, IPAddr, IPAddr6
import pox.openflow.libopenflow_01 as of
import csv

# TODO:
# Ether any
# Transport
# act like a switch
# IPv6

log = core.getLogger()


class Firewall (object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.mac_to_port = {}
        log.debug('Parsing firewall rules')
        self.firewall = read_firewall_rules()

    def can_send_packet(self, packet, packet_in, layers234_data):
        for rule in self.firewall:
            if l2_rule(rule) and match_mac(rule, layers234_data):
                log.debug('==============(Rule matched) \n %s %s \n ===> Dropping packet %s',
                    yellow(str(rule)), blue('Layer 2'), underline(yellow(str(layers234_data))))
                return False
            elif l34_rule(rule) and match_ip(rule, layers234_data) and match_dst_port(rule, layers234_data):
                layer = '4'
                if rule[3] == '*' or rule[3] == '':
                     layer = '3'
                log.debug('==============(Rule matched) \n %s Layer %s \n ===> Dropping packet %s',
                    yellow(str(rule)), blue(layer), underline(yellow(str(layers234_data))))
                return False
        log.debug('%s %s', yellow('Matched NO rules, allowing by default:'), green(str(layers234_data)))
        return True

    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def act_like_hub(self, packet, packet_in, layers234_data):
        """
        Implement hub-like behavior -- send all packets to all ports besides
        the input port.
        """
        if self.can_send_packet(packet, packet_in, layers234_data):
            self.resend_packet(packet_in, of.OFPP_ALL)
        # self.resend_packet(packet_in, of.OFPP_ALL)

    def act_like_switch(self, packet, packet_in):
        # Learn the port for the source MAC
        if packet.src not in self.mac_to_port:
            log.debug(
                "Learned %s from Port %d!" %
                (packet.src, packet_in.in_port))
            self.mac_to_port[packet.src] = packet_in.in_port

        if packet.dst in self.mac_to_port:
            # Send packet out the associated port
            log.debug("CAM table hit, sending out packet to Port %d" %
                      self.mac_to_port[packet.dst])
            self.resend_packet(packet_in, self.mac_to_port[packet.dst])

            log.debug("Installing flow ...")
            #log.debug("MATCH: In Port =  %s" % packet_in.in_port)
            # log.debug("MATCH: Source MAC =  %s" % packet.src)
            log.debug("MATCH: Destination MAC =  %s" % packet.dst)
            log.debug("ACTION: Out Port =  %s" % self.mac_to_port[packet.dst])

            msg = of.ofp_flow_mod()
            #msg.match.in_port = self.mac_to_port[packet.src]
            #msg.match.dl_src = packet.src
            msg.match.dl_dst = packet.dst
            msg.actions.append(of.ofp_action_output(
                port=self.mac_to_port[packet.dst]))
            msg.idle_timeout = 60
            msg.hard_timeout = 600
            # msg.buffer_id = packet_in.buffer_id
            self.connection.send(msg)

        else:
            # Flood the packet out everything but the input port
            self.resend_packet(packet_in, of.OFPP_ALL)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        packet_in = event.ofp

        self.act_like_hub(packet, packet_in, get_layers_234_data(packet))
        #self.act_like_switch(packet, packet_in)


def launch():
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Firewall(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)


# ==================================
# Firewall helpers (start)
# ==================================


def read_firewall_rules():
    firewall = []
    with open('pox/misc/firewall.csv', 'rb') as csvfile:
        log.debug(yellow('Added firewall rules:'))
        for rule in csv.reader(csvfile, delimiter=','):
            if rule[0] == 'mac':
                if rule[1] != '*':
                    rule[1] = EthAddr(rule[1])
                if rule[2] != '*':
                    rule[2] = EthAddr(rule[2])
            elif rule[0] == 'ip':
                if rule[1] != '*':
                    rule[1] = IPAddr(rule[1])
                if rule[2] != '*':
                    rule[2] = IPAddr(rule[2])
            else:
                log.debug(yellow('Skipping wrongly formatted rule:' + ','.join(rule)))
                continue
            log.debug(blue(str(rule)))
            firewall.append(rule)
    return firewall


def get_layers_234_data(packet):
    layers234_data = {}
    layer2 = packet
    if hasattr(layer2, 'src'):
        layers234_data['src_mac'] = layer2.src
    if hasattr(layer2, 'dst'):
        layers234_data['dst_mac'] = layer2.dst
    if hasattr(layer2, 'next'):
        layer3 = layer2.next
        if hasattr(layer3, 'srcip'):
            if isinstance(layer3.srcip, IPAddr):
                layers234_data['src_ip'] = layer3.srcip
        if hasattr(layer3, 'dstip'):
            if isinstance(layer3.dstip, IPAddr):
                layers234_data['dst_ip'] = layer3.dstip
        if hasattr(layer3, 'next'):
            layer4 = layer3.next
            # if hasattr(layer4, 'srcport'):
            #   layers234_data['src_port'] = layer4.srcport
            if hasattr(layer4, 'dstport'):
                layers234_data['dst_port'] = layer4.dstport
    return layers234_data


def l2_rule(rule):
    return rule[0] == 'mac'


def l34_rule(rule):
    return rule[0] == 'ip'


def match_mac(rule, layers234_data):
    if (isinstance(rule[1], str) and rule[1] == '*') or (isinstance(rule[2], str) and rule[2] == '*'):
        return True

    if 'src_mac' in layers234_data and 'dst_mac' in layers234_data:
        return (rule[1] == layers234_data['src_mac'] and rule[2] == layers234_data['dst_mac']) or (rule[2] == layers234_data['src_mac'] and rule[1] == layers234_data['dst_mac'])
    return False


def match_ip(rule, layers234_data):
    if (isinstance(rule[1], str) and rule[1] == '*') or (isinstance(rule[2], str) and rule[2] == '*'):
        return True

    if 'src_ip' in layers234_data and 'dst_ip' in layers234_data:
        return (rule[1] == layers234_data['src_ip'] and rule[2] == layers234_data['dst_ip']) or (rule[2] == layers234_data['src_ip'] and rule[1] == layers234_data['dst_ip'])
    return False


def match_dst_port(rule, layers234_data):
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


def header(msg):
    return '\033[95m' + msg + '\033[0m'


def blue(msg):
    return '\033[94m' + msg + '\033[0m'


def green(msg):
    return '\033[92m' + msg + '\033[0m'


def yellow(msg):
    return '\033[93m' + msg + '\033[0m'


def red(msg):
    return '\033[91m' + msg + '\033[0m'


def white(msg):
    return '\033[0m' + msg + '\033[0m'


def bold(msg):
    return '\033[1m' + msg + '\033[0m'


def underline(msg):
    return '\033[4m' + msg + '\033[0m'


def boolean_with_log(boolean, msg, true_msg=None, false_msg=None):
    if isinstance(msg, str):
        msg = yellow(msg)
    log.debug(msg)
    if boolean:
        if isinstance(true_msg, str):
            true_msg = green(true_msg)
        log.debug(true_msg)
    else:
        if isinstance(false_msg, str):
            false_msg = red(false_msg)
        log.debug(false_msg)
    return boolean


def inspect_object(obj):
    pprint(vars(obj))

# ==================================
# Helpers (end)
# ==================================
