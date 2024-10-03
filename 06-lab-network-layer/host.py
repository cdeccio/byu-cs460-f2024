#!/usr/bin/python3

import argparse
import asyncio
import os
import socket
import sys

from cougarnet.sim.host import BaseHost
from cougarnet.util import \
        mac_str_to_binary, mac_binary_to_str, \
        ip_str_to_binary, ip_binary_to_str

from prefix import *
from forwarding_table import ForwardingTable

# From /usr/include/linux/if_ether.h:
ETH_P_IP = 0x0800 # Internet Protocol packet
ETH_P_ARP = 0x0806 # Address Resolution packet

# From /usr/include/net/if_arp.h:
ARPHRD_ETHER = 1 # Ethernet 10Mbps
ARPOP_REQUEST = 1 # ARP request
ARPOP_REPLY = 2 # ARP reply

# From /usr/include/linux/in.h:
IPPROTO_ICMP = 1 # Internet Control Message Protocol
IPPROTO_TCP = 6 # Transmission Control Protocol
IPPROTO_UDP = 17 # User Datagram Protocol

class Host(BaseHost):
    def __init__(self, ip_forward: bool):
        super().__init__()

        self._ip_forward = ip_forward

        # do any additional initialization here

    def _handle_frame(self, frame: bytes, intf: str) -> None:
        pass

    def handle_ip(self, pkt: bytes, intf: str) -> None:
        pass

    def handle_tcp(self, pkt: bytes) -> None:
        pass

    def handle_udp(self, pkt: bytes) -> None:
        pass

    def handle_arp(self, pkt: bytes, intf: str) -> None:
        pass

    def handle_arp_response(self, pkt: bytes, intf: str) -> None:
        pass

    def handle_arp_request(self, pkt: bytes, intf: str) -> None:
        pass

    def send_packet_on_int(self, pkt: bytes, intf: str, next_hop: str) -> None:
        print(f'Attempting to send packet on {intf} with next hop {next_hop}:\n{repr(pkt)}')

    def send_packet(self, pkt: bytes) -> None:
        print(f'Attempting to send packet:\n{repr(pkt)}')

    def forward_packet(self, pkt: bytes) -> None:
        pass

    def not_my_frame(self, frame: bytes, intf: str) -> None:
        pass

    def not_my_packet(self, pkt: bytes, intf: str) -> None:
        pass

    def prefix_for_int(self, intf: str) -> str:
        obj = self.ipv4_address_info_single(intf)
        ip_int = ip_str_to_int(obj['address'])
        ip_prefix_int = ip_prefix(ip_int, socket.AF_INET, obj['prefixlen'])
        first_addr = ip_int_to_str(ip_prefix_int, socket.AF_INET)
        return '%s/%d' % (first_addr, obj['prefixlen'])

    def bcast_for_int(self, intf: str) -> str:
        obj = self.ipv4_address_info_single(intf)
        ip_int = ip_str_to_int(obj['address'])
        ip_prefix_int = ip_prefix(ip_int, socket.AF_INET, obj['prefixlen'])
        ip_bcast_int = ip_prefix_last_address(ip_prefix_int, socket.AF_INET, obj['prefixlen'])
        bcast = ip_int_to_str(ip_bcast_int, socket.AF_INET)
        return bcast

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--router', '-r',
            action='store_const', const=True, default=False,
            help='Act as a router by forwarding IP packets')
    args = parser.parse_args(sys.argv[1:])

    Host(args.router).run()

if __name__ == '__main__':
    main()
