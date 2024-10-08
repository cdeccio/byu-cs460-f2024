#!/usr/bin/python3

import argparse
import asyncio
import os
import socket
import sys
import traceback

from scapy.all import Ether, IP, UDP, ARP
from scapy.data import IP_PROTOS 

from host import Host, ETH_P_ARP, ARPOP_REQUEST, ARPOP_REPLY

class SimHost(Host):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_frame(self, frame, intf):
        try:
            eth = Ether(frame)
            if eth.type == ETH_P_ARP:
                arp = eth.getlayer(ARP)
                if arp.op == ARPOP_REQUEST:
                    op = 'REQUEST'
                elif arp.op == ARPOP_REPLY:
                    op = 'REPLY'
                else:
                    op = 'UNKNOWN'
                self.log(f'Received ARP {op} from {arp.psrc}/{arp.hwsrc} for {arp.pdst} on {intf}.')
        except:
            traceback.print_exc()
        super()._handle_frame(frame, intf)

    def handle_udp(self, pkt):
        try:
            ip = IP(pkt)
            self.log(f'Received UDP packet from {ip.src}.')
        except:
            traceback.print_exc()
        super().handle_udp(pkt)

    def send_udp(self, src, dst, next_hop):
        ip = IP(src=src, dst=dst, proto=IP_PROTOS.udp)
        udp = UDP(dport=5900)
        pkt = ip / udp / b'0123456789'

        intf = self.physical_interface_single()
        self.send_packet_on_int(bytes(pkt), intf, next_hop)

    def schedule_items(self):
        pass

class SimHostA(SimHost):
    def schedule_items(self):
        a_to_bcast = ('10.0.0.2', '10.0.0.255', '10.0.0.255')

        loop = asyncio.get_event_loop()
        loop.call_later(3, self.log, 'START')
        loop.call_later(4, self.send_udp, *a_to_bcast)
        loop.call_later(12, self.log, 'STOP')

class SimHostB(SimHost):
    def schedule_items(self):
        b_to_bcast = ('10.0.0.3', '10.0.0.255', '10.0.0.255')

        loop = asyncio.get_event_loop()
        loop.call_later(5, self.send_udp, *b_to_bcast)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--router', '-r',
            action='store_const', const=True, default=False,
            help='Act as a router by forwarding IP packets')
    args = parser.parse_args(sys.argv[1:])

    hostname = socket.gethostname()
    if hostname == 'a':
        cls = SimHostA
    elif hostname == 'b':
        cls = SimHostB
    else:
        cls = SimHost

    host = cls(args.router)
    host.schedule_items()
    host.run()

if __name__ == '__main__':
    main()
