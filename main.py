#!/usr/bin/env python3
import sys
import struct
import json
from socket import socket, inet_ntop
from socket import AF_INET, SOCK_RAW, IPPROTO_TCP
from packet import ip, tcp

FORWARD_RULES_FILE="forward.json"

if __name__ == "__main__":
    forward_rules = None
    with open(FORWARD_RULES_FILE, 'r') as f:
        forward_rules = json.load(f)

    # The DNAT table is used to forward traffic coming from the "outside" back to the "inside".
    # Keys in this table are in the form "forward_dst_ip:dst_port", where "forward_dst_ip" is
    # an IP to which packets are forwarded (right-hand side of a forwarding rule) and "dst_port"
    # is the source port assigned by the forwarder for the "inside" machine.
    #
    # These keys map to another map with mappings "ip":[little-endian IP address],
    # "port":[little-endian port].
    #
    # The SNAT table is used to do the opposite. Keys in this table are in the form
    # "forwarded_src_ip:src_port", where "forwarded_src_ip" is the IP of some "internal" host,
    # and "src_port" is also exactly what it sounds like.
    #
    # These keys map to the source port to use as a little-endian int.
    dnat_table = {}
    snat_table = {}

    # Create a raw socket to get TCP packets
    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    s.bind(('', IPPROTO_TCP)) # '' binds to any (all?) available interface

    while (True):
        try:
            response, address = s.recvfrom(1522)

            ip_header = ip.IpHeader(response)
            tcp_header = tcp.TcpHeader(response[ip_header.header_len:])

            # Of course, in a real router converting to string would be an enormous
            # waste of time... Oh well
            src_ip_str = inet_ntop(AF_INET, ip_header.src_ip.to_bytes(4, 'big'))
            dst_ip_str = inet_ntop(AF_INET, ip_header.dst_ip.to_bytes(4, 'big'))

            snat_entry_str = src_ip_str + ":" + str(tcp_header.src_port)
            dnat_entry_str = dst_ip_str + ":" + str(tcp_header.src_port)

            forward_str = src_ip_str + ":" + str(tcp_header.dst_port)
            if forward_str in forward_rules:
                new_src_port = None

                if snat_entry_str in snat_table:
                    # There's already a NAT entry for this source IP:port pair; perfect.
                    new_src_port = snat_table[snat_entry_str]

                elif dnat_entry_str not in dnat_table:
                    # There wasn't already a mapping for this source NAT. There's no collision though
                    # (no other host is forwarding to the same dest IP with the same source port), so
                    # so just reuse the source port and update the mappings.
                    dnat_table[dnat_entry_str] = {"ip":ip_header.src_ip, "port":tcp_header.src_port}
                    snat_table[snat_entry_str] = tcp_header.src_port
                    new_src_port = tcp_header.src_port
                else:
                    # There wasn't already a mapping for this source NAT and there was a collision.
                    # Choose a random new unused source port and create the mapping.
                    # Theoretically this could loop infinitely (and almost certainly would in real life
                    # since we never clear the used mappings), but for this case it doesn't matter.
                    while True:
                        possible_port = randint(49152, 65535)
                        possible_dnat_str = dst_ip_str + ":" + str(possible_port)
                        if possible_dnat_str not in dnat_table:
                            new_src_port = possible_port
                            snat_table[snat_entry_str] = possible_port
                            dnat_table[possible_dnat_str] = {"ip":ip_header.src_ip, "port":tcp_header.src_port}
                            break
                
                # TODO: Change source port, source IP address, dest IP address, then forward
            else:
                # Is this traffic a response from a dest IP?
                if dnat_entry_str in dnat_table:
                    # TODO Change source IP, dest IP, and destination port, then forward
                    pass

        except KeyboardInterrupt:
            print("\nExiting")
            sys.exit(0)
