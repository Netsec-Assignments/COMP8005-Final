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

    #while (True):
    try:
        #response, address = s.recvfrom(1522)

        response = bytes([0x45, 0x00,\
        0x00, 0xe9, 0xfb, 0x3f, 0x40, 0x00, 0x3c, 0x06,\
        0x28, 0x3b, 0x97, 0x65, 0xc1, 0x45, 0xc0, 0xa8,\
        0x01, 0x41, 0x01, 0xbb, 0xd2, 0xf8, 0x88, 0x30,\
        0x91, 0x16, 0xa7, 0xa9, 0x52, 0xc0, 0x80, 0x18,\
        0x00, 0x41, 0x16, 0x87, 0x00, 0x00, 0x01, 0x01,\
        0x08, 0x0a, 0x2f, 0x5a, 0x73, 0xb5, 0x00, 0x0d,\
        0x86, 0xe8, 0x17, 0x03, 0x03, 0x00, 0xb0, 0x0d,\
        0xb4, 0x0f, 0x8e, 0x01, 0x0c, 0x1d, 0x9c, 0x5e,\
        0xe8, 0xca, 0xcd, 0xc7, 0x1c, 0x52, 0xc0, 0x2b,\
        0xe7, 0x0f, 0x5d, 0x8e, 0xe4, 0x92, 0x06, 0xc2,\
        0xda, 0x02, 0xf8, 0x82, 0xe4, 0xee, 0xcd, 0xe8,\
        0xd0, 0x40, 0x9f, 0xfe, 0x8e, 0x22, 0xbe, 0x80,\
        0x68, 0x5c, 0xb9, 0x84, 0x86, 0xd8, 0x4e, 0xfb,\
        0xfc, 0x04, 0xf8, 0xea, 0x99, 0x7b, 0x7a, 0x0f,\
        0x1b, 0x59, 0xe4, 0xe6, 0x38, 0xbb, 0xdf, 0x6d,\
        0x36, 0xef, 0x11, 0x73, 0x62, 0xac, 0xfd, 0x3c,\
        0x38, 0x38, 0x87, 0xe3, 0xda, 0x51, 0x84, 0xdd,\
        0xd0, 0x85, 0x3f, 0x16, 0x18, 0x77, 0x63, 0xaa,\
        0x46, 0xc7, 0x6a, 0x9d, 0xa9, 0x25, 0x42, 0xad,\
        0xdd, 0xd6, 0xa4, 0xbf, 0xbd, 0x7b, 0x06, 0x68,\
        0x9a, 0x2e, 0xd2, 0xaa, 0x56, 0x4d, 0xef, 0xa8,\
        0x10, 0xa7, 0x86, 0xee, 0xda, 0x3c, 0xe2, 0x09,\
        0x79, 0xd3, 0x19, 0x7b, 0x6a, 0x31, 0x52, 0xcb,\
        0xa1, 0xef, 0x1f, 0x44, 0x77, 0xdd, 0xe5, 0xce,\
        0xa5, 0xfa, 0xe0, 0xfe, 0x54, 0x1c, 0x35, 0x78,\
        0x13, 0x40, 0xa4, 0xfc, 0xad, 0xf9, 0xae, 0x4a,\
        0xd4, 0xb4, 0x76, 0x48, 0x10, 0xec, 0xe1, 0x62,\
        0xb1, 0x0a, 0x8e, 0x89, 0x27, 0xfd, 0xac, 0xa2,\
        0x16, 0xd9, 0xe5, 0x87, 0xfb, 0xf0, 0x44])


        ip_header = ip.IpHeader(response)
        tcp_header = tcp.TcpHeader(response[ip_header.header_len:])
        print(ip_header)
        print(tcp_header)

#            src_ip_str = inet_ntop(AF_INET, ip_header.src_ip.to_bytes(4, 'big'))
#            dst_ip_str = inet_ntop(AF_INET, ip_header.dst_ip.to_bytes(4, 'big'))
#
#            snat_entry_str = src_ip_str + ":" + str(tcp_header.src_port)
#            dnat_entry_str = dst_ip_str + ":" + str(tcp_header.src_port)
#
#            forward_str = src_ip_str + ":" + str(tcp_header.dst_port)
#            if forward_str in forward_rules:
#                new_src_port = None
#
#                if snat_entry_str in snat_table:
#                    # There's already a NAT entry for this source IP:port pair; perfect.
#                    new_src_port = snat_table[snat_entry_str]
#
#                elif dnat_entry_str not in dnat_table:
#                    # There wasn't already a mapping for this source NAT. There's no collision though
#                    # (no other host is forwarding to the same dest IP with the same source port), so
#                    # so just reuse the source port and update the mappings.
#                    dnat_table[dnat_entry_str] = {"ip":ip_header.src_ip, "port":tcp_header.src_port}
#                    snat_table[snat_entry_str] = tcp_header.src_port
#                    new_src_port = tcp_header.src_port
#                else:
#                    # There wasn't already a mapping for this source NAT and there was a collision.
#                    # Choose a random new unused source port and create the mapping.
#                    # Theoretically this could loop infinitely (and almost certainly would in real life
#                    # since we never clear the used mappings), but for this case it doesn't matter.
#                    while True:
#                        possible_port = randint(49152, 65535)
#                        possible_dnat_str = dst_ip_str + ":" + str(possible_port)
#                        if possible_dnat_str not in dnat_table:
#                            new_src_port = possible_port
#                            snat_table[snat_entry_str] = possible_port
#                            dnat_table[possible_dnat_str] = {"ip":ip_header.src_ip, "port":tcp_header.src_port}
#                            break
#                
#                # TODO: Change source port, source IP address, dest IP address, then forward
#            else:
#                # Is this traffic a response from a dest IP?
#                if dnat_entry_str in dnat_table:
#                    # TODO Change source IP, dest IP, and destination port, then forward
#                    pass

        test = tcp_header.calc_checksum(ip_header.src_ip, ip_header.dst_ip, response[ip_header.header_len + tcp_header.data_off:])
        print("Actual checksum: " + str(tcp_header.checksum) + "; calculated checksum: " + str(test))
        print("Calculated checksum in hex: " + format(test, '0x'))

        # Of course, in a real router converting to string would be an enormous
        # waste of time... Oh well


    except KeyboardInterrupt:
        print("\nExiting")
        sys.exit(0)
