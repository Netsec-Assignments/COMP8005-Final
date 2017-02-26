#!/usr/bin/env python3
import sys, inspect
import struct
import enum
from socket import socket, inet_ntop
from socket import AF_INET, SOCK_RAW, IPPROTO_TCP

class IpHeader:
    NO_OPT_SIZE = 20 # The size of an IP header with no optional data

    class Flags(enum.IntEnum):
        MF = 1, # More Fragments
        DF = 2, # Don't Fragment
        RESERVED = 4

    def __init__(self, header_bytes = None):
        """If bytes are provided, unpacks then into an IP header; otherwise, creates a new header with all fields set to None.
        
        hdr_bytes -- a bytes-like object containing the packet data without link-layer header.
        """
        if not (header_bytes is None):
            # Unpack the byte-aligned fields of the IP header
            self.service_type = header_bytes[1]
            self.total_len    = int.from_bytes(header_bytes[2:4], 'big')
            self.id           = int.from_bytes(header_bytes[4:6], 'big')
            self.ttl          = header_bytes[8]
            self.protocol     = header_bytes[9]
            self.checksum     = int.from_bytes(header_bytes[10:12], 'big')
            self.src_ip       = int.from_bytes(header_bytes[12:16], 'big')
            self.dst_ip       = int.from_bytes(header_bytes[16:20], 'big')

            # Unpack the bit fields
            version_and_len = header_bytes[0]
            self.version    = (version_and_len & 0xF0) >> 4
            self.header_len = (version_and_len & 0x0F) * 4 # header length is in 4-byte words

            flags_and_fragoff = int.from_bytes(header_bytes[6:8], 'big')
            self.flags = (flags_and_fragoff & 0xE000) >> 13
            self.frag_off = flags_and_fragoff & 0x1FFF

            # Check for options at the end of the header
            if self.header_len != IpHeader.NO_OPT_SIZE:
                self.options = header_bytes[IpHeader.NO_OPT_SIZE:self.header_len]
            else:
                self.options = None
        else:
            self.version      = None
            self.header_len   = None
            self.service_type = None
            self.total_len    = None
            self.id           = None
            self.flags        = None
            self.frag_off     = None
            self.ttl          = None
            self.protocol     = None
            self.checksum     = None
            self.src_ip       = None
            self.dst_ip       = None
            self.options      = None

    def __str__(self):
        string = "IP header contents:\n"
        string += "\tIP version: " + str(self.version) + "\n"
        string += "\theader length: " + str(self.header_len) + "\n"
        string += "\tservice type: " + str(self.service_type) + "\n"
        string += "\ttotal_len: " + str(self.total_len) + "\n"
        string += "\tidentification: " + str(self.id) + "\n"
        string += "\tflags: " + self.get_flags_string() + "\n"
        string += "\tfragment offset: " + (str(self.frag_off) if (self.flags & IpHeader.Flags.MF == IpHeader.Flags.MF) else "MF flag not set") + "\n"
        string += "\tTTL: " + str(self.ttl) + "\n"
        string += "\tprotocol: " + str(self.protocol) + "\n"
        string += "\theader checksum: " + str(self.checksum) + "\n"
        string += "\tsource IP: " + inet_ntop(AF_INET, self.src_ip.to_bytes(4, 'big')) + "\n"
        string += "\tdestination IP: " + inet_ntop(AF_INET, self.dst_ip.to_bytes(4, 'big')) + "\n"
        string += "\thas options? : " + ("no" if (self.options is None) else "yes") + "\n"

        return string

    def get_flags_string(self):
        flag_names = []
        for flag in IpHeader.Flags:
            if self.flags & flag == flag:
                flag_names.append(flag.name)
        
        return '|'.join(map(str, flag_names))

class TcpHeader:
    NO_OPT_SIZE = 20 # The size of a TCP header with no optional data

    class Flags(enum.IntEnum):
        FIN = 1,
        SYN = 2,
        RST = 4,
        PSH = 8,
        ACK = 16,
        URG = 32

    def __init__(self, header_bytes = None):
        """If bytes are provided, unpacks them into a TCP header; otherwise, creates a new header with all fields set to None.
        
        Arguments:
        header_bytes -- a bytes-like object containing the packet data without link- or network-layer headers.
        """
        if not (header_bytes is None):
            # Unpack the buffer into a TCP header
            self.src_port = int.from_bytes(header_bytes[0:2], 'big')
            self.dst_port = int.from_bytes(header_bytes[2:4], 'big')
            self.seq_num  = int.from_bytes(header_bytes[4:8], 'big')
            self.ack_num  = int.from_bytes(header_bytes[8:12], 'big')
            self.win_size = int.from_bytes(header_bytes[14:16], 'big')
            self.checksum = int.from_bytes(header_bytes[16:18], 'big')
            self.urg_ptr  = int.from_bytes(header_bytes[18:20], 'big')

            data_off_and_flags = int.from_bytes(header_bytes[12:14], 'big')
            self.data_off = (data_off_and_flags & 0xF000) >> 10 # The data offset is in 4-byte words, so only shift 10 (i.e. multiply by 4)
            self.flags = (data_off_and_flags & 0x003F)

            # Check for options at the end of the header
            if self.data_off != TcpHeader.NO_OPT_SIZE:
                self.options = header_bytes[TcpHeader.NO_OPT_SIZE:self.data_off]
            else:
                self.options = None

        else:
            self.src_port = None
            self.dst_port = None
            self.seq_num = None
            self.ack_num = None
            self.flags = None
            self.data_off = None
            self.win_size = None
            self.checksum = None
            self.urg_ptr = None
            self.options = None

    def __str__(self):
        string = "TCP header contents:\n"
        string += "\tsource port: " + str(self.src_port) + "\n"
        string += "\tdestination port: " + str(self.dst_port) + "\n"
        string += "\tsequence number: " + str(self.seq_num) + "\n"
        string += "\tack number: " + str(self.ack_num) + "\n"
        string += "\tflags: " + self.get_flags_string() + "\n"
        string += "\tdata offset: " + str(self.data_off) + "\n"
        string += "\twindow size: " + str(self.win_size) + "\n"
        string += "\tchecksum: " + str(self.checksum) + "\n"
        string += "\turg_ptr: " + (str(self.urg_ptr) if (self.flags & TcpHeader.Flags.URG == TcpHeader.Flags.URG) else "URG flag not set") + "\n"

        return string

    def get_flags_string(self):
        flag_names = []
        for flag in TcpHeader.Flags:
            if self.flags & flag == flag:
                flag_names.append(flag.name)
        
        return '|'.join(map(str, flag_names))
    
    def to_bytes(self, src_ip, dst_ip, data):
        """Creates a TCP header with the given source and destination addresses and data.

        All other members of the header must be set before calling this function. Note that
        the IP addresses and the data won't actually be included in a header anywhere; they're
        used for creating the TCP "pseudo-header" included in the checksum calculation.

        Arguments:
        src_ip -- the source IP address as an integer in host byte order.
        dst_ip -- the destination IP address as an integer in host byte order.
        data   -- the data that will be included in the packet.
        """
        pass


# Create a raw socket to get TCP packets
s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
s.bind(('', IPPROTO_TCP)) # '' binds to any (all?) available interface

while (True):
    response, address = s.recvfrom(1522)

    ip_header = IpHeader(response)
    tcp_header = TcpHeader(response[ip_header.header_len:])
    print(str(ip_header))
    print(str(tcp_header))
