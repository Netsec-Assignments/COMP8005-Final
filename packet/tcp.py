import enum
from socket import inet_ntop
from socket import AF_INET

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
