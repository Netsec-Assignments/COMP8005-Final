###################################################################################################
#Name:	ip.py
#
#       Developer:	Mat Siwoski/Shane Spoor
#
#       Created On: 2017-03-04
#
#       Description:
#       This is parses the ip header and will also display the ip header out to the user.
#
#    Revisions:
#    (none)
#
###################################################################################################

import enum
from socket import inet_ntop
from socket import AF_INET

class IpHeader:
    NO_OPT_SIZE = 20 # The size of an IP header with no optional data

    class Flags(enum.IntEnum):
        MF = 1, # More Fragments
        DF = 2, # Don't Fragment
        RESERVED = 4

#########################################################################################################
# FUNCTION
#
#   Name:		__init__
#
#    Prototype:	def __init__(self, header_bytes = None)
#
#    Developer:	Mat Siwoski/Shane Spoor
#
#    Created On: 2017-03-04
#
#    Parameters:
#    self  - contents of the ip header
#    header_bytes - a bytes-like object containing the packet data without link-layer header.
#
#    Return Values:
#	
#    Description:
#    This function unpacks contents into an IP header. If bytes are provided, unpacks then into an IP header; 
#    otherwise, creates a new header with all fields set to None. 
#
#    Revisions:
#	(none)
#    
#########################################################################################################
    def __init__(self, header_bytes = None):
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

#########################################################################################################
# FUNCTION
#
#   Name:		__str__
#
#    Prototype:	def __str__(self)
#
#    Developer:	Mat Siwoski/Shane Spoor
#
#    Created On: 2017-03-04
#
#    Parameters:
#    self  - ip header info
#
#    Return Values:
#	
#    Description:
#    This function displays the contents of the ip header.
#
#    Revisions:
#	(none)
#    
#########################################################################################################
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
#########################################################################################################
# FUNCTION
#
#   Name:		get_flags_string
#
#    Prototype:	def get_flags_string(self)
#
#    Developer:	Mat Siwoski/Shane Spoor
#
#    Created On: 2017-03-04
#
#    Parameters:
#    self  - flags
#
#    Return Values:
#	
#    Description:
#    This function will get the flags in a string.
#
#    Revisions:
#	(none)
#    
#########################################################################################################
    def get_flags_string(self):
        flag_names = []
        for flag in IpHeader.Flags:
            if self.flags & flag == flag:
                flag_names.append(flag.name)
        
        return '|'.join(map(str, flag_names))
