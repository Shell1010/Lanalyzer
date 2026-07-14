"""
Most information about the Internet Control Message Protocol (ICMP)
is obtained from RFC 792. Refer to https://datatracker.ietf.org/doc/html/rfc792
for a full explanation. Codes and additional types have been obtained from IANA ICMP Parameters, link
https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-0.
"""
from typing import Union
import enum
import struct



class ICMPType(enum.IntEnum):
    """ICMP types as defined in RFC 792. Specified near the bottom."""
    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    
    # According to IANA it's deprecated, RFC still specifies
    SOURCE_QUENCH = 4
    
    REDIRECT = 5

    # According to IANA it's deprecated
    ALTERNATE_HOST_ADDRESS = 6

    
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SELECTION = 10
    TIMEOUT = 11
    PARAMETER_PROBLEM = 12
    TIMESTAMP = 13
    TIMESTAMP_REPLY = 14
    INFORMATION_REQUEST = 15
    INFORMATION_REPLY = 16

    # There was a bunch of deprecated ones I skipped

    PHOTURIS = 40
    EXTENDED_ECHO_REQUEST = 42
    EXTENDED_ECHO_REPLY = 43
    

class EchoReplyCode(enum.IntEnum):
    """Echo reply codes as defined in IANA ICMP Parameters."""
    NO_CODE = 0
    
class DestinationUnreachableCode(enum.IntEnum):
    """Destination unreachable codes as defined in IANA ICMP Parameters."""
    NETWORK_UNREACHABLE = 0
    HOST_UNREACHABLE = 1
    PROTOCOL_UNREACHABLE = 2
    PORT_UNREACHABLE = 3
    FRAGMENTATION_NEEDED_AND_DF_FLAG_SET = 4
    SOURCE_ROUTE_FAILED = 5
    DESTINATION_NETWORK_UNKNOWN = 6
    DESTINATION_HOST_UNKNOWN = 7
    SOURCE_HOST_ISOLATED = 8
    COMMUNICATION_WITH_DESTIONATION_NETWORK_IS_ADMINISTRATIVELY_PROHIBITED = 9
    COMMUNICATION_WITH_DESTINATION_HOST_IS_ADMINISTRATIVELY_PROHIBITED = 10
    DESTINATION_NETWORK_UNREACHABLE_FOR_TYPE_OF_SERVICE = 11
    DESTINATION_HOST_UNREACHABLE_FOR_TYPE_OF_SERVICE = 12
    COMMUNICATION_ADMINISTRATIVELY_PROHIBITED = 13
    HOST_PRECEDENCE_VIOLATION = 14
    PRECEDENCE_CUTOFF_IN_EFFECT = 15

class SourceQuenchCode(enum.IntEnum):
    """Source quench codes as defined in IANA ICMP Parameters."""
    NO_CODE = 0

class RedirectCode(enum.IntEnum):
    """Redirect codes as defined in IANA ICMP Parameters."""
    REDIRECT_DATAGRAM_FOR_THE_NETWORK = 0
    REDIRECT_DATAGRAM_FOR_THE_HOST = 1
    REDIRECT_DATAGRAM_FOR_THE_TYPE_OF_SERVICE_AND_NETWORK = 2
    REDIRECT_DATAGRAM_FOR_THE_TYPE_OF_SERVICE_AND_HOST = 3

class AlternateRouteCode(enum.IntEnum):
    """Alternate route codes as defined in IANA ICMP Parameters."""
    NO_CODE = 0

class EchoRequestCode(enum.IntEnum):
    """Echo request codes as defined in IANA ICMP Parameters."""
    NO_CODE = 0

class RouterAdvertisementCode(enum.IntEnum):
    """Router advertisement codes as defined in IANA ICMP Parameters."""
    NORMAL = 0
    DOES_NOT_ROUTE_COMMON_TRAFFIC = 16

class RouterSelectionCode(enum.IntEnum):
    """Router selection codes as defined in IANA ICMP Parameters."""
    NO_CODE = 0

class TimeoutCode(enum.IntEnum):
    """Timeout codes as defined in IANA ICMP Parameters."""
    TIME_TO_LIVE_EXCEEDED_IN_TRANSIT = 0
    FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1

class ParameterProblemCode(enum.IntEnum):
    """Parameter problem codes as defined in IANA ICMP Parameters."""
    POINTER_INDICATES_THE_ERROR = 0
    MISSING_A_REQUIRED_OPTION = 1
    BAD_LENGTH = 2

class TimestampCode(enum.IntEnum):
    """Timestamp codes as defined in IANA ICMP Parameters."""
    NO_CODE = 0

class TimestampReplyCode(enum.IntEnum):
    """Timestamp reply codes as defined in IANA ICMP Parameters."""
    NO_CODE = 0

class InformationRequestCode(enum.IntEnum):
    """Information request codes as defined in IANA ICMP Parameters."""
    NO_CODE = 0

class InformationReplyCode(enum.IntEnum):
    """Information reply codes as defined in IANA ICMP Parameters."""
    NO_CODE = 0

class PhoturisCode(enum.IntEnum):
    """Photuris codes as defined in IANA ICMP Parameters."""
    BAD_SPI = 0
    AUTHENTICATION_FAILED = 1
    DECOMPRESSION_FAILED = 2
    DECRYPTION_FAILED = 3
    NEED_AUTHENTICATION = 4
    NEED_AUTHORIZATION = 5

class ExtendedEchoRequestCode(enum.IntEnum):
    """Extended echo request codes as defined in IANA ICMP Parameters."""
    NO_CODE = 0
    
class ExtendedEchoReplyCode(enum.IntEnum):
    """Extended echo reply codes as defined in IANA ICMP Parameters."""
    NO_ERROR = 0
    MALFORMED_QUERY = 1
    NO_SUCH_INTERFACE = 2
    NO_SUCH_TABLE_ENTRY = 3
    MULTIPLE_INTERFACES = 4


ICMPCode = Union[
    EchoReplyCode,
    DestinationUnreachableCode,
    SourceQuenchCode,
    RedirectCode,
    AlternateRouteCode,
    EchoRequestCode,
    RouterAdvertisementCode,
    RouterSelectionCode,
    TimeoutCode,
    ParameterProblemCode,
    TimestampCode,
    TimestampReplyCode,
    InformationRequestCode,
    InformationReplyCode,
    PhoturisCode,
    ExtendedEchoRequestCode,
    ExtendedEchoReplyCode,
    int 
]


class ICMP:
    def __init__(self, type: ICMPType = ICMPType.ECHO_REQUEST, code: ICMPCode = EchoRequestCode.NO_CODE, identifier: int = 0, sequence: int = 0, data: bytes = b""):
        self.type = type

        self.code = int(code)
        
        # We calculate later
        self.checksum = 0
        
        # This is the payload
        self.data = data
        
        # Data in the header
        self.identifier = identifier
        self.sequence = sequence
        

    def build_icmp_header(self) -> bytes:
        """
        Format is 1 Byte (Type), 1 Byte (Code), 2 Byte (Checksum), 4 Byte (Header) 
        Using Structs documentation, this is represented as BBHHH, or 2B3H
        Total size is 8 bytes
        
        """
        
        # THe ! indicates Big-Endian which is apparently a network standard
        # This is according to RFC 1700 - Assigned Numbers
        header_format = "!2B3H"

        # Packing is apparently just converting python values into bytes
        # It's fine that the checksum is 0 here for calculation, RFC states it's meant to be like this
        packet = struct.pack(header_format, self.type, self.code, self.checksum, self.identifier, self.sequence)
        return packet

    def calculate_checksum(self, packet: bytes) -> bytes:
        """
        The checksum is the 16-bit ones's complement of the one's
        complement sum of the ICMP message. 

        Basically means we're gonna have to get a one's complement sum of the header and payload.
        One's complement is basically just inverting the bits.

        Packet argument in this context just refers to the header + self.data
        """

        # if odd, add null byte to end to make even
        if len(packet) % 2 != 0:
            packet += b"\x00"

        checksum = 0

        # Advance 2 because we're iterating over 2 bytes
        for i in range(0, len(packet), 2):
            # ! -> Big Endian for Networking
            # H -> 2 bytes
            # Basically format our two bytes from the packet into a Big-Endian 2 byte word
            word = struct.unpack("!H", packet[i:i+2]) 
            checksum += word[0]

            # Checksum can only be 16 bits
            # This checks if its above 16 bits
            # 65535 is the highest possible value 16 bits can hold
            # If checksum is higher than this it begins this one's complement check
            if checksum > 0xFFFF:
                # According to google
                # The first operation effectively removes the bottom that is beyond 16 bits
                # So if it was 0x12345 & 0xFFFF -> 0x2345
                # The second operation basically extracts the excluded part
                # So 0x12345 >> 16 -> 0x1
                # So the two operations added together it's doing this
                # 0010 0011 0100 0101 +
                # 0000 0000 0000 0001
                # ===================
                # 0010 0011 0100 0110 -> 0x2346
                checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # Basically format our checksum to take two bytes as specified by the spec
        # ~checksum is bitwise NOT. Flips all the bits
        # The 0xFFFF is there to check if it exceeds 16 bits, if it does it yeets that extra bit from the bottom
        return struct.pack("!H", ~checksum & 0xFFFF)