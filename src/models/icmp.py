"""
Most information about the Internet Control Message Protocol (ICMP)
is obtained from RFC 792. Refer to https://datatracker.ietf.org/doc/html/rfc792
for a full explanation. Codes and additional types have been obtained from IANA ICMP Parameters, link
https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-0.
"""
from __future__ import annotations
import enum
import struct
from ..logging import get_logger
from typing import Union, Dict, Type

logging = get_logger(__name__)


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


# Basically for type hinting
# Just to make things more "readable"
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
    int,
]

# This is so that I can provide more information during response handling
# E.g Respone(2) is less informative than Response(ExtendedReplyCode.NO_SUCH_INTERFACE)
# A specific ICMP type has codes that mean different things
# So this dict exists to map the types to their corresponding codes
TYPE_TO_CODE_MAPPING: Dict[ICMPType, Type[enum.IntEnum]] = {
    ICMPType.ECHO_REPLY: EchoReplyCode,
    ICMPType.DESTINATION_UNREACHABLE: DestinationUnreachableCode,
    ICMPType.SOURCE_QUENCH: SourceQuenchCode,
    ICMPType.REDIRECT: RedirectCode,
    ICMPType.ALTERNATE_HOST_ADDRESS: AlternateRouteCode,
    ICMPType.ECHO_REQUEST: EchoRequestCode,
    ICMPType.ROUTER_ADVERTISEMENT: RouterAdvertisementCode,
    ICMPType.ROUTER_SELECTION: RouterSelectionCode,
    ICMPType.TIMEOUT: TimeoutCode,
    ICMPType.PARAMETER_PROBLEM: ParameterProblemCode,
    ICMPType.TIMESTAMP: TimestampCode,
    ICMPType.TIMESTAMP_REPLY: TimestampReplyCode,
    ICMPType.INFORMATION_REQUEST: InformationRequestCode,
    ICMPType.INFORMATION_REPLY: InformationReplyCode,
    ICMPType.PHOTURIS: PhoturisCode,
    ICMPType.EXTENDED_ECHO_REQUEST: ExtendedEchoRequestCode,
    ICMPType.EXTENDED_ECHO_REPLY: ExtendedEchoReplyCode,
}

class ICMP:
    """
    ICMP Sta
    """
    def __init__(
        self,
        type: Union[ICMPType, int] = ICMPType.ECHO_REQUEST,
        code: ICMPCode = EchoRequestCode.NO_CODE,
        identifier: int = 0,
        sequence: int = 0,
        data: bytes = b"",
    ):
        try:
            self.type = ICMPType(type)
            logging.info(f"ICMP type set to {self.type}")
        except ValueError:
            # Gonna add some way to warn cause logging
            # This shouldn't happen but if it does we should know what we're missing
            logging.warning(f"Invalid type {type} for ICMP")
            self.type = type

        self.code = code
        if isinstance(self.type, ICMPType) and self.type in TYPE_TO_CODE_MAPPING:
            code_enum_class = TYPE_TO_CODE_MAPPING[self.type]
            try:
                self.code = code_enum_class(code)
                logging.info(f"ICMP code set to {self.code} for type {self.type}")
            except ValueError:
                # Gonna add some way to warn cause logging
                # This shouldn't happen but if it does we should know what we're missing
                logging.warning(f"Invalid code {code} for ICMP type {self.type}")
                self.code = code
                        
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
        packet = struct.pack(
            header_format,
            self.type,
            self.code,
            self.checksum,
            self.identifier,
            self.sequence,
        )
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
            word = struct.unpack("!H", packet[i : i + 2])
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

    def pack(self) -> bytes:
        """
        Finalizes the packet by calculating the checksum over the header and data,
        then returns the complete binary packet. Checksum needs to be 0 for this.
        """
        # According to RFC, needs to be 0 when calculating initial checksum
        self.checksum = 0
        header = self.build_icmp_header()

        # Now we calculate the checksum using this header and the original data
        # Basically the full data
        packed_checksum = self.calculate_checksum(header + self.data)
        # Need to unpack bytes to an int
        # Checksum is 2 bytes, hence using H
        self.checksum: int = struct.unpack("!H", packed_checksum)[0]

        # Create a real header using the real checksum
        return self.build_icmp_header() + self.data

    # Need a way to construct raw data into our object
    # So we make this method to build it from raw data
    @classmethod
    def unpack(cls, data: bytes) -> ICMP:
        # Total size of the ICMP Header that we're parsing is 8 bytes
        # So we extract the last 8 bytes from our data
        header_bytes = data[:8]
        
        # Check build_icmp_header, same concept but reverse
        # Effectively pulling 
        type, code, _, identifier, sequence = struct.unpack("!2B3H", header_bytes)

        # Extract the data part (everything after the header)
        data_bytes = data[8:]

        return cls(type=type, code=code, identifier=identifier, sequence=sequence, data=data_bytes)