# python
#
# Copyright 2019 The usbmon-tools Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import enum
import re
from typing import Union

import construct
import errno

class PacketType(enum.Enum):
    SUBMISSION = 'S'
    CALLBACK = 'C'
    ERROR = 'E'


class XferType(enum.Enum):
    ISOCHRONOUS = 0
    INTERRUPT = 1
    CONTROL = 2
    BULK = 3


def _usbmon_structure(endianness):
    """Return a construct.Struct() object suitable to parse a usbmon packet."""

    return construct.Struct(
        'id' / construct.FormatField(endianness, 'Q'),
        'type' / construct.Mapping(
            construct.Byte,
            {e: ord(e.value) for e in PacketType}),
        'xfer_type' / construct.Mapping(
            construct.Byte,
            {e: e.value for e in XferType}),
        'epnum' / construct.Byte,
        'devnum' / construct.Byte,
        'busnum' / construct.FormatField(endianness, 'H'),
        'flag_setup' / construct.Byte,
        'flag_data' / construct.PaddedString(1, 'ascii'),
        'ts_sec' / construct.FormatField(endianness, 'q'),
        'ts_usec' / construct.FormatField(endianness, 'l'),
        'status' / construct.FormatField(endianness, 'l'),
        'length' / construct.FormatField(endianness, 'L'),
        'len_cap' / construct.FormatField(endianness, 'L'),
        's' / construct.Union(
            0,
            'setup' / construct.Bytes(8),
            'iso' / construct.Struct(
                'error_count' / construct.FormatField(endianness, 'l'),
                'numdesc' / construct.FormatField(endianness, 'l'),
            ),
        ),
        'interval' / construct.FormatField(endianness, 'l'),
        'start_frame' / construct.FormatField(endianness, 'l'),
        'xfer_flags' / construct.FormatField(endianness, 'L'),
        'ndesc' / construct.FormatField(endianness, 'L'),
        'payload' / construct.GreedyBytes,
    )


_USB_SETUP_PACKET = construct.Struct(
    'bmRequestType' / construct.Byte,
    'bRequest' / construct.Byte,
    'wValue' / construct.Int16ul,
    'wIndex' / construct.Int16ul,
    'wLength' / construct.Int16ul,
)


class Direction(enum.Enum):
    OUT = 'o'
    IN = 'i'


_XFERTYPE_TO_MNEMONIC = {
    XferType.ISOCHRONOUS: 'Z',
    XferType.INTERRUPT: 'I',
    XferType.CONTROL: 'C',
    XferType.BULK: 'B',
}



class Packet:

    @staticmethod
    def from_bytes(endianness: str, raw_packet: bytes) -> 'Packet':
        return Packet(_usbmon_structure(endianness).parse(raw_packet))

    def __init__(self, constructed_object):
        # The binary ID value is usually a pointer in memory. Keep the text
        # representation instead, because it should be considered an opaque
        # value.
        self.tag = f'{constructed_object.id:08x}'

        self.type = constructed_object.type

        self.xfer_type = constructed_object.xfer_type

        self.devnum = constructed_object.devnum
        self.busnum = constructed_object.busnum

        self.flag_setup = constructed_object.flag_setup
        if self.flag_setup == 0:
            self.setup_packet = _USB_SETUP_PACKET.parse(constructed_object.s.setup)
        else:  # No setup for this kind of URB, or unable to capture setup packet.
            self.setup_packet = None

        self.flag_data = constructed_object.flag_data
        if not self.flag_data:
            self.flag_data = '='

        self.timestamp = datetime.datetime.fromtimestamp(
            constructed_object.ts_sec + (1e-6 * constructed_object.ts_usec))
        self.status = constructed_object.status
        self.length = constructed_object.length

        if self.xfer_type in (XferType.INTERRUPT, XferType.ISOCHRONOUS):
            self.interval = constructed_object.interval

        if self.xfer_type == XferType.ISOCHRONOUS:
            self.error_count = constructed_object.s.iso.error_count
            self.numdesc = constructed_object.s.iso.numdesc
            self.start_frame = constructed_object.start_frame

        self.xfer_flags = constructed_object.xfer_flags
        self.ndesc = constructed_object.ndesc
        self.payload = constructed_object.payload

        assert constructed_object.len_cap == len(self.payload)

        # Split the direction from the endpoint
        self.endpoint = constructed_object.epnum & 0x7F
        if constructed_object.epnum & 0x80:
            self.direction = Direction.IN
        else:
            self.direction = Direction.OUT

    @property
    def error(self) -> Union[str, int, None]:
        """Returns a standard errno symbol for error status."""
        if self.status < 0:
            try:
                return errno.errorcode[abs(self.status)]
            except LookupError:
                return self.status
        else:
            return None

    @property
    def address(self) -> str:
        return f'{self.busnum}.{self.devnum}.{self.endpoint}'

    @property
    def type_mnemonic(self) -> str:
        return _XFERTYPE_TO_MNEMONIC[self.xfer_type]

    @property
    def setup_packet_string(self) -> str:
        if self.setup_packet:
            return (
                f's {self.setup_packet.bmRequestType:02x} {self.setup_packet.bRequest:02x} '
                f'{self.setup_packet.wValue:04x} {self.setup_packet.wIndex:04x} '
                f'{self.setup_packet.wLength:04x}')
        else:
            if self.xfer_type == XferType.INTERRUPT:
                value = f'{self.status}:{self.interval}'
            elif self.xfer_type == XferType.ISOCHRONOUS:
                value = f'{self.status}:{self.interval}:{self.start_frame}'
                if self.type != PacketType.SUBMISSION:
                    value += f':{self.error_count}'
            else:
                value = f'{self.status}'
            if self.flag_setup == '-':
                value += ' __ __ ____ ____ ____'
            return value

    def __repr__(self) -> str:
        return f'Packet<tag: {self.tag} address: {self.address!r} payload: {self.payload!r}>'

    def __str__(self) -> str:
        # Try to keep compatibility with Linux usbmon's formatting,
        # which annoyingly seems to cut this at 4-bytes groups.
        payload_string = re.sub(r'(.{8})', r'\1 ', self.payload.hex())

        return (
            f'{self.tag} {self.timestamp.timestamp() * 1e6:.0f} '
            f'{self.type.value} {self.type_mnemonic}{self.direction.value}:{self.busnum}:{self.devnum:03d}:{self.endpoint} '
            f'{self.setup_packet_string} {self.length} {self.flag_data} {payload_string}').rstrip()
