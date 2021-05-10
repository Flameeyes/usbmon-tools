# python
#
# Copyright 2019-2020 The usbmon-tools Authors
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
# SPDX-FileCopyrightText: © 2020 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0

import datetime
import enum
import logging

import construct
import hexdump
import pcapng

from usbmon import constants, packet, setup


@enum.unique
class ControlStage(enum.IntEnum):
    SETUP = 0
    DATA = 1
    STATUS = 2
    COMPLETE = 3


# usbpcap reuses the transfer field for two extra conditions:
#  - IRP information (on error such as stalled pipes);
#  - Unknown IRPs.
# We map them together but then reject them as we don't have use for them,
# at least for now.


@enum.unique
class UsbcapXferType(enum.IntEnum):
    IRP_INFO = 0xFE
    UNKNOWN = 0xFF


_USBPCAP_XFER_TYPE_MAPPING = {e: e.value for e in UsbcapXferType}
_USBPCAP_XFER_TYPE_MAPPING.update({e: e.value for e in constants.XferType})


class UnsupportedCaptureData(ValueError):
    """Raised when an unsupported capture data struct is being parsed."""


_STRUCT = construct.Struct(
    headerLen=construct.Int16ul,
    id=construct.Int64ul,
    status=construct.Int32ul,
    function=construct.Int16ul,
    info=construct.Byte,
    busnum=construct.Int16ul,
    devnum=construct.Int16ul,
    epnum=construct.Byte,
    xfer_type=construct.Mapping(construct.Byte, _USBPCAP_XFER_TYPE_MAPPING),
    dataLength=construct.Int32ul,
    # Start of additional headers.
    control_header=construct.If(
        construct.this.xfer_type == constants.XferType.CONTROL,
        construct.Struct(
            control_stage=construct.Mapping(
                construct.Byte, {e: e.value for e in ControlStage}
            ),
            setup_packet=construct.If(
                construct.this.control_stage == ControlStage.SETUP, construct.Bytes(8)
            ),
        ),
    ),
    payload=construct.GreedyBytes,
)


class UsbpcapPacket(packet.Packet):
    def __init__(self, block: pcapng.blocks.EnhancedPacket):
        super().__init__()

        self.timestamp = datetime.datetime.fromtimestamp(block.timestamp)

        constructed_object = _STRUCT.parse(block.packet_data)

        if not isinstance(constructed_object.xfer_type, constants.XferType):
            raise UnsupportedCaptureData(
                f"Unable to parse capture data of type {constructed_object.xfer_type!r}"
            )

        self.tag = constructed_object.id

        # This appears to be an approximation.
        if constructed_object.info == 0x01:
            self.type = constants.PacketType.CALLBACK
        else:
            self.type = constants.PacketType.SUBMISSION

        self.xfer_type = constructed_object.xfer_type

        self.devnum = constructed_object.devnum
        self.busnum = constructed_object.busnum

        self.status = constructed_object.status

        self.length = constructed_object.dataLength

        self.setup_packet = None
        if self.xfer_type == constants.XferType.CONTROL:
            if constructed_object.control_header.setup_packet:
                self.setup_packet = setup.SetupPacket(
                    constructed_object.control_header.setup_packet
                )
                self.length -= 8  # size of setup packet.

        self.epnum = constructed_object.epnum

        self.payload = constructed_object.payload
        if self.length != len(self.payload):
            logging.warning(
                "expected %d bytes, found %d", self.length, len(self.payload)
            )

    @property
    def setup_packet_string(self) -> str:
        if self.setup_packet:
            return str(self.setup_packet)
        # elif self.xfer_type == constants.XferType.ISOCHRONOUS:
        #     value = f'{self.status}::{self.start_frame}'
        #     if self.type != constants.PacketType.SUBMISSION:
        #         value += f':{self.error_count}'
        #     return value
        else:
            return str(self.status)

    def __str__(self) -> str:
        # Try to keep compatibility with Linux usbmon's formatting, which
        # annoyingly seems to cut this at 4-bytes groups.
        if self.payload:
            payload_dump = hexdump.dump(self.payload, size=8).lower()
            payload_string = f"= {payload_dump}"
        elif (
            self.xfer_type == constants.XferType.INTERRUPT
            and self.direction == constants.Direction.IN
        ):
            payload_string = "<"
        else:
            payload_string = "?"

        return (
            f"{self.tag:016x} {self.timestamp.timestamp() * 1e6:.0f} "
            f"{self.type.value} {self.type_mnemonic}{self.direction.value}:{self.busnum}:{self.devnum:03d}:{self.endpoint} "
            f"{self.setup_packet_string} {self.length} {payload_string}"
        ).rstrip()
