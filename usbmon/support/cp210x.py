# Copyright 2021 The usbmon-tools Authors
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
# SPDX-FileCopyrightText: © 2021 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0
"""Support module for Silicon Labs CP2104/CP2102 protocol structures.

Based on the AN571 document by Silicon Labs, available at:

https://www.silabs.com/documents/public/application-notes/AN571.pdf
"""

import dataclasses
import enum
from typing import Any, Optional, Tuple

import construct

import usbmon.constants
import usbmon.packet
import usbmon.setup

DEFAULT_VENDOR_ID = 0x10C4  # Silicon Labs
DEFAULT_PRODUCT_ID = 0xEA60


@enum.unique
class Request(enum.IntEnum):
    IFC_ENABLE = 0x00
    SET_BAUDDIV = 0x01
    GET_BAUDDIV = 0x02
    SET_LINE_CTL = 0x03
    GET_LINE_CTL = 0x04
    SET_BREAK = 0x05
    IMM_CHAR = 0x06
    SET_MHS = 0x07
    GET_MDMSTS = 0x08
    SET_XON = 0x09
    SET_XOFF = 0x0A
    SET_EVENTMASK = 0x0B
    GET_EVENTMASK = 0x0C
    SET_CHAR = 0x0D
    GET_CHARS = 0x0E
    GET_PROPS = 0x0F
    GET_COMM_STATUS = 0x10
    RESET = 0x11
    PURGE = 0x12
    SET_FLOW = 0x13
    GET_FLOW = 0x14
    EMBED_EVENTS = 0x15
    GET_EVENTSTATE = 0x16
    SET_RECEIVE = 0x17
    GET_RECEIVE = 0x18
    SET_CHARS = 0x19
    GET_BAUDRATE = 0x1D
    SET_BAUDRATE = 0x1E


WIRE_SETUPS_COMMANDS = {Request.SET_LINE_CTL, Request.SET_BAUDRATE}


@enum.unique
class Parity(enum.IntEnum):
    NONE = 0x0
    ODD = 0x10
    EVEN = 0x20
    MARK = 0x30
    SPACE = 0x40


@enum.unique
class StopBits(enum.IntEnum):
    ONE = 0x00
    ONE_AND_HALF = 0x01
    TWO = 0x02


@dataclasses.dataclass
class LineCtl:
    stop_bits: StopBits
    parity: Parity
    data_bits: int

    @classmethod
    def from_word(cls, value: int) -> "LineCtl":
        assert 0 <= value <= 0xFFFF

        data_bits = (value & 0x0F00) >> 8
        parity = Parity(value & 0x00F0)
        stop_bits = StopBits(value & 0x000F)

        return cls(stop_bits, parity, data_bits)

    def __str__(self):
        return f"parity={self.parity.name} data_bits={self.data_bits} stop_bits={self.stop_bits.name}"


@enum.unique
class SpecialChars(enum.IntEnum):
    EOF_CHAR = 0x00
    ERROR_CHAR = 0x01
    BREAK_CHAR = 0x02
    EVENT_CHAR = 0x03
    XON_CHAR = 0x04
    XOFF_CHAR = 0x05


@dataclasses.dataclass
class UndocumentedRequest:
    value: int
    index: int
    payload: Optional[bytes]

    def __str__(self):
        payload_str = self.payload.hex() if self.payload else "[]"

        return f"value: {self.value} index: {self.index} payload: {payload_str}"


def control_command(
    submission: usbmon.packet.Packet, callback: usbmon.packet.Packet
) -> Tuple[Request, Any]:
    if submission.xfer_type != usbmon.constants.XferType.CONTROL:
        raise ValueError(
            f"Control commands are sent as CONTROL packets, not {submission.xfer_type}"
        )

    setup_packet = submission.setup_packet
    if not setup_packet:
        raise ValueError("Missing setup packet")

    if setup_packet.type != usbmon.setup.Type.VENDOR:
        raise ValueError(
            f"Control commands are sent as VENDOR type, not {setup_packet.type}"
        )
    if setup_packet.recipient != usbmon.setup.Recipient.INTERFACE:
        raise ValueError(
            f"Control commands are sent/received to the INTERFACE, not {setup_packet.recipient}"
        )

    request = Request(setup_packet.request)
    if request == Request.IFC_ENABLE:
        return (request, bool(setup_packet.value))
    elif request == Request.RESET:
        return (request, None)
    elif request == Request.GET_BAUDDIV:
        assert len(callback.payload) == 2
        bauddiv = construct.Int16ul.parse(callback.payload)
        return (request, bauddiv)
    elif request == Request.SET_BAUDRATE:
        assert len(submission.payload) == 4
        baudrate = construct.Int32ul.parse(submission.payload)
        return (request, baudrate)
    elif request == Request.GET_BAUDRATE:
        assert len(callback.payload) == 4
        baudrate = construct.Int32ul.parse(callback.payload)
        return (request, baudrate)
    elif request == Request.SET_LINE_CTL:
        ctl = LineCtl.from_word(setup_packet.value)
        return (request, ctl)
    elif request == Request.GET_LINE_CTL:
        assert len(callback.payload) == 2
        value = construct.Int16ul.parse(callback.payload)
        ctl = LineCtl.from_word(value)
        return (request, ctl)
    elif request == Request.SET_MHS:
        return (request, setup_packet.value)
    elif request == Request.GET_MDMSTS:
        assert len(callback.payload) == 1
        return (request, callback.payload[0])
    elif request == Request.SET_FLOW:
        assert len(submission.payload) == 0x10
        return (request, submission.payload)
    elif request == Request.GET_FLOW:
        assert len(callback.payload)
        return (request, callback.payload)
    elif request == Request.SET_XON or request == Request.SET_XOFF:
        return (request, None)
    elif request == Request.SET_EVENTMASK:
        return (request, setup_packet.value)
    elif request == Request.GET_EVENTMASK:
        assert len(callback.payload) == 2
        value = construct.Int16ul.parse(callback.payload)
        return (request, value)
    elif request == Request.GET_EVENTSTATE:
        assert len(callback.payload) == 2
        value = construct.Int16ul.parse(callback.payload)
        return (request, value)
    elif request == Request.SET_RECEIVE:
        return (request, setup_packet.value)
    elif request == Request.GET_RECEIVE:
        # AN571 says this has a length of 0x10 and no data, but
        # the one above passes the max timeout in wValue.
        assert len(callback.payload) == 2
        value = construct.Int16ul.parse(callback.payload)
        return (request, value)
    elif request == Request.SET_BREAK:
        return (request, bool(setup_packet.value))
    elif request == Request.GET_COMM_STATUS:
        assert len(callback.payload) == 0x13
        return (request, callback.payload)
    elif request == Request.IMM_CHAR:
        return (request, setup_packet.value)
    elif request == Request.SET_CHAR:
        character_value = setup_packet.value >> 8
        special_character = SpecialChars(setup_packet.value & 0xFF)
        return (request, {special_character.name: character_value})
    elif request == Request.SET_CHARS:
        assert len(submission.payload) == 6
        special_character_mapping = {
            special_char.name: char
            for special_char, char in zip(SpecialChars, submission.payload)
        }
        return (request, special_character_mapping)
    elif request == Request.GET_CHARS:
        assert len(callback.payload) == 6
        special_character_mapping = dict(zip(SpecialChars, callback.payload))
        return (request, special_character_mapping)
    elif request == Request.GET_PROPS:
        # AN571 suggests this should be requested as length 0x100, but only
        # documents up to 0x40.
        return (request, callback.payload)
    elif request == Request.PURGE:
        return (request, setup_packet.value)
    elif request == Request.EMBED_EVENTS:
        return (request, setup_packet.value)
    else:
        if submission.direction == usbmon.constants.Direction.OUT:
            payload = submission.payload
        else:
            payload = callback.payload
        return (
            request,
            UndocumentedRequest(setup_packet.value, setup_packet.index, payload),
        )


def control_command_to_str(request: Request, argument: Any) -> str:
    request_str = request.name

    if isinstance(argument, bytes):
        argument_str = argument.hex()
    elif isinstance(argument, dict):
        argument_str = repr(argument)
    elif request in (Request.SET_BAUDRATE, Request.GET_BAUDRATE):
        argument_str = str(argument)
    elif isinstance(argument, int):
        argument_str = hex(argument)
    else:
        argument_str = str(argument)

    return f"{request_str} {argument_str}"
