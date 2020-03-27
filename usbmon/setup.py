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
# SPDX-FileCopyrightText: © 2019 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0
"""Utilities to parse and inspect USB setup packets."""

import enum
from typing import Optional

import construct


@enum.unique
class Direction(enum.IntEnum):
    HOST_TO_DEVICE = 0
    DEVICE_TO_HOST = 1


@enum.unique
class Type(enum.IntEnum):
    STANDARD = 0
    CLASS = 1
    VENDOR = 2
    RESERVED = 3


@enum.unique
class StandardRequest(enum.IntEnum):
    GET_STATUS = 0x00
    CLEAR_FEATURE = 0x01
    SET_FEATURE = 0x03
    SET_ADDRESS = 0x05
    GET_DESCRIPTOR = 0x06
    SET_DESCRIPTOR = 0x07
    GET_CONFIGURATION = 0x08
    SET_CONFIGURATION = 0x09


@enum.unique
class Recipient(enum.IntEnum):
    DEVICE = 0
    INTERFACE = 1
    ENDPOINT = 2
    OTHER = 3
    RESERVED = 4


_USB_SETUP_PACKET = construct.Struct(
    bmRequestType=construct.Union(
        0,
        parsed=construct.BitStruct(
            direction=construct.Mapping(
                construct.BitsInteger(1), {e: e.value for e in Direction}
            ),
            type=construct.Mapping(
                construct.BitsInteger(2), {e: e.value for e in Type}
            ),
            recipient=construct.Mapping(
                construct.BitsInteger(5), {e: e.value for e in Recipient}
            ),
        ),
        raw=construct.Byte,
    ),
    bRequest=construct.Byte,
    wValue=construct.Int16ul,
    wIndex=construct.Int16ul,
    wLength=construct.Int16ul,
)


class SetupPacket:
    def __init__(self, raw_packet: bytes):
        self._raw = raw_packet
        self._parsed = _USB_SETUP_PACKET.parse(raw_packet)

    @property
    def request_type(self) -> int:
        return self._parsed.bmRequestType.raw

    @property
    def direction(self) -> Direction:
        return self._parsed.bmRequestType.parsed.direction

    @property
    def type(self) -> Type:
        return self._parsed.bmRequestType.parsed.type

    @property
    def recipient(self) -> Recipient:
        return self._parsed.bmRequestType.parsed.recipient

    @property
    def request(self) -> int:
        return self._parsed.bRequest

    @property
    def standard_request(self) -> Optional[StandardRequest]:
        if self.type == Type.STANDARD:
            return StandardRequest(self.request)
        else:
            return None

    @property
    def value(self) -> int:
        return self._parsed.wValue

    @property
    def index(self) -> int:
        return self._parsed.wIndex

    @property
    def length(self) -> int:
        return self._parsed.wLength

    @property
    def raw(self) -> bytes:
        return self._raw

    def __str__(self) -> str:
        return (
            f"s {self.request_type:02x} {self.request:02x} "
            f"{self.value:04x} {self.index:04x} {self.length:04x}"
        )

    def __repr__(self) -> str:
        return f"<usbmon.setup.SetupPacket {self.raw.hex()}>"
