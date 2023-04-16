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
# SPDX-FileCopyrightText: © 2019 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0

import abc
import datetime
from typing import Optional, Tuple

from usbmon import addresses, constants, setup

PacketPair = Tuple["Packet", Optional["Packet"]]


_XFERTYPE_TO_MNEMONIC = {
    constants.XferType.ISOCHRONOUS: "Z",
    constants.XferType.INTERRUPT: "I",
    constants.XferType.CONTROL: "C",
    constants.XferType.BULK: "B",
}


class Packet(abc.ABC):
    tag: int
    type: constants.PacketType
    xfer_type: constants.XferType
    devnum: int
    busnum: int
    setup_packet: Optional[setup.SetupPacket]
    timestamp: datetime.datetime
    status: int

    length: int  # submitted length
    payload: bytes

    epnum: int

    @property
    def endpoint(self) -> int:
        return self.epnum & 0x7F

    @property
    def direction(self) -> constants.Direction:
        if self.epnum & 0x80:
            return constants.Direction.IN
        else:
            return constants.Direction.OUT

    @property
    def address(self) -> addresses.EndpointAddress:
        return addresses.EndpointAddress(self.busnum, self.devnum, self.endpoint)

    @property
    def type_mnemonic(self) -> str:
        return _XFERTYPE_TO_MNEMONIC[self.xfer_type]

    def __repr__(self) -> str:
        return (
            f"<{type(self).__name__} type: {self.type} tag: {self.tag}"
            f" address: {self.address!r} payload: {self.payload!r}>"
        )


def get_submission(pair: PacketPair):
    first, second = pair
    if first.type == constants.PacketType.SUBMISSION:
        return first
    else:
        return second


def get_callback(pair: PacketPair):
    first, second = pair
    if first.type == constants.PacketType.CALLBACK:
        return first
    else:
        return second


def get_error(pair: PacketPair):
    first, second = pair
    if first.type == constants.PacketType.ERROR:
        return first
    else:
        return second
