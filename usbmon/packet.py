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
# SPDX-License-Identifier: Apache-2.0

import abc
import datetime

from typing import Tuple, Optional

from usbmon import constants
from usbmon import setup

PacketPair = Tuple['Packet', Optional['Packet']]


_XFERTYPE_TO_MNEMONIC = {
    constants.XferType.ISOCHRONOUS: 'Z',
    constants.XferType.INTERRUPT: 'I',
    constants.XferType.CONTROL: 'C',
    constants.XferType.BULK: 'B',
}

class Packet(abc.ABC):

    tag: str
    type: constants.PacketType
    xfer_type: constants.XferType
    devnum: int
    busnum: int
    setup_packet: Optional[setup.SetupPacket]
    timestamp: datetime.datetime
    status: int
    length: int

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
    def address(self) -> str:
        return f'{self.busnum}.{self.devnum}.{self.endpoint}'

    @property
    def type_mnemonic(self) -> str:
        return _XFERTYPE_TO_MNEMONIC[self.xfer_type]

    def __repr__(self) -> str:
        return (
            f'<{type(self).__name__} type: {self.type} tag: {self.tag}'
            f' address: {self.address!r} payload: {self.payload!r}>')


def get_submission(pair: PacketPair):
    first, second = pair
    if first.type == usbmon.constants.PacketType.SUBMISSION:
        return first
    else:
        return second

def get_callback(pair: PacketPair):
    first, second = pair
    if first.type == usbmon.constants.PacketType.CALLBACK:
        return first
    else:
        return second

def get_error(pair: PacketPair):
    first, second = pair
    if first.type == usbmon.constants.PacketType.ERROR:
        return first
    else:
        return second
