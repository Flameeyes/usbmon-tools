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

import hexdump

from usbmon import constants
from usbmon import structs

_DIRECTION_TO_PREFIX = {
    constants.Direction.OUT: 'H>>D ',
    constants.Direction.IN: 'H<<D ',
}


def dump_bytes(direction: constants.Direction, payload: bytes) -> str:
    if not payload:
        return ''

    hexd = hexdump.dumpgen(payload)
    return '\n'.join(''.join((_DIRECTION_TO_PREFIX[direction], hexrow))
                     for hexrow in hexd)


def dump_packet(packet: structs.Packet) -> str:
    return dump_bytes(packet.direction, packet.payload)
