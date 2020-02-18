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

from typing import Optional

import hexdump

from usbmon import constants, packet

_DIRECTION_TO_PREFIX = {
    constants.Direction.OUT: 'H>>D ',
    constants.Direction.IN: 'H<<D ',
}


def dump_bytes(
        direction: constants.Direction,
        payload: bytes,
        prefix: Optional[str] = None,
        print_empty: bool = False,
) -> str:
    """Return a "chatter" string for the provided payload.

    This function provides a hexdump-based output for a given binary payload,
    including a direction marker prefix, and an optional customized prefix.

    Args:
      direction: The direction the payload traveled.
      payload: The actual payload to dump.
      prefix: If provided, this string will be added in front of each output
        line.
      print_empty: Whether to print an empty dump for zero-length payloads.

    Returns:
      A multi-line string suitable for printing to standard output.
    """
    line_prefix = _DIRECTION_TO_PREFIX[direction]

    if prefix:
        line_prefix = f'{prefix} {line_prefix}'

    if not payload:
        if not print_empty:
            return ''
        else:
            # This is tricky, hexdump does not actually do what we want it to,
            # so we fake it.
            return f'{line_prefix}00000000:'

    hexd = hexdump.dumpgen(payload)
    return '\n'.join(
        ''.join((line_prefix, hexrow)) for hexrow in hexd)


def dump_packet(packet: packet.Packet, **kwargs) -> str:
    return dump_bytes(packet.direction, packet.payload, **kwargs)
