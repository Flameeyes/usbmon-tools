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
"""Support module for HID-based protocols."""

import dataclasses
import logging
from typing import Iterator, Optional

import usbmon.addresses
import usbmon.capture_session
import usbmon.chatter
import usbmon.constants
import usbmon.packet

_LOGGER = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class HIDPacket:
    urb: usbmon.packet.Packet

    @property
    def direction(self) -> usbmon.constants.Direction:
        return self.urb.direction

    @property
    def report_id(self) -> int:
        return self.urb.payload[0]

    @property
    def report_content(self) -> bytes:
        return self.urb.payload[1:]


def _is_possible_hid_submission(packet: usbmon.packet.Packet) -> bool:
    if packet.xfer_type == usbmon.constants.XferType.INTERRUPT:
        return True

    if (
        packet.xfer_type == usbmon.constants.XferType.CONTROL
        and packet.setup_packet
        and packet.setup_packet.type == usbmon.setup.Type.CLASS
    ):
        return True

    return False


def select(
    session: usbmon.capture_session.Session,
    device_address: Optional[usbmon.addresses.DeviceAddress] = None,
) -> Iterator[HIDPacket]:
    """Extract packets pairs from a session that match the HID protocol.

    This function simplifies the logic behind the selection of packets in a capture,
    optionally including limiting to one specific address.
    """
    for pair in session.in_pairs():
        submission = usbmon.packet.get_submission(pair)
        callback = usbmon.packet.get_callback(pair)

        if not submission or not callback:
            # We don't care which one is missing, we can just get the first
            # packet's tag. If there's an ERROR packet, it'll also behave as we
            # want it to.
            _LOGGER.debug("Ignoring singleton packet: {pair[0].tag}")
            continue

        if (
            device_address is not None
            and submission.address.device_address != device_address
        ):
            # No need to check second, they will be linked.
            continue

        if not _is_possible_hid_submission(submission):
            continue

        if submission.direction == usbmon.constants.Direction.OUT:
            if submission.payload:
                yield HIDPacket(submission)
        else:
            if callback.payload:
                yield HIDPacket(callback)


def dump_packet(packet: HIDPacket, **kwargs) -> str:
    return usbmon.chatter.dump_bytes(
        packet.direction,
        packet.report_content,
        prefix=f"[0x{packet.report_id:02x}]",
        **kwargs,
    )
