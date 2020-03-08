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
"""Abstraction to work with a collection of captured packets."""

import datetime
import itertools
import logging
import uuid
from typing import Dict, Generator, List, Mapping, Optional, Tuple

from usbmon import constants, descriptors, packet

_MAX_CALLBACK_ANTICIPATION = datetime.timedelta(seconds=0.2)


class Session:
    def __init__(self, retag_urbs: bool = True):
        """Initialize the capture session.

        Args:
          retag_urbs: Whether to replace URB tags with new UUIDs.
        """
        self._packet_pairs: List[packet.PacketPair] = []
        self._submitted_packets: Dict[str, packet.Packet] = {}
        self._retag_urbs: bool = retag_urbs

        self._device_descriptors: Optional[
            Dict[str, descriptors.DeviceDescriptor]
        ] = None

    def _append(self, first: packet.Packet, second: Optional[packet.Packet]) -> None:
        if self._retag_urbs:
            # Totally random UUID, is more useful than the original URB ID.  We
            # take the hex string format, because that complies with the usbmon
            # documentation, without risking parsing errors due to dashes.
            tag = uuid.uuid4().hex
            first.tag = tag
            if second is not None:
                second.tag = tag
        self._packet_pairs.append((first, second))

    def add(self, packet: packet.Packet) -> None:
        """Add a packet to the session, matching with its previous event."""

        # Events can be in either S;E, S;C, or C;S order. So we just keep a
        # "previous" packet for each tag, and once we matched two we reset the
        # URB.
        if packet.tag in self._submitted_packets:
            first = self._submitted_packets.pop(packet.tag)
            time_distance = abs(first.timestamp - packet.timestamp)

            # Unfortunately, since the promise of the ID being unique is not
            # maintained by Linux, there may be false matches. To reduce the
            # likeliness of it, reject C events arriving more than 200ms before
            # their matching S event.
            if (
                first.type == constants.PacketType.CALLBACK
                and time_distance > _MAX_CALLBACK_ANTICIPATION
            ):
                logging.debug(
                    "Callback (%r) arrived long before submit (%r): %s",
                    first,
                    packet,
                    time_distance,
                )
                self._append(first, None)
                self._submitted_packets[packet.tag] = packet
            else:
                self._append(first, packet)
        else:
            self._submitted_packets[packet.tag] = packet

    def in_pairs(self) -> Generator[packet.PacketPair, None, None]:
        yield from self._packet_pairs
        for unmatched_packet in self._submitted_packets.values():
            yield (unmatched_packet, None)

    def _scan_for_descriptors(self) -> None:
        self._device_descriptors = {}
        for pair in self.in_pairs():
            descriptor = descriptors.search_device_descriptor(pair)
            if descriptor:
                self._device_descriptors[descriptor.address] = descriptor

    def in_order(self) -> Generator[packet.Packet, None, None]:
        """Yield the packets in their timestamp order."""
        yield from sorted(
            filter(None, itertools.chain(*self.in_pairs())), key=lambda x: x.timestamp,
        )

    def __iter__(self) -> Generator[packet.Packet, None, None]:
        return self.in_order()

    @property
    def device_descriptors(self) -> Mapping[str, descriptors.DeviceDescriptor]:
        if self._device_descriptors is None:
            self._scan_for_descriptors()
        assert self._device_descriptors is not None

        return self._device_descriptors
