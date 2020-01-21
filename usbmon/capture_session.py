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

import itertools
import logging
from typing import Dict, Generator, List, Mapping, Optional, Tuple
import uuid

from usbmon import descriptors
from usbmon import structs


class Session:

    def __init__(self, retag_urbs: bool = True):
        """Initialize the capture session.

        Args:
          retag_urbs: Whether to replace URB tags with new UUIDs.
        """
        self._packet_pairs: List[structs.PacketPair] = []
        self._submitted_packets: Dict[str, structs.Packet] = {}
        self._retag_urbs: bool = retag_urbs

        self._device_descriptors: Optional[
            Dict[str, descriptors.DeviceDescriptor]] = None

    def _append(
            self, first: structs.Packet, second: Optional[structs.Packet]
    ) -> None:
        if self._retag_urbs:
            # Totally random UUID, is more useful than the original URB ID.  We
            # take the hex string format, because that complies with the usbmon
            # documentation, without risking parsing errors due to dashes.
            tag = uuid.uuid4().hex
            first.tag = tag
            if second is not None:
                second.tag = tag
        self._packet_pairs.append((first, second))

    def add(self, packet: structs.Packet) -> None:
        """Add a packet to the session, matching with its previous event."""

        # Events can be in either S;E, S;C, or C;S order. So we just keep a
        # "previous" packet for each tag, and once we matched two we reset the
        # URB.
        if packet.tag in self._submitted_packets:
            first = self._submitted_packets.pop(packet.tag)
            self._append(first, packet)
        else:
            self._submitted_packets[packet.tag] = packet

    def _scan_for_descriptors(self) -> None:
        self._device_descriptors = {}
        for pair in self.in_pairs():
            descriptor = descriptors.search_device_descriptor(pair)
            if descriptor:
                self._device_descriptors[descriptor.address] = descriptor

    def in_order(self) -> Generator[structs.Packet, None, None]:
        """Yield the packets in their timestamp order."""
        yield from sorted(
            filter(None, itertools.chain(*self._packet_pairs)),
            key=lambda x: x.timestamp)

    def in_pairs(self) -> Generator[structs.PacketPair, None, None]:
        yield from self._packet_pairs

    def __iter__(self) -> Generator[structs.Packet, None, None]:
        return self.in_order()

    @property
    def device_descriptors(self) -> Mapping[str, descriptors.DeviceDescriptor]:
        if self._device_descriptors is None:
            self._scan_for_descriptors()
        assert self._device_descriptors is not None

        return self._device_descriptors
