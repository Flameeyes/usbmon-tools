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
"""Abstraction to work with a collection of captured packets."""

import datetime
import itertools
import logging
from typing import Dict, Iterator, List, Mapping, Optional

from usbmon import addresses, constants, descriptors, packet

_MAX_CALLBACK_ANTICIPATION = datetime.timedelta(seconds=0.2)


class Session:
    def __init__(self, retag_urbs: bool = True):
        """Initialize the capture session.

        Args:
          retag_urbs: Whether to replace URB tags with sequence numbers.
        """
        self._packet_pairs: List[packet.PacketPair] = []
        self._submitted_packets: Dict[int, packet.Packet] = {}
        self._next_tag = 0
        self._retag_urbs: bool = retag_urbs

        self._device_descriptors: Optional[
            Dict[addresses.DeviceAddress, descriptors.DeviceDescriptor]
        ] = None

    def _append(self, first: packet.Packet, second: Optional[packet.Packet]) -> None:
        if self._retag_urbs:
            # The original URB IDs are not as unique as they should be. Instead, we
            # apply an incremental sequence number. This allows for unique package
            # identification, while maintaining compatibility with the usbmon binary
            # format, that expects a 64-bit value maximum.
            tag = self._next_tag
            self._next_tag += 1
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

    def in_pairs(self) -> Iterator[packet.PacketPair]:
        yield from self._packet_pairs
        for unmatched_packet in self._submitted_packets.values():
            yield (unmatched_packet, None)

    def _scan_for_descriptors(self) -> None:
        self._device_descriptors = {}
        for pair in self.in_pairs():
            descriptor = descriptors.search_device_descriptor(pair)
            if descriptor:
                self._device_descriptors[descriptor.address] = descriptor

    def in_order(self) -> Iterator[packet.Packet]:
        """Yield the packets in their timestamp order."""
        yield from sorted(
            filter(None, itertools.chain(*self.in_pairs())),
            key=lambda x: x.timestamp,
        )

    def __iter__(self) -> Iterator[packet.Packet]:
        return self.in_order()

    @property
    def device_descriptors(
        self,
    ) -> Mapping[addresses.DeviceAddress, descriptors.DeviceDescriptor]:
        if self._device_descriptors is None:
            self._scan_for_descriptors()
        assert self._device_descriptors is not None

        return self._device_descriptors

    def find_devices_by_ids(
        self, vendor_id: int, product_id: Optional[int]
    ) -> Iterator[addresses.DeviceAddress]:
        """Look up in the descriptors table for a device matching the VID/PID provided.

        If product_id is None, look up any device from the corresponding vendor.
        """
        for descriptor in self.device_descriptors.values():
            # Sometimes there's a descriptor for a not-fully-initialized
            # device, with no address. Exclude those.
            if descriptor.address.device == 0:
                continue

            if descriptor.vendor_id != vendor_id:
                continue

            if product_id is None or descriptor.product_id == product_id:
                yield descriptor.address
