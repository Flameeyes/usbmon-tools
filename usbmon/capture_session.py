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
import uuid

from usbmon import structs


class Session:

    def __init__(self, retag_urbs=True):
        """Initialize the capture session.
        
        Args:
          retag_urbs: Whether to replace URB tags with new UUIDs.
        """
        self._packet_pairs = []
        self._submitted_packets = {}
        self._retag_urbs = retag_urbs

    def _append(self, submission, callback):
        if self._retag_urbs:
            # Totally random UUID, is more useful than the original URB ID.  We
            # take the hex string format, because that complies with the usbmon
            # documentation, without risking parsing errors due to dashes.
            tag = uuid.uuid4().hex
            if submission is not None:
                submission.tag = tag
            if callback is not None:
                callback.tag = tag
        self._packet_pairs.append((submission, callback))

    def add(self, packet):
        if packet.type == structs.PacketType.SUBMISSION:
            # Check first if there's already a submission with the same ID. This
            # should never happen but it can happen if there is a corrupted
            # capture file. If there is a stale capture, append it as such.
            stale_submission = self._submitted_packets.get(packet.tag, None)
            if stale_submission is not None:
                logging.debug('Found stale submission for URB %s', packet.tg)
                self._append(stale_submission, None)

            self._submitted_packets[packet.tag] = packet
        else:
            submission = self._submitted_packets.pop(packet.tag, None)
            self._append(submission, packet)

    def in_order(self):
        """Yield the packets in their timestamp order."""
        yield from sorted(
            filter(None, itertools.chain(*self._packet_pairs)),
            key=lambda x: x.timestamp)

    def in_pairs(self):
        yield from self._packet_pairs
