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
"""Tests for usbmon.structs."""

import binascii
import collections

from absl.testing import absltest

import usbmon.capture_session
import usbmon.structs


_SESSION_BASE64 = (
    'AKrN2gAAAABTAoACAQAAPMUvaFwAAAAAIsoBAI3///8oAAAAAAAAAIAGAAEAACgAAAAAAAAAAAAAAgAAAAAAAA==',
    'AKrN2gAAAABDAoACAQAtAMUvaFwAAAAAUdABAAAAAAASAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAABIBAAIAAAAIbgX/AAABAQIAAQ==',
    'AKrN2gAAAABTAoABAQAAPMUvaFwAAAAAuNIBAI3///8oAAAAAAAAAIAGAAEAACgAAAAAAAAAAAAAAgAAAAAAAA==',
    'AKrN2gAAAABDAoABAQAtAMUvaFwAAAAAX9MBAAAAAAASAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAABIBAAIJAAFAax0CABQEAwIBAQ==',
    'gLi22gAAAABDAYECAQAtAMgvaFwAAAAAskoEAAAAAAAIAAAACAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAAEgAAAAAAAA',
    'gLi22gAAAABTAYECAQAtPMgvaFwAAAAAS0sEAI3///8IAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAA==',
    'gLi22gAAAABDAYECAQAtAMgvaFwAAAAAdUYGAAAAAAAIAAAACAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAAEAAAAAAAAA',
    'gLi22gAAAABTAYECAQAtPMgvaFwAAAAAC0cGAI3///8IAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAA==',
    'gLi22gAAAABDAYECAQAtAMgvaFwAAAAAS9oKAAAAAAAIAAAACAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAAFAAAAAAAAA',
    'gLi22gAAAABTAYECAQAtPMgvaFwAAAAA5doKAI3///8IAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAA==',
    'gLi22gAAAABDAYECAQAtAMgvaFwAAAAAI/0MAAAAAAAIAAAACAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAAEAAAAAAAAA',
    'gLi22gAAAABTAYECAQAtPMgvaFwAAAAAuf0MAI3///8IAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAA==',
    'gLi22gAAAABDAYECAQAtAMkvaFwAAAAAitkBAAAAAAAIAAAACAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAAGAAAAAAAAA',
    'gLi22gAAAABTAYECAQAtPMkvaFwAAAAAJNoBAI3///8IAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAA==',
    'gLi22gAAAABDAYECAQAtAMkvaFwAAAAAYfwDAAAAAAAIAAAACAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAAEAAAAAAAAA',
    'gLi22gAAAABTAYECAQAtPMkvaFwAAAAA9/wDAI3///8IAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAA==',
)


class SessionTest(absltest.TestCase):

    def test_retag(self):
        session = usbmon.capture_session.Session(retag_urbs=True)

        for base64_packet in _SESSION_BASE64:
            packet = usbmon.structs.Packet.from_bytes(
                '<', binascii.a2b_base64(base64_packet))
            session.add(packet)

        self.assertLen(list(session), 16)

        # Make sure that each URB tag only exists once.
        tag_counts = collections.Counter(
            (package.tag for package in session))
        self.assertCountEqual([2] * 8, tag_counts.values())

    def test_noretag(self):
        session = usbmon.capture_session.Session(retag_urbs=False)

        for base64_packet in _SESSION_BASE64:
            packet = usbmon.structs.Packet.from_bytes(
                '<', binascii.a2b_base64(base64_packet))
            session.add(packet)

        self.assertLen(list(session), 16)

        # Make sure that each URB tag only exists once.
        tag_counts = collections.Counter(
            (package.tag for package in session))
        self.assertCountEqual([4, 12], tag_counts.values())

    def test_incomplete(self):
        session = usbmon.capture_session.Session(retag_urbs=False)

        # Skip over the first and last packets.
        incomplete_session = _SESSION_BASE64[1:-1]
        for base64_packet in incomplete_session:
            packet = usbmon.structs.Packet.from_bytes(
                '<', binascii.a2b_base64(base64_packet))
            session.add(packet)

        self.assertLen(list(session), 14)
        self.assertLen(list(session.in_pairs()), 8)


class ConstructedSessionTest(absltest.TestCase):

    def setUp(self):
        super().setUp()
        self.session = usbmon.capture_session.Session(retag_urbs=True)

        for base64_packet in _SESSION_BASE64:
            packet = usbmon.structs.Packet.from_bytes(
                '<', binascii.a2b_base64(base64_packet))
            self.session.add(packet)

    def test_device_descriptors(self):
        self.assertLen(self.session.device_descriptors, 2)
