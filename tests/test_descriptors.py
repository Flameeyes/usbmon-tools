# python
#
# Copyright 2020 The usbmon-tools Authors
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
"""Tests for usbmon.setup."""

import binascii

from absl.testing import absltest

import usbmon.descriptors
import usbmon.structs


_GET_DEVICE_DESCRIPTOR_PAIR = (
    'AKrN2gAAAABTAoACAQAAPMUvaFwAAAAAIsoBAI3///8oAAAAAAAAAIAGAAEAACgAAAAAAAAAAAAAAgAAAAAAAA==',
    'AKrN2gAAAABDAoACAQAtAMUvaFwAAAAAUdABAAAAAAASAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAABIBAAIAAAAIbgX/AAABAQIAAQ==',
)

_OTHER_PAIR = (
    'gLi22gAAAABDAYECAQAtAMgvaFwAAAAAskoEAAAAAAAIAAAACAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAAEgAAAAAAAA',
    'gLi22gAAAABTAYECAQAtPMgvaFwAAAAAS0sEAI3///8IAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAEAgAAAAAAAA==',
)


def _get_packets(base64_packets):
    return tuple(
        usbmon.structs.Packet.from_bytes('<', binascii.a2b_base64(packet))
        for packet in base64_packets)


class DescriptorsTest(absltest.TestCase):

    def test_device_descriptor(self):
        packet_pair = _get_packets(_GET_DEVICE_DESCRIPTOR_PAIR)

        descriptor = usbmon.descriptors.search_device_descriptor(packet_pair)
        self.assertIsNotNone(descriptor)

        self.assertEqual(descriptor.address, '1.2')
        self.assertEqual(descriptor.language_id, 0)
        self.assertEqual(descriptor.index, 0)

        self.assertEqual(descriptor.vendor_id, 0x056e)
        self.assertEqual(descriptor.product_id, 0x00ff)

    def test_no_descriptor(self):
        packet_pair = _get_packets(_OTHER_PAIR)
        descriptor = usbmon.descriptors.search_device_descriptor(packet_pair)
        self.assertIsNone(descriptor)
