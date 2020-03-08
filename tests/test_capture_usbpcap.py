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
"""Tests for usbmon.capture.usbpcap."""

import os

from absl.testing import absltest

import usbmon.pcapng


class TestUsbpcap(absltest.TestCase):
    def test_parse(self):
        session = usbmon.pcapng.parse_file(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "testdata/usbpcap1.pcap",
            )
        )
        self.assertLen(list(session), 498)

        self.assertLen(session.device_descriptors, 1)

        (device_descriptor,) = session.device_descriptors.values()
        self.assertEqual(device_descriptor.address, "1.1")
        self.assertEqual(device_descriptor.vendor_id, 0x0627)
