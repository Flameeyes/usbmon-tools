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
"""Tests for usbmon.pcapng."""

import os

from absl.testing import absltest

import usbmon.pcapng


class PcapTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self._test1_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "../../testdata/test1.pcap"
        )

    def test_parse_file(self):
        session = usbmon.pcapng.parse_file(self._test1_path)
        self.assertLen(list(session), 16)

    def test_parse_bytes(self):
        with open(self._test1_path, "rb") as test1_file:
            pcap_data = test1_file.read()

        session = usbmon.pcapng.parse_bytes(pcap_data)
        self.assertLen(list(session), 16)

    def test_parse_stream(self):
        with open(self._test1_path, "rb") as test1_file:
            session = usbmon.pcapng.parse_stream(test1_file)
            self.assertLen(list(session), 16)
