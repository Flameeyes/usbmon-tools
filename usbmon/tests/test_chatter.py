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
# SPDX-FileCopyrightText: © 2020 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0
"""Tests for usbmon.chatter."""

from absl.testing import absltest

import usbmon.chatter
import usbmon.constants


class DumpBytesTest(absltest.TestCase):
    def test_simple(self):
        self.assertEqual(
            usbmon.chatter.dump_bytes(usbmon.constants.Direction.IN, b"\x01\x02\x03"),
            "H<<D 00000000: 01 02 03                                          ...",
        )

        self.assertEqual(
            usbmon.chatter.dump_bytes(usbmon.constants.Direction.OUT, b"\x01\x02\x03"),
            "H>>D 00000000: 01 02 03                                          ...",
        )

    def test_empty(self):
        self.assertEqual(
            usbmon.chatter.dump_bytes(usbmon.constants.Direction.OUT, b""), ""
        )

    def test_print_empty(self):
        self.assertEqual(
            usbmon.chatter.dump_bytes(
                usbmon.constants.Direction.OUT,
                b"",
                print_empty=True,
            ),
            "H>>D 00000000:",
        )

    def test_custom_prefix(self):
        self.assertEqual(
            usbmon.chatter.dump_bytes(
                usbmon.constants.Direction.IN,
                b"\x01\x02\x03",
                prefix="pfx",
            ),
            "pfx H<<D 00000000: 01 02 03                                          ...",
        )

    def test_custom_prefix_empty(self):
        self.assertEqual(
            usbmon.chatter.dump_bytes(
                usbmon.constants.Direction.OUT,
                b"",
                prefix="pfx",
                print_empty=True,
            ),
            "pfx H>>D 00000000:",
        )
