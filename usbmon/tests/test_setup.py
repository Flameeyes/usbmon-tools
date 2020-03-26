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

from absl.testing import absltest

import usbmon.setup

setup_packet = b"\x80\x06\x00\x01\x00\x00\x28\x00"


class SetupTest(absltest.TestCase):
    def test_setup_packet(self):
        setup = usbmon.setup.SetupPacket(setup_packet)

        self.assertEqual(str(setup), "s 80 06 0100 0000 0028")
        self.assertEqual(repr(setup), "<usbmon.setup.SetupPacket 8006000100002800>")

        self.assertEqual(setup.raw, setup_packet)
        self.assertEqual(setup.type, usbmon.setup.Type.STANDARD)
        self.assertEqual(
            setup.standard_request, usbmon.setup.StandardRequest.GET_DESCRIPTOR
        )

        self.assertEqual(setup.direction, usbmon.setup.Direction.DEVICE_TO_HOST)
