# Copyright 2021 The usbmon-tools Authors
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
# SPDX-FileCopyrightText: © 2021 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0

from absl.testing import parameterized

import usbmon.addresses


class DeviceAddressTest(parameterized.TestCase):
    @parameterized.parameters(
        ("1.2", usbmon.addresses.DeviceAddress(1, 2)),
        ("2.74", usbmon.addresses.DeviceAddress(2, 74)),
        ("3.127", usbmon.addresses.DeviceAddress(3, 127)),
    )
    def test_valid_address_from_str(
        self, str_input: str, expected: usbmon.addresses.DeviceAddress
    ):
        received = usbmon.addresses.DeviceAddress.from_string(str_input)
        self.assertEqual(received, expected)
        self.assertEqual(str(received), str_input)

    def test_valid_address_no_roundtrip(self):
        received = usbmon.addresses.DeviceAddress.from_string("002.034")
        self.assertEqual(received, usbmon.addresses.DeviceAddress(2, 34))
        self.assertEqual(str(received), "2.34")

    @parameterized.parameters(
        "1.2.0", "1.3.5.6", "42", "a", "1.a", "a2", "0xf3", "1,3", "1/2", "Ranma"
    )
    def test_invalid_address(self, str_input: str):
        with self.assertRaises(ValueError):
            usbmon.addresses.DeviceAddress.from_string(str_input)


class EndpointAddressTest(parameterized.TestCase):
    @parameterized.parameters(
        ("1.2.2", usbmon.addresses.EndpointAddress(1, 2, 2)),
        ("2.74.0", usbmon.addresses.EndpointAddress(2, 74, 0)),
        ("3.127.5", usbmon.addresses.EndpointAddress(3, 127, 5)),
    )
    def test_valid_address_from_str(
        self, str_input: str, expected: usbmon.addresses.EndpointAddress
    ):
        received = usbmon.addresses.EndpointAddress.from_string(str_input)
        self.assertEqual(received, expected)
        self.assertEqual(str(received), str_input)

    def test_valid_address_no_roundtrip(self):
        received = usbmon.addresses.EndpointAddress.from_string("002.034.005")
        self.assertEqual(received, usbmon.addresses.EndpointAddress(2, 34, 5))
        self.assertEqual(str(received), "2.34.5")

    @parameterized.parameters(
        "1.2", "1.3.5.6", "42", "a", "1.a", "a2", "0xf3", "1,3", "1/2", "Ranma"
    )
    def test_invalid_address(self, str_input: str):
        with self.assertRaises(ValueError):
            usbmon.addresses.EndpointAddress.from_string(str_input)

    def test_device_address(self):
        received = usbmon.addresses.EndpointAddress(1, 2, 5)
        self.assertEqual(received.device_address, usbmon.addresses.DeviceAddress(1, 2))
