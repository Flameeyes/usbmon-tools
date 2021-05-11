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

import dataclasses


@dataclasses.dataclass(frozen=True, eq=True, order=True)
class DeviceAddress:
    bus: int
    device: int

    @classmethod
    def from_string(cls, address: str) -> "DeviceAddress":
        bus, device = address.split(".", 1)
        return cls(int(bus), int(device))

    def __str__(self) -> str:
        return f"{self.bus}.{self.device}"


@dataclasses.dataclass(frozen=True, eq=True, order=True)
class EndpointAddress:
    bus: int
    device: int
    endpoint: int

    @classmethod
    def from_string(cls, address: str) -> "EndpointAddress":
        bus, device, endpoint = address.split(".", 2)
        return cls(int(bus), int(device), int(endpoint))

    @property
    def device_address(self) -> DeviceAddress:
        return DeviceAddress(self.bus, self.device)

    def __str__(self) -> str:
        return f"{self.bus}.{self.device}.{self.endpoint}"
