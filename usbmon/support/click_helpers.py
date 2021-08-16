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

import click

import usbmon.addresses


class DeviceAddressType(click.ParamType):
    name = "device address"

    def convert(self, value: str, param, ctx) -> usbmon.addresses.DeviceAddress:
        try:
            return usbmon.addresses.DeviceAddress.from_string(value)
        except (TypeError, ValueError):
            self.fail(f"{value!r} is not a valid device address", param, ctx)


class EndpointAddressType(click.ParamType):
    name = "endpoint address"

    def convert(self, value: str, param, ctx) -> usbmon.addresses.EndpointAddress:
        try:
            return usbmon.addresses.EndpointAddress.from_string(value)
        except (TypeError, ValueError):
            self.fail(f"{value!r} is not a valid endpoint address", param, ctx)
