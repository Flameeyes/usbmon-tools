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

import itertools
from typing import Optional, Set, Tuple

import usbmon.addresses
import usbmon.capture_session


class ExtractorError(Exception):
    pass


class DeviceSearchError(ExtractorError):
    pass


def find_device_in_session(
    session: usbmon.capture_session.Session,
    device_address: Optional[usbmon.addresses.DeviceAddress],
    id_pairs: Set[Tuple[int, int]],
    device_name="the device",
) -> usbmon.addresses.DeviceAddress:
    if device_address is not None:
        return device_address

    # If there was no --device-address flag on the command line, we need to search for the device
    # in the session's descriptors (if it's there at all.)
    # Note that this is not foolproof, as different devices have multiple possible custom VID/PID
    # pairs, so we do a best guess.

    found_addresses = [session.find_devices_by_ids(vid, pid) for vid, pid in id_pairs]
    possible_addresses = list(itertools.chain(*found_addresses))

    if len(possible_addresses) > 1:
        possible_addresses_str = ", ".join(
            str(address) for address in possible_addresses
        )
        raise DeviceSearchError(
            f"Multiple device addresses for {device_name} found, please select one of {possible_addresses_str}"
        )
    elif len(possible_addresses) == 0:
        raise DeviceSearchError(
            f"No descriptor for {device_name} found, please select an address."
        )
    else:
        (device_address,) = possible_addresses

    return device_address
