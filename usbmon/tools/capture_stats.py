#!/usr/bin/env python3
# Copyright 2019 Google LLC
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
# SPDX-FileCopyrightText: © 2019 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0

import collections
import sys
from typing import BinaryIO, MutableMapping

import click

import usbmon
import usbmon.addresses
import usbmon.pcapng


@click.command()
@click.option(
    "--address-prefix",
    help=(
        "Prefix match applied to the device address in text format. "
        "Only packets with source or destination matching this prefix "
        "will be printed out."
    ),
    default="",
)
@click.argument(
    "pcap-file",
    type=click.File(mode="rb"),
    required=True,
)
def main(*, address_prefix: str, pcap_file: BinaryIO) -> None:
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    direction_counter: MutableMapping[
        usbmon.constants.Direction, int
    ] = collections.Counter()
    addresses_counter: MutableMapping[
        usbmon.addresses.EndpointAddress, int
    ] = collections.Counter()
    xfer_type_counter: MutableMapping[
        usbmon.constants.XferType, int
    ] = collections.Counter()

    session = usbmon.pcapng.parse_stream(pcap_file, retag_urbs=True)

    for packet in session:
        if not str(packet.address).startswith(address_prefix):
            continue

        direction_counter[packet.direction] += 1
        addresses_counter[packet.address] += 1
        xfer_type_counter[packet.xfer_type] += 1

    print("Identified descriptors:")

    print(" Devices")
    for address, descriptor in session.device_descriptors.items():
        if str(address).startswith(address_prefix):
            print(f"   {address}: {descriptor}")

    print()

    print("Packet Counters:")
    print(" Per direction:")
    for direction, count in direction_counter.items():
        print(f"  {direction!s}: {count}")

    print(" Per address:")
    for endpoint_address, count in addresses_counter.items():
        print(f"  {endpoint_address!s}: {count}")

    print(" Per transfer type:")
    for xfertype, count in xfer_type_counter.items():
        print(f"  {xfertype!s}: {count}")


if __name__ == "__main__":
    main()
