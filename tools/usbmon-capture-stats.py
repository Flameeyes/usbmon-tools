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

import argparse
import collections
import sys

import usbmon.pcapng


def main():
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "pcap_file",
        action="store",
        type=str,
        help="Path to the pcapng file with the USB capture.",
    )

    args = parser.parse_args()

    direction_counter = collections.Counter()
    addresses_counter = collections.Counter()
    xfer_type_counter = collections.Counter()

    session = usbmon.pcapng.parse_file(args.pcap_file, retag_urbs=True)

    for packet in session:
        direction_counter[packet.direction] += 1
        addresses_counter[packet.address] += 1
        xfer_type_counter[packet.xfer_type] += 1

    print("Identified descriptors:")

    print(" Devices")
    for address, descriptor in session.device_descriptors.items():
        print(f"   {address}: {descriptor!r}")

    print()

    print("Packet Counters:")
    print(" Per direction:")
    for key, count in direction_counter.items():
        print(f"  {key!s}: {count}")

    print(" Per address:")
    for key, count in addresses_counter.items():
        print(f"  {key!s}: {count}")

    print(" Per transfer type:")
    for key, count in xfer_type_counter.items():
        print(f"  {key!s}: {count}")


if __name__ == "__main__":
    main()
