#!/usr/bin/env python3
#
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
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys

from typing import Optional

import usbmon.chatter
import usbmon.pcapng


def main():
    if sys.version_info < (3, 7):
        raise Exception(
            'Unsupported Python version, please use at least Python 3.7.')

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--cp2110_addr', action='store', type=str, required=True,
        help='USB address of the CP2110 device to extract chatter of.')

    parser.add_argument(
        'pcap_file', action='store', type=str,
        help='Path to the pcapng file with the USB capture.')

    args = parser.parse_args()

    direction: Optional[usbmon.constants.Direction] = None
    reconstructed_packet: bytes = b''

    session = usbmon.pcapng.parse_file(args.pcap_file, retag_urbs=True)
    for first, second in session.in_pairs():
        if not first.address.startswith(args.cp2110_addr):
            # No need to check second, they will be linked.
            continue

        if first.xfer_type != usbmon.constants.XferType.INTERRUPT:
            continue

        if first.direction != direction and reconstructed_packet:
            print(usbmon.chatter.dump_bytes(direction, reconstructed_packet))
            direction = None
            reconstructed_packet = b''

        direction = first.direction
        if direction == usbmon.constants.Direction.OUT:
            payload = first.payload
        else:
            payload = second.payload

        if payload and 0 <= payload[0] <= 0x3F:
            reconstructed_packet += payload[1:]

    print(usbmon.chatter.dump_bytes(direction, reconstructed_packet))


if __name__ == "__main__":
    main()
