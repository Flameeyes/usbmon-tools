#!/usr/bin/env python3
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

import usbmon
import usbmon.chatter
import usbmon.pcapng

import argparse
import sys

def main():
    if sys.version_info < (3, 7):
        raise Exception(
            'Unsupported Python version, please use at least Python 3.7.')

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--addr_prefix', action='store', type=str, required=True,
        help=('Prefix match applied to the device address in text format. '
              'Only packets with source or destination matching this prefix '
              'will be printed out.'))

    parser.add_argument(
        'pcap_file', action='store', type=str,
        help='Path to the pcapng file with the USB capture.')

    args = parser.parse_args()

    session = usbmon.pcapng.parse_file(args.pcap_file, retag_urbs=True)
    for first, second in session.in_pairs():
        if not first.address.startswith(args.addr_prefix):
            # No need to check second, they will be linked.
            continue

        if first.xfer_type != usbmon.constants.XferType.INTERRUPT:
            continue

        if first.direction == usbmon.constants.Direction.OUT:
            packet = first
        else:
            packet = second

        if packet.payload:
            print(usbmon.chatter.dump_packet(packet), '\n')


if __name__ == "__main__":
    main()
