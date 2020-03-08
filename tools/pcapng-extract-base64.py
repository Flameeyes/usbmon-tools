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
"""Extract the packets from a pcapng capture in base64 format."""

import argparse
import binascii
import sys

import pcapng


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

    with open(args.pcap_file, "rb") as pcap_file:
        scanner = pcapng.FileScanner(pcap_file)
        endianness = None
        for block in scanner:
            if isinstance(block, pcapng.blocks.SectionHeader):
                endianness = block.endianness
            elif isinstance(block, pcapng.blocks.InterfaceDescription):
                if (
                    block.link_type
                    != pcapng.constants.link_types.LINKTYPE_USB_LINUX_MMAPPED
                ):
                    raise Exception(
                        f"In file {args.pcap_file}: expected USB capture, "
                        f"found {block.link_type_description}."
                    )
            elif isinstance(block, pcapng.blocks.EnhancedPacket):
                assert block.interface_id == 0
                _, _, payload = block.packet_payload_info
                print(binascii.b2a_base64(payload, newline=False).decode("ascii"))


if __name__ == "__main__":
    main()
