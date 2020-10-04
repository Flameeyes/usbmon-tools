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
# SPDX-FileCopyrightText: © 2019 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0
"""Extract the packets from a pcapng capture in base64 format."""

import binascii
import sys
from typing import BinaryIO

import pcapng

import click


@click.command()
@click.argument(
    "pcap-file", type=click.File(mode="rb"), required=True,
)
def main(*, pcap_file: BinaryIO) -> None:
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    scanner = pcapng.FileScanner(pcap_file)
    for block in scanner:
        if isinstance(block, pcapng.blocks.InterfaceDescription):
            if (
                block.link_type
                != pcapng.constants.link_types.LINKTYPE_USB_LINUX_MMAPPED
            ):
                raise Exception(
                    f"In file {pcap_file.name}: expected USB capture, "
                    f"found {block.link_type_description}."
                )
        elif isinstance(block, pcapng.blocks.EnhancedPacket):
            assert block.interface_id == 0
            _, _, payload = block.packet_payload_info
            print(binascii.b2a_base64(payload, newline=False).decode("ascii"))


if __name__ == "__main__":
    main()
