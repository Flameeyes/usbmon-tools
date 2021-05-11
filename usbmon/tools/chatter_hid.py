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

import sys
from typing import BinaryIO

import click

import usbmon
import usbmon.pcapng
import usbmon.support.hid


@click.command()
@click.option(
    "--device-address",
    help="USB address of the HID device to extract chatter of.",
    required=True,
)
@click.argument(
    "pcap-file",
    type=click.File(mode="rb"),
    required=True,
)
def main(*, device_address: str, pcap_file: BinaryIO) -> None:
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    session = usbmon.pcapng.parse_stream(pcap_file, retag_urbs=True)
    for packet in usbmon.support.hid.select(session, device_address=device_address):
        print(usbmon.support.hid.dump_packet(packet), "\n")


if __name__ == "__main__":
    main()
