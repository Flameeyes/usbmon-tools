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
"""Convert a pcapng usbmon capture to usbmon text format.

This is a simple tool that allows generating usbmon text format output based on
the binary (mmap) API.

It tries to stay as close to the current Linux text format as possible, although
with a few notable changes:

 - URBs can be optionally retagged, so that each Submission/Callback pair has a
   unique tag. This is unlike the Linux interface, where the tag is the
   in-memory pointer to the URB structure, and is thus repeated in the same
   capture, as structures are reused. When this is enabled, the tag is a UUID,
   and thus much longer than the kernel's own tag.

 - The timestamp for the captures is provided in full, rather than being
   constrained to 32-bit range.
"""

import sys
from typing import BinaryIO

import click

import usbmon.pcapng


@click.command()
@click.option(
    "--address-prefix",
    help=(
        "Prefix match applied to the device address in text format. "
        "Only packets with source or destination matching this prefix "
        "will be printed out."
    ),
    required=True,
)
@click.option(
    "--retag-urbs / --no-retag-urbs",
    help=(
        "Apply new, unique tags to the URBs when converting to text "
        "format. This works around the lack of unique keys in the "
        "captures."
    ),
    default=True,
    show_default=True,
)
@click.argument(
    "pcap-file",
    type=click.File(mode="rb"),
    required=True,
)
def main(*, address_prefix: str, retag_urbs: bool, pcap_file: BinaryIO) -> None:
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    session = usbmon.pcapng.parse_stream(pcap_file, retag_urbs=retag_urbs)
    for packet in session:
        if not packet.address.startswith(address_prefix):
            continue
        print(str(packet))


if __name__ == "__main__":
    main()
