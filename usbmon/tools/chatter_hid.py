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

import logging
import sys
from typing import BinaryIO

import click

import usbmon
import usbmon.chatter
import usbmon.constants
import usbmon.pcapng

HID_XFER_TYPES = (
    usbmon.constants.XferType.INTERRUPT,
    usbmon.constants.XferType.CONTROL,
)


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
    for pair in session.in_pairs():
        submission = usbmon.packet.get_submission(pair)
        callback = usbmon.packet.get_callback(pair)

        if not submission or not callback:
            # We don't care which one is missing, we can just get the first
            # packet's tag. If there's an ERROR packet, it'll also behave as we
            # want it to.
            logging.debug("Ignoring singleton packet: %s" % pair[0].tag)
            continue

        if not submission.address == device_address:
            # No need to check second, they will be linked.
            continue

        if submission.xfer_type == usbmon.constants.XferType.INTERRUPT:
            pass
        elif (
            submission.xfer_type == usbmon.constants.XferType.CONTROL
            and submission.setup_packet
            and submission.setup_packet.type == usbmon.setup.Type.CLASS
        ):
            pass
        else:
            continue

        if submission.direction == usbmon.constants.Direction.OUT:
            dumped_packet = submission
        else:
            dumped_packet = callback

        if dumped_packet.payload:
            print(usbmon.chatter.dump_packet(dumped_packet), "\n")


if __name__ == "__main__":
    main()
