#!/usr/bin/env python3
#
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

import logging
import sys
from typing import BinaryIO, Optional

import click

import usbmon
import usbmon.chatter
import usbmon.constants
import usbmon.pcapng
from usbmon.support import cp210x

CP210X_XFER_TYPES = (
    usbmon.constants.XferType.BULK,
    usbmon.constants.XferType.CONTROL,
)


@click.command()
@click.option(
    "--device-address",
    help="USB address of the CP210x device to extract the chatter of.",
)
@click.argument(
    "pcap-file",
    type=click.File(mode="rb"),
    required=True,
)
def main(*, device_address: str, pcap_file: BinaryIO) -> None:
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    direction: Optional[usbmon.constants.Direction] = None
    reconstructed_packet: bytes = b""

    session = usbmon.pcapng.parse_stream(pcap_file, retag_urbs=True)

    if not device_address:
        # If there's no cp2110_addr flag on the command line, we can search for
        # the device in the session's descriptors (if it's there at all.)  Note
        # that this is not foolproof, because the CP2110 devices can be set to
        # have their own custom VID/PID pairs.
        for descriptor in session.device_descriptors.values():
            if (
                descriptor.vendor_id == cp210x.DEFAULT_VENDOR_ID
                and descriptor.product_id == cp210x.DEFAULT_PRODUCT_ID
                and
                # Sometimes there's a descriptor for a not-fully-initialized
                # device, with no address. Exclude those.
                not descriptor.address.endswith(".0")
            ):
                device_address = descriptor.address

    if not device_address:
        raise click.UsageError("Unable to identify a CP210x device descriptor.")

    for pair in session.in_pairs():
        submission = usbmon.packet.get_submission(pair)
        callback = usbmon.packet.get_callback(pair)

        if not submission or not callback:
            # We don't care which one is missing, we can just get the first
            # packet's tag. If there's an ERROR packet, it'll also behave as we
            # want it to.
            logging.debug(f"Ignoring singleton packet: {pair[0].tag}")
            continue

        if not submission.address.startswith(device_address):
            # No need to check second, they will be linked.
            continue

        if submission.xfer_type == usbmon.constants.XferType.BULK:
            pass
        elif (
            submission.xfer_type == usbmon.constants.XferType.CONTROL
            and submission.setup_packet
            and submission.setup_packet.type == usbmon.setup.Type.CLASS
        ):
            pass
        else:
            continue

        if submission.direction != direction and reconstructed_packet:
            assert direction is not None
            print(usbmon.chatter.dump_bytes(direction, reconstructed_packet))
            print()
            direction = None
            reconstructed_packet = b""

        direction = submission.direction
        if direction == usbmon.constants.Direction.OUT:
            reconstructed_packet += submission.payload
        else:
            reconstructed_packet += callback.payload

    assert direction is not None
    print(usbmon.chatter.dump_bytes(direction, reconstructed_packet))


if __name__ == "__main__":
    main()
