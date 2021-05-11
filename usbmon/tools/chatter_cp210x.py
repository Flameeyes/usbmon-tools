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
import usbmon.addresses
import usbmon.chatter
import usbmon.constants
import usbmon.pcapng
from usbmon.support import cp210x

from . import _utils

CP210X_XFER_TYPES = (
    usbmon.constants.XferType.BULK,
    usbmon.constants.XferType.CONTROL,
)


@click.command()
@click.option(
    "--device-address",
    help="USB address of the CP210x device to extract the chatter of.",
    type=_utils.DeviceAddressType(),
)
@click.option(
    "--all-controls / --no-all-controls",
    "-a",
    default=False,
    help=(
        "If enabled, decode and print all the control requests. Otherwise only the"
        " wire setup control commands will be printed."
    ),
)
@click.argument(
    "pcap-file",
    type=click.File(mode="rb"),
    required=True,
)
def main(
    *,
    device_address: Optional[usbmon.addresses.DeviceAddress],
    all_controls: bool,
    pcap_file: BinaryIO,
) -> int:
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    direction: Optional[usbmon.constants.Direction] = None
    reconstructed_packet: bytes = b""

    session = usbmon.pcapng.parse_stream(pcap_file, retag_urbs=True)

    if not device_address:
        # If there's no --device-address flag on the command line, we can search for
        # the device in the session's descriptors (if it's there at all.)  Note
        # that this is not foolproof, because the CP210x devices can be set to
        # have their own custom VID/PID pairs.
        for descriptor in session.device_descriptors.values():
            if (
                descriptor.vendor_id == cp210x.DEFAULT_VENDOR_ID
                and descriptor.product_id == cp210x.DEFAULT_PRODUCT_ID
                and
                # Sometimes there's a descriptor for a not-fully-initialized
                # device, with no address. Exclude those.
                not descriptor.address.device == 0
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

        if submission.address.device_address != device_address:
            # No need to check second, they will be linked.
            continue

        if submission.xfer_type == usbmon.constants.XferType.BULK:
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
        elif submission.xfer_type == usbmon.constants.XferType.CONTROL:
            try:
                request, argument = cp210x.control_command(submission, callback)
            except ValueError:
                continue
            else:
                if not all_controls and request not in cp210x.WIRE_SETUPS_COMMANDS:
                    continue
                print(cp210x.control_command_to_str(request, argument))

    if direction is None:
        logging.error("No matching CP210x transaction found.")
        return 1

    print(usbmon.chatter.dump_bytes(direction, reconstructed_packet))
    return 0


if __name__ == "__main__":
    main()
