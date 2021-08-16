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
from typing import BinaryIO, Optional

import click

import usbmon
import usbmon.addresses
import usbmon.chatter
import usbmon.pcapng
import usbmon.support.hid
from usbmon.support import click_helpers, cp2110, extractors


@click.command()
@click.option(
    "--device-address",
    help="USB address of the CP2110 device to extract chatter of.",
    type=click_helpers.DeviceAddressType(),
)
@click.argument(
    "pcap-file",
    type=click.File(mode="rb"),
    required=True,
)
def main(
    *, device_address: Optional[usbmon.addresses.DeviceAddress], pcap_file: BinaryIO
) -> int:
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    direction: Optional[usbmon.constants.Direction] = None
    reconstructed_packet: bytes = b""

    session = usbmon.pcapng.parse_stream(pcap_file, retag_urbs=True)

    try:
        device_address = extractors.find_device_in_session(
            session,
            device_address,
            {(cp2110.DEFAULT_VENDOR_ID, cp2110.DEFAULT_PRODUCT_ID)},
            device_name="CP2110 adapter",
        )
    except extractors.DeviceSearchError as e:
        raise click.UsageError(str(e)) from e

    for packet in usbmon.support.hid.select(session, device_address=device_address):

        if packet.urb.xfer_type == usbmon.constants.XferType.INTERRUPT:
            if packet.direction != direction and reconstructed_packet:
                assert direction is not None
                print(usbmon.chatter.dump_bytes(direction, reconstructed_packet))
                direction = None
                reconstructed_packet = b""

            direction = packet.urb.direction

            if 0 <= packet.report_id <= 0x3F:
                reconstructed_packet += packet.report_content
            else:
                print(f"Report: {packet.report_id:02x}")
        elif packet.urb.xfer_type == usbmon.constants.XferType.CONTROL:
            print(cp2110.control_command_to_str(packet))

    if direction is None:
        logging.error("No matching CP2110 transaction found.")
        return 1

    print(usbmon.chatter.dump_bytes(direction, reconstructed_packet))
    return 0


if __name__ == "__main__":
    main()
