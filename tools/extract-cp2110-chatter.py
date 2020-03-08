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

import construct

import usbmon
import usbmon.chatter
import usbmon.pcapng
from usbmon.support import cp2110


def print_uart_config_packet(packet):
    uart_config = cp2110.UART_CONFIG_STRUCT.parse(packet.payload)

    if packet.direction == usbmon.constants.Direction.OUT:
        command = "SET UART CONFIG"
    else:
        command = "GET UART CONFIG"

    string_pieces = [
        f"{command}:",
        f"baudrate={uart_config.baudrate}",
        f"parity={uart_config.parity!s}",
        f"flow_control={uart_config.flow_control!s}",
        f"data_bits={uart_config.data_bits}",
        f"stop_bits={uart_config.stop_bits}",
    ]
    print(" ".join(string_pieces))


def main():
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--cp2110_addr",
        action="store",
        type=str,
        help="USB address of the CP2110 device to extract chatter of.",
    )

    parser.add_argument(
        "pcap_file",
        action="store",
        type=str,
        help="Path to the pcapng file with the USB capture.",
    )

    args = parser.parse_args()

    direction: Optional[usbmon.constants.Direction] = None
    reconstructed_packet: bytes = b""

    session = usbmon.pcapng.parse_file(args.pcap_file, retag_urbs=True)

    if not args.cp2110_addr:
        # If there's no cp2110_addr flag on the command line, we can search for
        # the device in the session's descriptors (if it's there at all.)  Note
        # that this is not foolproof, because the CP2110 devices can be set to
        # have their own custom VID/PID pairs.
        for descriptor in session.device_descriptors.values():
            if (
                descriptor.vendor_id == cp2110.DEFAULT_VENDOR_ID
                and descriptor.product_id == cp2110.DEFAULT_PRODUCT_ID
                and
                # Sometimes there's a descriptor for a not-fully-initialized
                # device, with no address. Exclude those.
                not descriptor.address.endswith(".0")
            ):
                args.cp2110_addr = descriptor.address

    if not args.cp2110_addr:
        raise parser.error("Unable to identify a CP2110 device descriptor.")

    for pair in session.in_pairs():
        submission = usbmon.packet.get_submission(pair)
        callback = usbmon.packet.get_callback(pair)

        if not submission or not callback:
            # We don't care which one is missing, we can just get the first
            # packet's tag. If there's an ERROR packet, it'll also behave as we
            # want it to.
            logging.debug("Ignoring singleton packet: %s" % pair[0].tag)
            continue

        if not submission.address.startswith(args.cp2110_addr):
            # No need to check second, they will be linked.
            continue

        if submission.xfer_type == usbmon.constants.XferType.INTERRUPT:
            if submission.direction != direction and reconstructed_packet:
                print(usbmon.chatter.dump_bytes(direction, reconstructed_packet))
                direction = None
                reconstructed_packet = b""

            direction = submission.direction
            if direction == usbmon.constants.Direction.OUT:
                payload = submission.payload
            else:
                payload = callback.payload

            if payload:
                report = payload[0]

                if 0 <= report <= 0x3F:
                    reconstructed_packet += payload[1:]
                else:
                    print("Report: %2x" % report)
        elif submission.xfer_type == usbmon.constants.XferType.CONTROL:
            if submission.payload:
                if submission.payload[0] == cp2110.ReportId.GET_SET_UART_CONFIG.value:
                    print_uart_config_packet(submission)
            if callback.payload:
                if callback.payload[0] == cp2110.ReportId.GET_SET_UART_CONFIG.value:
                    print_uart_config_packet(callback)

    print(usbmon.chatter.dump_bytes(direction, reconstructed_packet))


if __name__ == "__main__":
    main()
