#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: © 2020 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0
"""Minimal implementation of usbmon capturing in Python.
"""

import argparse
import sys

import usbmon.linux
from usbmon.capture.usbmon_mmap import UsbmonMmapPacket


def main():
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--addr_prefix",
        action="store",
        type=str,
        default="",
        help=(
            "Prefix match applied to the device address in text format. "
            "Only packets with source or destination matching this prefix "
            "will be printed out."
        ),
    )

    parser.add_argument(
        "usbmon_device",
        action="store",
        type=str,
        help="Path to the usbmon device to capture from.",
    )

    args = parser.parse_args()

    endianness = ">" if sys.byteorder == "big" else "<"

    with open(args.usbmon_device, "r") as usbmon_dev:
        for raw_packet, payload in usbmon.linux.monitor(usbmon_dev):
            packet = UsbmonMmapPacket(endianness, raw_packet, payload)
            if packet.address.startswith(args.addr_prefix):
                print(packet)


if __name__ == "__main__":
    main()
