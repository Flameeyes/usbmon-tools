#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: © 2020 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0
"""Minimal implementation of usbmon capturing in Python.
"""

import argparse
import sys

import pcapng

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
        "--pcap-output",
        action="store",
        type=argparse.FileType("wb"),
        help="Path to the file to write the pcapng output to. If not provided, the text output will be provided at stdout.",
    )

    parser.add_argument(
        "usbmon_device",
        action="store",
        type=argparse.FileType("rb"),
        help="Path to the usbmon device to capture from.",
    )

    args = parser.parse_args()

    endianness = ">" if sys.byteorder == "big" else "<"

    if args.pcap_output:
        shb = pcapng.blocks.SectionHeader()
        shb.new_member(
            pcapng.blocks.InterfaceDescription,
            link_type=pcapng.constants.link_types.LINKTYPE_USB_LINUX_MMAPPED,
        )

        pcap_writer = pcapng.FileWriter(args.pcap_output, shb)

        def _packet_callback(packet):
            new_packet = shb.new_member(pcapng.blocks.EnhancedPacket)
            new_packet.interface_id = 0
            new_packet.packet_data = packet.as_bytes()
            pcap_writer.write_block(new_packet)

    else:

        def _packet_callback(packet):
            print(packet)

    for raw_packet, payload in usbmon.linux.monitor(args.usbmon_device):
        packet = UsbmonMmapPacket(endianness, raw_packet, payload)
        if packet.address.startswith(args.addr_prefix):
            _packet_callback(packet)


if __name__ == "__main__":
    main()
