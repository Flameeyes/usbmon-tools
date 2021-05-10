# python
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
"""pcapng file parser for usbmon tooling."""

import io
from typing import BinaryIO, Optional

import pcapng

from usbmon import capture_session, packet
from usbmon.capture import usbmon_mmap, usbpcap

_SUPPORTED_LINKTYPES = (
    pcapng.constants.link_types.LINKTYPE_USB_LINUX_MMAPPED,
    # pcapng.constants.link_types.LINKTYPE_USBPCAP,
    249,
)


def parse_file(path: str, retag_urbs: bool = True) -> capture_session.Session:
    """Parse the provided pcang file path into a Session object.

    Args:
      path: The filesystem path to the pcapng file to parse.
      retag_urbs: Whether to re-generate tags for the URBs based on UUIDs.

    Returns:
      A usbmon.capture_session.Session object.
    """
    with open(path, "rb") as pcap_file:
        return parse_stream(pcap_file, retag_urbs)


def parse_bytes(data: bytes, retag_urbs: bool = True) -> capture_session.Session:
    """Parse the provided bytes array into a Session object.

    Args:
      data: a bytes array that contains the pcapng data to parse.
      retag_urbs: Whether to re-generate tags for the URBs based on UUIDs.

    Returns:
      A usbmon.capture_session.Session object.
    """
    return parse_stream(io.BytesIO(data), retag_urbs)


def parse_stream(stream: BinaryIO, retag_urbs: bool = True) -> capture_session.Session:
    """Parse the provided binary stream into a Session object.

    Args:
      stream: a BinaryIO object that contains the pcapng data to parse.
      retag_urbs: Whether to re-generate tags for the URBs based on UUIDs.

    Returns:
      A usbmon.capture_session.Session object.
    """
    session = capture_session.Session(retag_urbs)
    endianness: Optional[str] = None
    link_type: Optional[int] = None
    parsed_packet: Optional[packet.Packet] = None
    scanner = pcapng.FileScanner(stream)
    for block in scanner:
        if isinstance(block, pcapng.blocks.SectionHeader):
            endianness = block.endianness
        elif isinstance(block, pcapng.blocks.InterfaceDescription):
            if block.link_type not in _SUPPORTED_LINKTYPES:
                raise Exception(
                    f"Expected USB capture, found {block.link_type_description}."
                )
            link_type = block.link_type
        elif isinstance(block, pcapng.blocks.EnhancedPacket):
            assert block.interface_id == 0
            assert endianness is not None
            assert link_type is not None
            if link_type == pcapng.constants.link_types.LINKTYPE_USB_LINUX_MMAPPED:
                parsed_packet = usbmon_mmap.UsbmonMmapPacket(
                    endianness, block.packet_data
                )
            elif link_type == 249:
                try:
                    parsed_packet = usbpcap.UsbpcapPacket(block)
                except usbpcap.UnsupportedCaptureData:
                    pass

            assert parsed_packet is not None
            session.add(parsed_packet)
    return session
