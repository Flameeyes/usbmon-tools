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
# SPDX-License-Identifier: Apache-2.0
"""pcapng file parser for usbmon tooling."""

import pcapng

import usbmon.structs
import usbmon.capture_session


def parse_file(
        path: str, retag_urbs: bool = True) -> usbmon.capture_session.Session:
    """Parse the provided pcang file path into a Session object.

    Args:
      path: The filesystem path to the pcapng file to parse.
      retag_urbs: Whether to re-generate tags for the URBs based on UUIDs.

    Returns:
      A usbmon.capture_session.Session object.
    """
    session = usbmon.capture_session.Session(retag_urbs)
    endianness = None
    with open(path, 'rb') as pcap_file:
        scanner = pcapng.FileScanner(pcap_file)
        for block in scanner:
            if isinstance(block, pcapng.blocks.SectionHeader):
                endianness = block.endianness
            elif isinstance(block, pcapng.blocks.InterfaceDescription):
                if block.link_type != pcapng.constants.link_types.LINKTYPE_USB_LINUX_MMAPPED:
                    raise Exception(
                        f"In file {path}: expected USB capture, "
                        f"found {block.link_type_description}.")
            elif isinstance(block, pcapng.blocks.EnhancedPacket):
                assert block.interface_id == 0
                _, _, payload = block.packet_payload_info
                assert endianness is not None
                session.add(
                    usbmon.structs.Packet.from_bytes(
                        endianness, payload))
    return session
