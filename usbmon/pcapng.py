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


class File:
    """A pcapng file containing an USB capture.
    """

    def __init__(self, path):
        self._path = path
        self.packets = []

    def parse(self):
        with open(self._path, 'rb') as pcap_file:
            scanner = pcapng.FileScanner(pcap_file)
            for block in scanner:
                if isinstance(block, pcapng.blocks.SectionHeader):
                    self.endianness = block.endianness
                elif isinstance(block, pcapng.blocks.InterfaceDescription):
                    if block.link_type != pcapng.constants.link_types.LINKTYPE_USB_LINUX_MMAPPED:
                        raise Exception(
                            f"In file {self._path}: expected USB capture, "
                            f"found {block.link_type_description}.")
                elif isinstance(block, pcapng.blocks.EnhancedPacket):
                    assert block.interface_id == 0
                    self._parse_block(block.packet_payload_info)

    def _parse_block(self, payload):
        self.packets.append(
            usbmon.structs.Packet.from_bytes(
                self.endianness, payload[2]))
