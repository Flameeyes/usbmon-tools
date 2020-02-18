# python
#
# Copyright 2020 The usbmon-tools Authors
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
"""Functions to handle descriptor requests."""

import enum
import logging
from typing import Any, Optional

import construct

from usbmon import packet, setup

_USB_DEVICE_DESCRIPTOR = construct.Struct(
    bLength=construct.Const(18, construct.Byte),
    bDescriptorType=construct.Const(0x01, construct.Byte),
    bcdUSB=construct.Int16ub,
    bDeviceClass=construct.Byte,
    bDeviceSubClass=construct.Byte,
    bDeviceProtocol=construct.Byte,
    bMaxPacketSize=construct.Byte,
    idVendor=construct.Int16ul,
    idProduct=construct.Int16ul,
    bcdDevice=construct.Int16ul,
    iManufacturer=construct.Byte,
    iProduct=construct.Byte,
    iSerialNumber=construct.Byte,
    bNumConfigurations=construct.Byte,
)


class DeviceDescriptor:
    def __init__(
        self, address: str, index: int, language_id: int, descriptor: bytes
    ):
        self._address = address
        self._index = index
        self._language_id = language_id
        self._parsed = _USB_DEVICE_DESCRIPTOR.parse(descriptor)

    @property
    def address(self) -> str:
        return self._address

    @property
    def index(self) -> int:
        return self._index

    @property
    def language_id(self) -> int:
        return self._language_id

    @property
    def device_class(self) -> int:
        return self._parsed.bDeviceClass

    @property
    def device_sub_class(self) -> int:
        return self._parsed.bDeviceSubClass

    @property
    def protocol(self) -> int:
        return self._parsed.bDeviceProtocol

    @property
    def max_packet_size(self) -> int:
        return self._parsed.bMaxPacketSize

    @property
    def vendor_id(self) -> int:
        return self._parsed.idVendor

    @property
    def product_id(self) -> int:
        return self._parsed.idProduct

    # TODO: add support for indexed strings.

    @property
    def num_configurations(self) -> int:
        return self._parsed.bNumConfigurations

    def __repr__(self) -> str:
        return (
            f"<usbmon.descriptors.DeviceDescriptor "
            f"{self.vendor_id:04x}:{self.product_id:04x}>"
        )


def search_device_descriptor(
    pair: packet.PacketPair,
) -> Optional[DeviceDescriptor]:
    submit = packet.get_submission(pair)
    callback = packet.get_callback(pair)

    if (
        not callback
        or not submit.setup_packet
        or not submit.setup_packet.recipient == setup.Recipient.DEVICE
        or not submit.setup_packet.standard_request
        == setup.StandardRequest.GET_DESCRIPTOR
        or not callback.payload
    ):
        return None

    # Notably, this is not the same as `submit.address` because it should not
    # include the endpoint address for a device description.
    device_address = f"{submit.busnum}.{submit.devnum}"

    # Descriptor index and type are encoded in the wValue field.
    descriptor_index = submit.setup_packet.value & 0xFF
    descriptor_type = submit.setup_packet.value >> 8

    if descriptor_type != 0x01:
        logging.debug(
            "invalid GET_DESCRIPTION setup packet (%s): %r",
            submit.tag,
            submit.setup_packet,
        )
        return None

    try:
        return DeviceDescriptor(
            device_address,
            descriptor_index,
            submit.setup_packet.index,
            callback.payload,
        )
    except construct.core.StreamError as parse_error:
        logging.debug(
            "invalid device descriptor (%s): %s", submit.tag, parse_error
        )
        return None
