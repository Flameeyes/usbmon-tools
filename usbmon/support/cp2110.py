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
# SPDX-FileCopyrightText: © 2019 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0
"""Support module for Silicon Labs CP2110/4 protocol structures.

Based on the AN434 document by Silicon Labs, available at:

https://www.silabs.com/documents/public/application-notes/AN434-CP2110-4-Interface-Specification.pdf
"""

import dataclasses
import enum

import construct

import usbmon.support.hid

DEFAULT_VENDOR_ID = 0x10C4  # Silicon Labs
DEFAULT_PRODUCT_ID = 0xEA80


@enum.unique
class ReportId(enum.IntEnum):
    UART_ENABLE = 0x41
    GET_VERSION_INFORMATION = 0x46
    GET_SET_UART_CONFIG = 0x50


@enum.unique
class Commands(enum.Enum):
    SET_UART_ENABLE = enum.auto()
    GET_UART_ENABLE = enum.auto()
    GET_VERSION_INFORMATION = enum.auto()
    SET_UART_CONFIG = enum.auto()
    GET_UART_CONFIG = enum.auto()


@enum.unique
class Parity(enum.IntEnum):
    NONE = 0x00
    ODD = 0x01
    EVEN = 0x02
    MARK = 0x03
    SPACE = 0x04


@enum.unique
class FlowControl(enum.IntEnum):
    NO = 0x00
    HARDWARE = 0x01


@enum.unique
class StopBits(enum.IntEnum):
    SHORT = 0x00
    LONG = 0x01


@dataclasses.dataclass
class UartEnable:
    command: Commands
    enabled: bool

    @classmethod
    def from_packet(cls, packet: usbmon.support.hid.HIDPacket):
        if packet.direction == usbmon.constants.Direction.OUT:
            command = Commands.SET_UART_ENABLE
        else:
            command = Commands.GET_UART_ENABLE

        return cls(command, packet.report_content[0] == 0x01)

    def __str__(self) -> str:
        return f"{self.command.name} enabled={self.enabled}"


_GET_VERSION_INFORMATION = construct.Struct(
    device_part_number=construct.Byte,
    device_version=construct.Byte,
)


@dataclasses.dataclass
class VersionInformation:
    command: Commands
    device_part_number: int
    device_version: int

    @classmethod
    def from_packet(cls, packet: usbmon.support.hid.HIDPacket):
        assert packet.direction == usbmon.constants.Direction.IN

        version_information = _GET_VERSION_INFORMATION.parse(packet.report_content)

        return cls(
            Commands.GET_VERSION_INFORMATION,
            device_part_number=version_information.device_part_number,
            device_version=version_information.device_version,
        )

    def __str__(self) -> str:
        if self.device_part_number == 0x0A:
            device = "CP2110"
        else:
            device = f"Unknown ({self.device_part_number:02x})"

        return f"{self.command.name} device_part={device} device_version={self.device_version}"


_UART_CONFIG_STRUCT = construct.Struct(
    baudrate=construct.Int32ub,
    parity=construct.Enum(construct.Byte, Parity),
    flow_control=construct.Enum(construct.Byte, FlowControl),
    raw_data_bits=construct.Byte,
    data_bits=construct.Computed(construct.this.raw_data_bits + 5),
    stop_bits=construct.Enum(construct.Byte, StopBits),
)


@dataclasses.dataclass
class UartConfig:
    command: Commands
    baudrate: int
    parity: Parity
    flow_control: FlowControl
    data_bits: int
    stop_bits: StopBits

    @classmethod
    def from_packet(cls, packet: usbmon.support.hid.HIDPacket):
        uart_config = _UART_CONFIG_STRUCT.parse(packet.report_content)

        if packet.direction == usbmon.constants.Direction.OUT:
            command = Commands.SET_UART_CONFIG
        else:
            command = Commands.GET_UART_CONFIG

        return cls(
            command,
            uart_config.baudrate,
            uart_config.parity,
            uart_config.flow_control,
            uart_config.data_bits,
            uart_config.stop_bits,
        )

    def __str__(self):
        return (
            f"{self.command.name} "
            f"baudrate={self.baudrate} "
            f"parity={self.parity!s} "
            f"flow_control={self.flow_control!s} "
            f"data_bits={self.data_bits} "
            f"stop_bits={self.stop_bits}"
        )


_REPORTS_TO_CLASSES = {
    ReportId.UART_ENABLE: UartEnable,
    ReportId.GET_VERSION_INFORMATION: VersionInformation,
    ReportId.GET_SET_UART_CONFIG: UartConfig,
}


def control_command_to_str(packet: usbmon.support.hid.HIDPacket) -> str:
    try:
        report_id = ReportId(packet.report_id)
        return str(_REPORTS_TO_CLASSES[report_id].from_packet(packet))
    except (ValueError, KeyError):
        return f"REPORT_ID={packet.report_id:02x} PAYLOAD={packet.report_content.hex()}"
