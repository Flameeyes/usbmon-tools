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

import enum

import construct

DEFAULT_VENDOR_ID = 0x10C4  # Silicon Labs
DEFAULT_PRODUCT_ID = 0xEA80


@enum.unique
class ReportId(enum.IntEnum):
    GET_SET_UART_CONFIG = 0x50


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


UART_CONFIG_STRUCT = construct.Struct(
    report_id=construct.Const(b"\x50"),
    baudrate=construct.Int32ub,
    parity=construct.Enum(construct.Byte, Parity),
    flow_control=construct.Enum(construct.Byte, FlowControl),
    raw_data_bits=construct.Byte,
    data_bits=construct.Computed(construct.this.raw_data_bits + 5),
    stop_bits=construct.Enum(construct.Byte, StopBits),
)
