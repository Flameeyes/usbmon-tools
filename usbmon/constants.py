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

import enum

@enum.unique
class PacketType(enum.Enum):
    SUBMISSION = 'S'
    CALLBACK = 'C'
    ERROR = 'E'


@enum.unique
class XferType(enum.IntEnum):
    ISOCHRONOUS = 0
    INTERRUPT = 1
    CONTROL = 2
    BULK = 3


@enum.unique
class Direction(enum.Enum):
    OUT = 'o'
    IN = 'i'
