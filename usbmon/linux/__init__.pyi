# SPDX-FileCopyrightText: © 2020 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0

from typing import Generator, IO, Tuple

def get_ring_size(fid: IO) -> int: ...

def monitor(fid: IO) -> Generator[Tuple[bytes, bytes], None, None]: ...
