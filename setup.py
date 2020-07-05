# -*- coding: utf-8 -*-
#
# SPDX-FileCopyrightText: © 2019 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0

import sys

from setuptools import Extension, setup

# Ensure it's present.
import setuptools_scm  # noqa: F401
from Cython.Build import cythonize

configured_extensions = []

if sys.platform == "linux":
    configured_extensions.append(Extension("usbmon.linux", ["usbmon/linux/linux.pyx"]))

setup(
    ext_modules=cythonize(configured_extensions),
    entry_points={
        "console_scripts": [
            "usbmon-capture_stats=usbmon.tools.capture_stats:main",
            "usbmon-chatter_cp2110=usbmon.tools.chatter_cp2110:main",
            "usbmon-chatter_hid=usbmon.tools.chatter_hid:main",
            "usbmon_pcapng2base64=usbmon.tools.pcapng2base64:main",
            "usbmon-pcapng2text=usbmon.tools.pcapng2text:main",
        ]
    },
)
