# -*- coding: utf-8 -*-
#
# SPDX-FileCopyrightText: © 2019 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0

from setuptools import setup

# Ensure it's present.
import setuptools_scm  # noqa: F401

setup(
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
