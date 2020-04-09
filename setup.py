# -*- coding: utf-8 -*-
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

from setuptools import find_packages, setup

# Ensure it's present.
import setuptools_scm  # noqa: F401

setup(
    python_requires="~=3.7",
    packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    package_data={"": ["py.typed"]},
    install_requires=["construct>=2.9", "hexdump", "python-pcapng>=1.0"],
    extras_require={
        "dev": [
            "absl-py",
            "mypy",
            "pre-commit",
            "pytest-flake8",
            "pytest-mypy",
            "pytest-timeout>=1.3.0",
            "pytest>=3.6.0",
            "setuptools_scm",
        ],
    },
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
