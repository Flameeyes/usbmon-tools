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
# SPDX-License-Identifier: Apache-2.0

import sys

from setuptools import find_packages, setup
from setuptools.command.test import test as TestCommand

test_required = [
    "absl-py",
    "construct>=2.9",
    "hexdump",
    "mypy",
    "pre-commit",
    "pytest-timeout>=1.3.0",
    "pytest>=3.6.0",
    "python-pcapng>=1.0",
]

with open("README.md", "rt") as fh:
    long_description = fh.read()


all_packages = find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests",])


setup(
    name="usbmon-tools",
    version="1",
    description="usbmon processing utilities (for Linux and Windows captures).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Diego Elio Pettenò",
    author_email="flameeyes@flameeyes.com",
    python_requires="~=3.7",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
        "Topic :: System :: Hardware",
    ],
    packages=all_packages,
    package_data={package: ["py.typed"] for package in all_packages},
    install_requires=["construct>=2.9", "hexdump", "python-pcapng>=1.0",],
    tests_require=test_required,
    extras_require={"dev": test_required + ["pre-commit"],},
)
