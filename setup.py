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

from setuptools import find_packages, setup

import setuptools_scm  # Ensure it's present.

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

setup(
    python_requires="~=3.7",
    packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests",]),
    package_data={"": ["py.typed"]},
    install_requires=["construct>=2.9", "hexdump", "python-pcapng>=1.0",],
    tests_require=test_required,
    extras_require={"dev": test_required + ["pre-commit", "setuptools_scm"],},
)
