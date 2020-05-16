<!--
SPDX-FileCopyrightText: 2019 The usbmon-tools Authors

SPDX-License-Identifier: Apache-2.0
-->

<p align="center">
<a href="https://travis-ci.com/Flameeyes/usbmon-tools/builds/"><img alt="build status" src="https://travis-ci.com/Flameeyes/usbmon-tools.svg?branch=master"></a>
<a href="https://opensource.org/licenses/Apache-2.0"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-green"></a>
<a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
</p>

# usbmon tools

This repository contains a Python module and some command line tools to work
with Linux [usbmon](https://www.kernel.org/doc/Documentation/usb/usbmon.txt), as
well as Windows [usbpcap](https://desowin.org/usbpcap) captures.

## Tools

In addition to the `usbmon` module, containing the data structures to access USB
captures, this package contains a few scripts in the `tools/` directory, which
can be used to manipulate usbmon captures.

## Development

You can see <CONTRIBUTING.md> for the details on contributing to this project.

To set up a development environment, you can use the following commands:

```shell
$ git clone https://github.com/Flameeyes/usbmon-tools
$ cd usbmon-tools
$ python3 -m venv venv
$ . venv/bin/activate
$ pip install -e .[dev]  # editable installation
$ pre-commit install
```
