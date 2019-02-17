"""Tests for usbmon.structs."""

import binascii

from absl.testing import absltest


import usbmon.structs


_INTERRUPT_C_BASE64 = (
    'gLi22gAAAABDAYECAQAtAMkvaFwAAAAAYfwDAAAAAAAIAAAACAAAAAAAAAAAAAAACAAAAAAAAA'
    'AEAgAAAAAAAAEAAAAAAAAA')
_INTERRUPT_S_BASE64 = (
    'gLi22gAAAABTAYECAQAtPMkvaFwAAAAA9/wDAI3///8IAAAAAAAAAAAAAAAAAAAACAAAAAAAAA'
    'AEAgAAAAAAAA==')

_CONTROL_S_BASE64 = (
    'AKrN2gAAAABTAoABAQAAPMUvaFwAAAAAuNIBAI3///8oAAAAAAAAAIAGAAEAACgAAAAAAAAAAA'
    'AAAgAAAAAAAA==')
_CONTROL_C_BASE64 = (
    'AKrN2gAAAABDAoABAQAtAMUvaFwAAAAAX9MBAAAAAAASAAAAEgAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAgAAAAAAABIBAAIJAAFAax0CABQEAwIBAQ==')


class TestPacket(absltest.TestCase):

    def test_string_interrupt_c(self):
        packet = usbmon.structs.Packet.from_bytes(
            '<', binascii.a2b_base64(_INTERRUPT_C_BASE64))
        self.assertEqual(
            'dab6b880 1550331849261217 C Ii:1:002:1 0:8 8 = 01000000 00000000',
            str(packet))

    def test_string_interrupt_s(self):
        packet = usbmon.structs.Packet.from_bytes(
            '<', binascii.a2b_base64(_INTERRUPT_S_BASE64))
        self.assertEqual(
            'dab6b880 1550331849261367 S Ii:1:002:1 -115:8 8 <',
            str(packet))

    def test_string_control_s(self):
        packet = usbmon.structs.Packet.from_bytes(
            '<', binascii.a2b_base64(_CONTROL_S_BASE64))
        self.assertEqual(
            'dacdaa00 1550331845119480 S Ci:1:001:0 s 80 06 0100 0000 0028 40 <',
            str(packet))

    def test_string_control_c(self):
        packet = usbmon.structs.Packet.from_bytes(
            '<', binascii.a2b_base64(_CONTROL_C_BASE64))
        self.assertEqual(
            'dacdaa00 1550331845119647 C Ci:1:001:0 0 18 = 12010002 09000140 6b1d0200 14040302 0101',
            str(packet))
