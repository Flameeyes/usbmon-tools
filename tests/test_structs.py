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


class TestPacket(absltest.TestCase):

    def test_string_c_packet(self):
        c_packet = usbmon.structs.Packet.from_bytes(
            '<', binascii.a2b_base64(_INTERRUPT_C_BASE64))
        self.assertEqual(
            'dab6b880 1550331849261217 C Ii:1:002:1 0:8 8 = 01000000 00000000',
            str(c_packet))

    def test_string_s_packet(self):
        s_packet = usbmon.structs.Packet.from_bytes(
            '<', binascii.a2b_base64(_INTERRUPT_S_BASE64))
        self.assertEqual(
            'dab6b880 1550331849261367 S Ii:1:002:1 -115:8 8 <',
            str(s_packet))
