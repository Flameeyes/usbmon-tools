# cython: language_level=3

# SPDX-FileCopyrightText: © 2020 The usbmon-tools Authors
# SPDX-License-Identifier: Apache-2.0

from libc.stdint cimport int8_t, int32_t, int64_t, uint8_t, uint16_t, uint32_t, uint64_t
from libc.errno cimport errno
from posix.ioctl cimport ioctl
from posix.mman cimport mmap, munmap, MAP_FAILED, MAP_PRIVATE, PROT_READ

# These are calculated from the definition provided by the Linux kernel source code, and
# necessary to perform syscalls.
#
# Note that since ioctl(3p) uses `int` rather than `unsigned long`, we use the negative
# value for MFETCH.
#
# Replace these with an include of linux/usb/mon.h once the UAPI header is widely
# available.
MON_IOCQ_RING_SIZE = 37381
MON_IOCX_MFETCH = -1072655865

ctypedef struct mon_fetch_arg:
  uint32_t *offvec
  uint32_t nfetch
  uint32_t nflush


ctypedef struct usbmon_packet:
  uint64_t id
  uint8_t type
  uint8_t xfer_type
  uint8_t epnum
  uint8_t devnum
  uint16_t busnum
  int8_t flag_steu
  int8_t flag_data
  int64_t ts_sec
  int32_t ts_usec
  int32_t status
  uint32_t length
  uint32_t len_cap
  uint8_t setup[8]
  int32_t interval
  int32_t start_frame
  int32_t ndesc


def get_ring_size(fid):
    """Retrieve the usbmon ring buffer size."""

    result = ioctl(fid.fileno(), MON_IOCQ_RING_SIZE)
    if result < 0:
        raise OSError(errno, 'ioctl (MON_IOCQ_RING_SIZE) failed')

    return result


def monitor(fid):
    """Monitor the provided USB controller.

    Args:
      fid: The file object (open for read) for usbmon.

    Yields:
      Pairs of (usbmon_packet, packet_data) as bytes.
    """
    cdef uint32_t nflush = 0
    cdef uint32_t offvec[64]
    cdef mon_fetch_arg fetch
    cdef usbmon_packet *pkt

    map_size = get_ring_size(fid)

    cdef uint8_t *usbmon = <uint8_t*>mmap(
        NULL, map_size, PROT_READ, MAP_PRIVATE, fid.fileno(), 0)
    if usbmon == MAP_FAILED:
        raise OSError(errno, 'mmap failed')

    try:
        while True:
            # This should be optimized, just assume it's a decent value for now.
            fetch.offvec = offvec
            fetch.nfetch = 64
            fetch.nflush = nflush

            res = ioctl(fid.fileno(), MON_IOCX_MFETCH, &fetch)
            if res < 0:
                raise OSError(errno, 'ioctl (MON_IOCX_MFETCH) failed')
            nflush = fetch.nfetch
            for i in range(nflush):
                pkt_offset = offvec[i]
                pkt = <usbmon_packet*>&usbmon[pkt_offset]
                if pkt.type == ord('@'):
                    continue
                data_length = pkt.len_cap
                if data_length > 0:
                    data_start = pkt_offset + 64
                    data_end = pkt_offset + 64 + data_length
                    data = bytes(usbmon[data_start:data_end])
                else:
                    data = None
                yield (bytes(usbmon[pkt_offset:pkt_offset+64]), data)
    finally:
        munmap(usbmon, map_size)
