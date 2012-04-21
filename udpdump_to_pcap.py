#!/usr/bin/env python
"""
Copyright 2012 by Shoji KUMAGAI
Apache License v2

Read hexdump packet data from STDIN, write pcap format to STDOUT
Usage: udpdump_to_pcap.py < hexdump.txt > out.pcap

Notes
- UDP checksum is NOT calculated.
  Recommend disabling checksum validation in viewer such as Wireshark.

cf) See below about libpcap file format
http://wiki.wireshark.org/Development/LibpcapFileFormat

In pcap file, L2(MAC) is skipped by specifying Link-Layer header to IPv4.
So now support IPv4 only.

  Link-Layer header Types | TCPDUMP/LIBPCAP public repository
  (http://www.tcpdump.org/linktypes.html)
  LINKTYPE_IPV4 228 DLT_IPV4
  Raw IPv4; the packet begins with an IPv4 header.
"""

import sys
import time

from binascii import hexlify, unhexlify
from struct import pack


def debug(message, label=None):
    if label is not None:
        sys.stderr.write('===== %s =====\n' % label)
    sys.stderr.write('%d: %s\n' % (len(message), message))


def print_hex(data, label=None):
    # debug(data, label)
    sys.stdout.write(unhexlify(data))


def uint32_to_native_hex(value):
    """ pack unsigned int as native bytes, and unpack as hex. """
    if sys.byteorder == 'big':
        ORDER_MARK = '>'  # big endian
    else:
        ORDER_MARK = '<'  # little endian
    fmt_uint = ORDER_MARK + 'I'
    return hexlify(pack(fmt_uint, value))


def int_to_hex(value, octets=2):
    """ hex representation as network order with size of ``octets``
    ex) int_to_hex(1)     # => "0001"
        int_to_hex(32, 4) # => "00000020"
    """
    return ('%%0%dx' % (octets * 2)) % value


def ipv4_to_hex(ip_address):
    return ''.join([int_to_hex(int(i), 1) for i in ip_address.split('.')])


def udp_packet(src_port, dst_port, data_length):
    udp_length = 8 + data_length
    src_port = int_to_hex(int(src_port))
    dst_port = int_to_hex(int(dst_port))
    udp_header = ''.join(
        [src_port,                # Source port
         dst_port,                # Destination port
         int_to_hex(udp_length),  # length
         "0000", ])               # checksum (NOT checked)
    return (udp_header, udp_length)


def ipv4_packet(src_ip, dst_ip, udp_length):
    # 20 for ip header without option, 8 for udp header.
    ipv4_length = 20 + udp_length
    src_ip = ipv4_to_hex(src_ip)
    dst_ip = ipv4_to_hex(dst_ip)
    ipv4_header = ''.join(
        ['4',                      # version (IP=4)
         '5',                      # IHL header length
         '00',                     # Type of Service
         int_to_hex(ipv4_length),  # Total length
         'afd4',                   # identification
         '4000',                   # flags (3bits) + Fragment offset (13bits)
         '40',                     # TTL
         '11',                     # Protocol UDP=17=0x11
         '0000',                   # header checksum
         src_ip,                   # Source address
         dst_ip, ])                # Destination address
    return (ipv4_header, ipv4_length)


def pcap_packet(time_stamp, ipv4_length):
    (datetime, usec) = time_stamp.split('.')
    timetuple = time.strptime(datetime, '%Y-%m-%dT%H:%M:%S')
    ts_sec = uint32_to_native_hex(int(time.mktime(timetuple)))
    ts_usec = uint32_to_native_hex(int(usec))

    packet_incl_len = uint32_to_native_hex(ipv4_length)
    return ''.join(
        [ts_sec,              # ts_sec (UNIX time)
         ts_usec,             # ts_usec
         packet_incl_len,     # incl_len (uint32)
         packet_incl_len, ])  # orig_len (uint32)


def packet(time_stamp, src_ip, src_port, dst_ip, dst_port, data):
    (udp_header, udp_length) = udp_packet(src_port, dst_port, len(data) / 2)
    (ipv4_header, ipv4_length) = ipv4_packet(src_ip, dst_ip, udp_length)
    packet_header = pcap_packet(time_stamp, ipv4_length)

    print_hex(packet_header, 'packet_header')
    print_hex(ipv4_header, 'ipv4_header')
    print_hex(udp_header, 'udp_header')
    print_hex(data, 'data')


GLOBAL_HEADER = ''.join(
    ["d4c3b2a1" + "0200" + "0400",  # magic + major + minor
     "00000000" + "00000000",       # thiszone + sigfigs
     "ffff0000",                    # snaplen
     "e4000000", ])                 # LINKTYPE_IPv4(228=e4)


def convert():
    print_hex(GLOBAL_HEADER, 'global_header')
    for line in sys.stdin:
        (time_stamp, hostname, process_id,
         src_ip, src_port, dst_ip, dst_port, data) = line[:-1].split(',')
        packet(time_stamp, src_ip, src_port, dst_ip, dst_port, data)


def main():
    convert()


if __name__ == '__main__':
    main()
