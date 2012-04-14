#!/usr/bin/env ruby

# Copyright 2012 by Shunichi Shinohara
# Apache License v2

# Read hexdump packet data from STDIN, write pcap format to STDOUT
# Usage: udpdump_to_pcap.rb < hexdump.txt > out.pcap

# Notes
# - UDP checksum is NOT calculated.
#   Recommend disabling checksum validation in viewer such as Wireshark.

# cf) See below about libpcap file format
# http://wiki.wireshark.org/Development/LibpcapFileFormat

# In pcap file, L2(MAC) is skipped by specifying Link-Layer Header to IPv4.
# So now support IPv4 only.
#
#   Link-Layer Header Types | TCPDUMP/LIBPCAP public repository
#   (http://www.tcpdump.org/linktypes.html)
#   LINKTYPE_IPV4 228 DLT_IPV4
#   Raw IPv4; the packet begins with an IPv4 header.

require 'time'

def print_hex(output, hex, label=nil)
#   debug(hex, label)
  output.print([hex].pack("H*"))
end

def debug(message, label = nil)
  STDERR.puts("========", label, "=========") if label
  STDERR.puts(message)
end

def uint32_to_native_hex(value)
  # pack unsigned int as native bytes (little endian on x86 box)
  # and unpack as hex
  [value].pack("I*").unpack("H*")[0]
end

# hex representation as network order with size of ``octets``
# ex) int_to_hex(1)     # => "0001"
#     int_to_hex(32, 4) # => "00000020"
def int_to_hex(value, octets = 2)
  sprintf("%0#{octets*2}x", value)
end

def ipv4_to_hex(ip_address)
  ip_address.split(".").map{ |token| int_to_hex(token.to_i, 1)}.join("")
end

def udp_packet(src_port, dst_port, data_length)
  udp_length = 8 + data_length
  src_port = int_to_hex(src_port.to_i)
  dst_port = int_to_hex(dst_port.to_i)
  udp_header =
    src_port +               # Source port
    dst_port +               # Destination port
    int_to_hex(udp_length) + # length
    "0000"                   # checksum (NOT checked)
  [udp_header, udp_length]
end

def ipv4_packet(src_ip, dst_ip, udp_length)
  # 20 for ip header without option, 8 for udp header
  ipv4_length = 20 + udp_length
  src_ip = ipv4_to_hex(src_ip)
  dst_ip = ipv4_to_hex(dst_ip)
  ipv4_header =
    "4" +                      # version (IP=4)
    "5" +                      # IHL header length
    "00" +                     # Type of Service
    int_to_hex(ipv4_length)  + # Total length
    "afd4" +                   # identification
    "4000" +                   # flags (3bits) + Fragment offset (13bits)
    "40" +                     # TTL
    "11" +                     # Protocol UDP=17=0x11
    "0000" +                   # header checksum
    src_ip +                   # Source address
    dst_ip                     # Destination address
  [ipv4_header, ipv4_length]
end  

# In pcap packet, int's are represented as NATIVE byte order.
def pcap_packet(time, ipv4_length)
  datetime, usec = time.split(".")
  ts_sec = uint32_to_native_hex(Time.iso8601(datetime).to_i)
  ts_usec = uint32_to_native_hex(usec.to_i)

  packet_incl_len = uint32_to_native_hex(ipv4_length)
  packet_header =
    ts_sec +          # ts_sec (UNIX time)
    ts_usec +         # ts_usec
    packet_incl_len + # incl_len (uint32)
    packet_incl_len   # orig_len (uint32)
  packet_header
end

def packet(output, time, src_ip, src_port, dst_ip, dst_port, data)
  # data is hex representation, so devided by two
  udp_header, udp_length = udp_packet(src_port, dst_port, data.length/2)
  ipv4_header, ipv4_length = ipv4_packet(src_ip, dst_ip, udp_length)
  packet_header = pcap_packet(time, ipv4_length)

  print_hex(output, packet_header, :packet_header)
  print_hex(output, ipv4_header, :ipv4_header)
  print_hex(output, udp_header, :udp_header)
  print_hex(output, data, :data)
end

GLOBAL_HEADER =
  "d4c3b2a1" + "0200" + "0400" +  # magic + major + minor
  "00000000" + "00000000" +       # thiszone + sigfigs
  "ffff0000" +                    # snaplen
  "e4000000"                      # LINKTYPE_IPV4(228=e4)

def convert(input, output)
  print_hex(output, GLOBAL_HEADER, :global_header)
  input.each_line{ |line|
    time, hostname, process_id,
    src_ip, src_port,
    dst_ip, dst_port, data = line.chomp.split(",")
    packet(output, time,
      src_ip, src_port,
      dst_ip, dst_port,
      data)
  }
end

def main()
  input = STDIN
  output = STDOUT
  convert(input, output)
end

def debug_main()
  output = STDOUT
  print_hex(output, GLOBAL_HEADER, :global_header)
  
  packet(
    output,
    "2011-11-02T12:34:56.123456",
    "192.168.1.100", "12345",
    "192.168.1.1", "1812",
    "30 31 32 33".gsub(/ /, ""))
  
  packet(
    output,
    "2011-11-02T12:34:56.123456",
    "192.168.1.10", "12345",
    "192.168.1.20", "1812",
    (
      "01" +      # code
      "11" +      # identifier
      "00 18" +   # length
      "00" * 16 + # authenticator
      "01044142"  # User-Name
      ).gsub(/ /, ""))

  packet(
    output,
    "2011-08-26T12:48:52.904486",
    "127.0.0.1", "60348",
    "127.0.0.1", "1812",
    "01000030830c2b4e13a1b632228b148c4d43c6ca" +
    "010a66756c6c666c6578" +
    "0212303373615eac7c0b6cf6d5fa8f46a783")
end

if __FILE__ == $0
  main()
end
