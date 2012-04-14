================================
 UDP hex dump to pcap converter
================================

This is a small utility script which converts UDP hex dump strings to
pcap format.

See below about libpcap file format.
http://wiki.wireshark.org/Development/LibpcapFileFormat

Usage
=====

Read hexdump packet data from STDIN, write pcap format to STDOUT.

::

   $ ./udpdump_to_pcap.rb < hexdump.txt > out.pcap

Input file should be of comma-separated format,
with column order as follows:

#. Date and time, ISO 8601 with 6 digits microsec,
   ``2011-08-26T12:48:52.904486`` for example
#. Ignored (Maybe hostname comes here)
#. Ignored (Maybe process ID comes here)
#. Source IP address
#. Source UDP port
#. Distination IP address
#. Distination UDP port
#. Hex dump string of UDP payload

See ``sample_input.txt`` for example.

API
===

If your input data is not as above format,
you can use the ``packet`` function directly,
after `require 'udpdump_to_pcap'`.

The arguments are as follows:

#. Output stream
#. Date and time, ISO 8601 with 6 digits microsec,
   ``2011-08-26T12:48:52.904486`` for example
#. Source IP address
#. Source UDP port
#. Distination IP address
#. Distination UDP port
#. Hex dump string of UDP payload

See ``debug_main()`` in ``udpdump_to_pcap.rb`` for example.

Some notes
==========

#. I try this script only at little-endian environments.
   There may be bugs on big-endiean environments or cross environments.

#. UDP checksum is NOT calculated (jus ZEROs).
   If you use viewer software such as Wireshark,
   I recommend disabling checksum validation.

#. Also IP headers are passable hard-coded values.
   Don't take them seriously.

#. Assumes IPv4. Don't work with IPv6.

#. In pcap files, L2(MAC) is skipped by specifying
   Link-Layer Header to IPv4.
   So now support IPv4 only.

Copyright
=========

Copyright 2012 by Shunichi Shinohara.

License
=======

Apache License v2.

See LICENSE file for detail.
