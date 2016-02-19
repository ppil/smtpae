This script accepts a directory containing SMTP flows or a .pcap that it will run through tcpflow to create this directory. It will then parse these flows to extract messages, headers, and attachments.

Usage:
-f <file>, --file <file>
Specify .pcap file to read from.

-s <DIR>, --smtp <DIR>
Specify DIR containing already-extracted SMTP flows. 
(Ignored if .pcap is given)

-d <DIR>, --dir <DIR>
Specify DIR to save contents into. 
(Optional. Default: ./attachments)

-m
Extract message header, text, and HTML.

-q
Quiet, don't send anything to STDOUT.

-h, --help
Wait, what? Help!

