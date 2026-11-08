*************************************************************************
Alex Voneida, CSCI471
Programming Project 3: Traceroute
*************************************************************************

Build:
    make

Run (raw sockets require root):
    sudo ./traceroute -t <destination ip> [-d <debug level>]

    -t  Required. Destination IPv4 address in dotted decimal.
    -d  Optional. Debug level; 5 prints DEBUG messages for each step,
        6 also prints TRACE messages (ICMP checksum).

Behavior:
    Sends up to 30 ICMP Echo Requests starting with a TTL of 2. For each
    probe it prints the address of the router that returned a TTL Exceeded,
    "No response with TTL of X" after 15 seconds of silence, or the
    destination address once an Echo Reply arrives, then exits.

    Responses are matched to the current probe by ICMP identifier (process
    ID) and sequence number (the probe's TTL), so unrelated ICMP traffic and
    late responses to earlier probes are ignored.
