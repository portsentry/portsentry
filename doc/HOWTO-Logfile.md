Whenever a packet is matched to the filter specified in the config file (TCP_PORTS and/or UDP_PORTS) the packet is logged in the following way:

* If portsentry is configured to block the source host, the packet is logged in the BLOCKED_FILE file. The primary use for this log file is internal to portsentry. If another packet is detected from the same source host, the host won't be blocked again.
* If the HISTORY_FILE file is specified in the config file, the packet is logged in this file. This file will thus contain a complete record of all matched incoming packets. It can contain duplicate source hosts. This file will contain a complete historic record of triggered scans
* Finally, portsentry will also output a matched packet in stdout/syslog among all other portsentry logging (such as state of the program).

The format of the HISTORY_LOG and stdout/syslog output is:


Scan from: [<IP>] (<HOSTNAME>) protocol: [<PROTOCOL>] port: [<PORT>] type: [<SCAN TYPE>] IP opts: [<IP OPTIONS>] ignored: [<IGNORED>] triggered: [<TRIGGERED>] noblock: [<NOBLOCK>] blocked: [<BLOCKED>]

Where:

<IP>            is the IP address (IPv4 or IPv6) of the source host
<HOSTNAME>      is the hostname of the source host (if RESOLVED_HOST is set to "1" in the config file)
<PROTOCOL>      is the protocol of the packet (TCP or UDP)
<PORT>          is the destination port number of the packet
<SCAN TYPE>     is the type of scan detected
                "Connect" - A full TCP connect (--connect mode)
                "TCP NULL scan"
                "TCP XMAS scan"
                "TCP FIN scan"
                "TCP SYN/Normal scan"
                "Unknown Type: TCP Packet Flags: ..." - A TCP packet with unknown flags
<IP OPTIONS>    IP options of the packet. can also be "unknown" or "not set" if the options are not obtainable (such as --connect mode or if no options are present)
<IGNORED>       true/false: whether the packet was ignored, according to the IGNORE_FILE. If no IGNORE_FILE is specified, this will always be false
<TRIGGERED>     true/false/unset: Whether the packet triggered a block according to the SCAN_TRIGGER setting.
<NOBLOCK>       true/false/unset: If BLOCK_TCP or BLOCK_UDP was set to 0 and the packet matched, then NOBLOCK will be true
<BLOCKED>       true/false/unset: If BLOCK_TCP or BLOCK_UDP > 0 and the packet matched and the source host was blocked, then BLOCKED will be true. If the source host was already blocked by a previous packets, <BLOCKED> will be true.

In certain situations, the boolean flags <TRIGGERED>, <NOBLOCK>, and <BLOCKED> will be unset. If a flag is unset, a previous rule/flag in the rule engine has caused an abort before the current rule/flag could be set. This is normal behavior and should not be considered an error. The rule engine has been designed to halt processing of packets as soon as possible in order to be as efficient as possible. This is the reason you can't rely on <TRIGGERED>, <NOBLOCK>, and <BLOCKED> to be set to either true or false in all cases.
