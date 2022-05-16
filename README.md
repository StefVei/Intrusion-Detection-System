# Intrusion-Detection-System

A simple Intrusion Detection System (IDS) that will analyse all the packets from a .pcap with the help of the pcap library and generate alerts based on provided rules given by a .txt file.

The rule format should be the following:

    <src IP address> <src port> <dst IP address> <dst port> “ALERT”

Each rule should be separeted by new line.
End file with a new line.

For example:

    192.168.1.2 55 192.168.1.7 55 “this is a rule for testing”
    192.168.1.2 55 192.168.1.6 55 “another rule for testing”

Uses the standrd std libraries to read to I/O data. Netinet libraries which provide declarations for udp/tcp headers. Also pcap library to fetch packets from a .pcap file.
