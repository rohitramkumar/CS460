# CS460 Final Project

This project is a simple implementation of a packet capture malware. The malware is written in C and utilizes the libpcap library. 
In order to simulate how this malware could be placed on a victim's machine, Metasploit is used. 

## How To Use

1. [Download Metasploit](https://www.rapid7.com/products/metasploit/download/)

2. Create a Dropbox developer account, create an access token add it to your environment as "DROPBOX_ACCESS_TOKEN". 
   Dropbox is used for storing pcap files that have been created on the victim's machine.
   
3. Run ./build.sh, which creates the malware executable, creates a binary version of an exploit that is placed on the victim's machine and starts a metasploit console instance. The script takes a single argument, which is your IP address. If you are on the same LAN as the victim, then the argument you give should be your private IP and if the victim is outside your network, you should give your public IP. When the exploit binary is executed, a meterpreter shell is started on your machine. More info on meterpreter shells can be found [here  (https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/) The malware was only tested on Linux so it is advisable to only build it on Linux.

4. You must figure out a way to place the binary exploit onto the victim's machine. This project does not implement any Trojan Horse technique on it's own, so any method of placing the exploit on the victim's machine is fine. It is advisable to place the file under the user's directory of which you want to attack.

5. For demonstration purposes, access the victim's machine and execute the exploit. You may have to change permissions on the exploit before executing. On the attacking machine, a meterpreter shell should have started. Upload the malware executable onto the victim's machine using "upload a.out". Once the file is uploaded, start a bash shell on the victim machine with the command "shell". 

6. Now that you have a shell on the victim's machine, you can execute the malware. You may have to change permissions on the malware before executing. Once you execute the malware, watch as packet data starts flowing into your Dropbox folder associated with the project.

