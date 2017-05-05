# CS460 Final Project

This project is a simple implementation of a packet capture malware. The malware is written in C and utilizes the libpcap library. 
In order to simulate how this malware could be placed on a victim's machine, Metasploit is used. 

## How To Use

1. Create a Dropbox developer account, create an access token add it to your environment as "DROPBOX_ACCESS_TOKEN". 
   [More info here](https://www.google.com/searchq=dropbox+access+token&oq=dropbox+access+token&aqs=chrome.0.0l6.2639j0j4&sourceid=chrome&ie=UTF-8)
   Dropbox is used for storing pcap files that have been created on the victim's machine.
2. Run ./build.sh to create the malware executable. The malware was only tested on Linux so it is advisable to only build it on Linux.
