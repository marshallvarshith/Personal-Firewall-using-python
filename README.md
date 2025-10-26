*Personal Firewall Using Python*

A very simple firewall system built using python in local system to understand

* Firewall configuration
* iptables
* network traffic
* firewall rules

This project has helped me understand the above concepts and added a value to be learning path in Elevate Labs

About Project:
This project is to understand how a firewall system works, how the iptables are setup and how the rules set in this iptables are used to BLOCK or ALLOW a protocol to communicate in the system. all the events are logged as .txt file for auditing or recording the events. scapy is a tool used to sniff network traffic from the system.

You'll find the code with some snapshots for your understanding.

Tools Used
* python
* scapy - for sniffing the network
* iptables

commands used - in kali linux

* sudo apt install scapy && python
* sudo python main.py start
       this command starts the firewall and the main python function starts scapy and iptables with logging the events in firewall.txt
* sudo python main.py stop
       this command stops the firewall and flushes the system
