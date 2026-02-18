# sdn_automation | An RPI3-based Software-Defined Network designed with an Automated Intrusion Detection and Blocking System
This project aims to create a software-defined network using an RPi3 as a switch and implementing a Random Forest AI Model into the IDS for automated flood detection and blocking. 

For easy navigation, refer to the following links below:
- [About the Project](#project-description-and-objectives)
- [Network Architecture](#network-architecture)

## Project Description and Objectives
This project aims to do the following:
- Interface a software-defined network using a Raspberry Pi 3 as a switch
- Train an Artificial Intelligence using the Random Forest Regression Model to detect ping floods (ICMP, UDP, and TCP flooding)
- Integrate the model into the Intrusion Detection System to block flooding and malicious connections

## Network Architecture
<img width="577" height="475" alt="Screenshot 2026-02-18 at 2 40 07 PM" src="https://github.com/user-attachments/assets/e5136a62-c1ce-4ecb-a13b-09f6cca44fb7" />

There are two network interfaces present here; the one in green represents a Wi-Fi network connected to the laboratory’s Wi-Fi, and the other is a network interface via Ethernet cables. The blue connection represents the mirrored port that sniffs the packets communicating between the two hosts.

From this architecture, the following physical requirements are needed:
- 1 Raspberry Pi 3
- 3 Ethernet cables
- SD Card (min. storage of 32 GB)
- 2 USB-to-Ethernet Adapters
- A minimum of 5 Computers (1 for the SDN Controller, 1 for the Intrusion Detection System, 2 Host Computers, and 1 Pseudo-attacker Host)



