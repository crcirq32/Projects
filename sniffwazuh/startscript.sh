#!/bin/bash
#rm /home/deck/.wifi_sniffer.db

python3 -m venv ~/wifi-env &&
source ~/wifi-env/bin/activate &&
python3 ./sniffwroguedetect.py -sniff -serve 


#python3 webbrowser.get('firefox').open_new_tab('http://127.0.0.1:5000')


#iwconfig::
#wlan1     IEEE 802.11  Mode:Monitor  Tx-Power=12 dBm   
#          Retry short limit:7   RTS thr:off   Fragment thr:off
#          Power Management:off
# Replace wlan0 with your actual interface
#sudo ip link set wlan0 down
#sudo iwconfig wlan0 mode monitor
#sudo ip link set wlan0 up
# Verify
#iwconfig wlan0
#
#
#
