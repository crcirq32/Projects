#!/bin/bash
#rm /home/deck/.wifi_sniffer.db

python3 -m venv ~/wifi-env &&
source ~/wifi-env/bin/activate &&
python3 ./sniffwroguedetect.py -sniff -serve 


python3 webbrowser.get('firefox').open_new_tab('http://127.0.0.1:5000')
