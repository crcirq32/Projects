### Box Info

OS: Linux 
IP: 10.10.11.105

Part I
Skills learned:
SSH 
nginx 

### Enumeration
nmap -p- -A -oN Horizontall.txt ${IP}
    + 22 SSH
    + 80 http nginx 1.14.0 (Ubuntu)

### Search yields:

https://www.exploit-db.com/exploits/32277.tgz

TODO: look into nginx exploit
