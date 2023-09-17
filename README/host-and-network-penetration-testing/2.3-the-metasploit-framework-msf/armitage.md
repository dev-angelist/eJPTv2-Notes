# Armitage

## ​[Armitage](https://www.offsec.com/metasploit-unleashed/armitage/) - MSF GUI <a href="#armitage-msf-gui" id="armitage-msf-gui"></a>

🗒️ **Armitage** is a graphical user interface (GUI) for the Metasploit Framework, a widely used penetration testing and ethical hacking tool. Armitage provides a user-friendly interface for interacting with Metasploit's powerful features, making it easier for cybersecurity professionals to perform tasks related to network penetration testing, vulnerability assessment, and exploit development.

Some key features of Armitage include:

1. **Visual Interface:** Armitage offers a visual representation of network targets and their vulnerabilities, making it easier for users to understand and manage their testing environment.
2. **Automated Exploitation:** It simplifies the process of finding and exploiting vulnerabilities in target systems by providing automated tools and workflows.
3. **Session Management:** Armitage allows users to manage active sessions and connections to compromised systems, which is crucial for post-exploitation tasks.
4. **Reporting:** Users can generate reports detailing their penetration testing activities and findings.

> 🔬 **Port Scanning & Enumeration With Armitage** - lab by INE
>
> * Victim Machine 1: `10.2.21.86`
> * Victim Machine 2: `10.2.25.150`

```bash
service postgresql start && msfconsole -qdb_status
[*] Connected to msf. Connection type: postgresql. 
# Open a new tab and start Armitagearmitage
# Answer "YES" for the RPC serverArmitage
```

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-f904d06c20ea9b281adbd29080a55da613d7b57e%2Fimage-20230422172326118.png?alt=media" alt=""><figcaption></figcaption></figure>

* **Hosts - Add Hosts**
  * Add victim 1 IP
  * Set the lab as `Victim 1`
* Right-click the target and **Scan** it

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-a53c7667e990970553e6edec9bc36283decae547%2Fimage-20230422172731476.png?alt=media" alt=""><figcaption></figcaption></figure>

* Check **Services**
* Perform an **Nmap Scan** from the **Hosts** menu

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-959d828ae25353531072e17d3e69bf54c444d770%2Fimage-20230422173026361.png?alt=media" alt=""><figcaption></figcaption></figure>

* Check **Services**

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-91b06c94b8705da0674d6fc589193c3844f6f7df%2Fimage-20230422173127590.png?alt=media" alt=""><figcaption></figcaption></figure>

#### Exploitation <a href="#exploitation" id="exploitation"></a>

* Search for `rejetto` and launch the exploit module

![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-9df574e8bb53e8691054af5000a6f3de697520be%2Fimage-20230422173456328.png?alt=media)![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-34b3185a08d1884a6069ad109d1fd193cc0bc3cd%2Fimage-20230422173621170.png?alt=media)

* Try **Dump Hashes** via the `registry method`

Metasploit - post/windows/gather/smart\_hashdump

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-152abcd90ca82912756d14c11cd27bfe89ff39bb%2Fimage-20230422174938564.png?alt=media" alt=""><figcaption></figcaption></figure>

* Saved hashes can be found under the **View - Loot** menu

Administrator:500:aad3b435b51404eeaad3b435b51404ee:5c4d59391f656d5958dab124ffeabc20:::

* **Browse Files**

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-fd40b2a2cd54e84bf911ffb5c84c904aed746348%2Fimage-20230422175355019.png?alt=media" alt=""><figcaption></figcaption></figure>

* **Show Processes**

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-b333383b01ea5e7a005a3b880114e1ccfb64634a%2Fimage-20230422175459608.png?alt=media" alt=""><figcaption></figcaption></figure>

#### Pivoting <a href="#pivoting" id="pivoting"></a>

* Setup **Pivoting**

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-40b0bf170483ebc9b690f70c7602415bcfbc135d%2Fimage-20230422175630076.png?alt=media" alt=""><figcaption></figcaption></figure>

* Add, Enumerate and Exploit `Victim 2`

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-432af299eca1238d2e8a3a221b9de47b0138b6ba%2Fimage-20230422180124226.png?alt=media" alt=""><figcaption></figcaption></figure>

* Port forward the port `80` and use `nmap`

\# In the Meterpreter tabportfwd add -l 1234 -p 80 -r 10.2.25.150# In the msf Console tabdb\_nmap -sV -p 1234 localhost

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-dd4d5d7e4d215d6dccaa98a9420a9dcb74d84251%2Fimage-20230422180508381.png?alt=media" alt=""><figcaption></figcaption></figure>

* Remove the created localhost `127.0.0.1`
* Search for `BadBlue` and use the `badblue_passthru` exploit on `Victim 2`

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-40bbac8f8d285bb67df85ab45158658bf7a3a824%2Fimage-20230422181450963.png?alt=media" alt=""><figcaption></figcaption></figure>

* Migrate to an `x64` from the **Processes** tab
* Dump hashes with the `lsass method`

#### Armitage Kali Linux Install <a href="#armitage-kali-linux-install" id="armitage-kali-linux-install"></a>

sudo apt install armitage -ysudo msfdb initsudo nano /etc/postgresql/15/main/pg\_hba.conf# On line 87 switch “scram-sha-256” to “trust”sudo systemctl enable postgresqlsudo systemctl restart postgresqlsudo armitage
