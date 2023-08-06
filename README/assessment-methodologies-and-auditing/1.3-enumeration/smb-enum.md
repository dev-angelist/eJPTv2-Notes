# SMB Enum

## What is SMB?

**SMB** stands for Server Message Block, and it's a network protocol used for sharing files, printers, and other resources between computers on a network. It enables devices to communicate and collaborate by providing a way to access shared folders, files, and other resources on remote systems. SMB is primarily used in Windows environments, but it's also supported by various other operating systems.

Here are some key features and uses of the SMB protocol:

1. **File and Printer Sharing:** SMB allows computers to share files and printers over a network. Users can access remote files as if they were on their local machine and send print jobs to remote printers.
2. **Access Control:** SMB supports access control and authentication mechanisms, allowing administrators to set permissions for who can access shared resources and what level of access they have.
3. **Named Pipes and Interprocess Communication:** SMB provides named pipes for interprocess communication between programs running on different computers. This facilitates communication and data exchange between applications.
4. **Network Browsing:** SMB enables network browsing, allowing users to discover available computers, shared folders, and resources on the network.
5. **Remote Procedure Calls (RPCs):** SMB can be used for remote procedure calls, which enable a program to execute code on a remote server as if it were local.
6. **Version History:** SMB has gone through several versions, including SMB1, SMB2, and SMB3. Each version introduced improvements in terms of security, performance, and functionality.
7. **Encryption and Security:** Recent versions of SMB (SMB3) incorporate advanced security features such as encryption, signing, and improved authentication mechanisms to enhance the protection of data in transit.
8. **Cross-Platform Support:** While SMB is closely associated with Windows, it is supported on various platforms through different implementations. For example, Samba is an open-source implementation of the SMB/CIFS protocol that allows Unix-like systems to share resources with Windows systems.
9. **CIFS:** Common Internet File System (CIFS) is a more advanced version of SMB that provides additional features and better compatibility with modern network environments.

## SMB Enumeration

**SMB** enumeration refers to the process of extracting information and details from a target system that is running the Server Message Block (SMB) protocol. SMB is a network file sharing protocol that enables applications and systems to communicate and share resources such as files, printers, and other devices across a network. SMB is commonly used in Windows environments for sharing files and resources.

During SMB enumeration, a penetration tester or security analyst attempts to retrieve valuable information from the target system by querying the SMB services. This process involves querying various aspects of the system, including:

1. **Shares:** Enumerating the shared folders and resources on the target system, which can reveal information about directory structures, file names, and access permissions.
2. **Users and Groups:** Extracting information about users and groups present on the system. This information can help identify potential user accounts for further exploitation.
3. **Services:** Identifying active services, applications, and processes running on the target system, which could potentially lead to vulnerabilities or weaknesses.
4. **Session Information:** Gathering details about active user sessions and connections to the target system.
5. **System Information:** Extracting information about the target system's operating system, version, and other configuration details.
6. **Security Policies:** Obtaining information about security policies, such as password policies, that could impact the strength of user credentials.
7. **Error Messages:** Analyzing error messages or responses from the SMB service, which might provide insights into potential misconfigurations or vulnerabilities.

### SMB Ports

* TCP Port 445 - **Microsoft-DS** (Microsoft Directory Services): This is the main port used for SMB traffic on modern networks. It is commonly used for file and printer sharing, as well as other SMB-related operations.
* UDP Port 137 - **NetBIOS Name Service**: This port is used for the NetBIOS Name Resolution service. NetBIOS (Network Basic Input/Output System) is a service that allows computers to communicate within a local network. This port is involved in resolving NetBIOS names to IP addresses.
* UDP Port 138 - **NetBIOS Datagram Service**: This port is used for the NetBIOS Datagram Service. It is involved in the communication of datagrams between devices on the network.
* TCP Port 139 - **NetBIOS Session Service**: In the past, this port was widely used for SMB traffic, but it has become less common in modern networks. It was used for file access operations and resource sharing.

### SMB: Windows Discover & Mount

#### Task List

Windows machine (Server 2012) is provided to you.

Learn to use Nmap to scan the target machine and mount the SMB share of the target machine using the Windows File Explorer as well as using the command prompt.

**Objective**: Discover SMB share and mount it

The following username and password may be used to access the service:

\| Username | Password | | administrator | smbserver\_771 |

<figure><img src="../../../.gitbook/assets/Schermata del 2023-08-06 12-17-42.png" alt=""><figcaption><p>systeminfo</p></figcaption></figure>

This is IP address of the machine with hostname "ATTACKER":

<figure><img src="../../../.gitbook/assets/Schermata del 2023-08-06 12-19-41.png" alt=""><figcaption><p>ifconfig</p></figcaption></figure>

Run Nmap scan against the subnet to discover the target machine’s IP address.

The target subnet is “255.255.240.0” hence we have mentioned CIDR to 20.

<figure><img src="../../../.gitbook/assets/Schermata del 2023-08-06 12-29-05.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/Schermata del 2023-08-06 12-31-55.png" alt=""><figcaption></figcaption></figure>

We see that hosts with IP: 10.2.22.92 and 10.2.25.111 have SMB open ports (139, 445).

We have the credentials to access the target server, we can use GUI mode or terminal.

```bash
net use Z: \\10.2.22.92\C$ smbserver_771 /user:administrator
```

to delete sharing files we use this command:

```bash
 net use * /delete
```

<div align="left">

<figure><img src="../../../.gitbook/assets/smb (1).gif" alt=""><figcaption></figcaption></figure>

</div>

### SMB: Nmap Scripts

###

###

###

###

### SMB: SMBmap

###

###

###

### SMB: Recon

###

###

###

### SMB: Dictionary Attack

###

###

### &#x20;
