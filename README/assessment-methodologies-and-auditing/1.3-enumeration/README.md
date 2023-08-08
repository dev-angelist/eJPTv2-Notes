# 1.3 Enumeration

## Enumeration

> **⚡ Prerequisites**
>
> * Basic familiarity with Linux and networks concepts
> * Footprinting and Scanning
>
> **📕 Learning Objectives**
>
> * Purpose of service enumeration
> * Enumeration on common and uncommon services and protocols
>
> **🔬 Training list - PentesterAcademy/INE Labs**`subscription required`
>
> * ​[SMB Servers Win Recon](https://attackdefense.com/listing?labtype=windows-recon\&subtype=windows-recon-smb)​
> * ​[SMB Servers Network Recon](https://attackdefense.com/listing?labtype=network-recon\&subtype=recon-smb)​
> * ​[FTP Servers Linux Recon](https://attackdefense.com/listing?labtype=linux-security-recon\&subtype=recon-ftp)​
> * ​[SSH Servers Network Recon](https://attackdefense.com/listing?labtype=network-recon\&subtype=recon-ssh)​
> * ​[IIS Servers Win Recon](https://attackdefense.com/listing?labtype=windows-recon\&subtype=windows-recon-iis)​
> * ​[Webservers Network Recon](https://attackdefense.com/listing?labtype=network-recon\&subtype=recon-webserver)​
> * ​[SQL Databases Linux Recon](https://attackdefense.com/listing?labtype=linux-security-recon\&subtype=linux-security-recon-sqldbs)​
> * ​[SQL Databases Network Recon](https://attackdefense.com/listing?labtype=network-recon\&subtype=recon-sqldb)​
> * ​[MSSQL Servers Win Recon](https://attackdefense.com/listing?labtype=windows-recon\&subtype=windows-recon-mssql)​

## Server & Services

A **server** refers to a specialized computer or software system that provides various resources, services, or functionality to other computers or clients over a network. Servers are designed to handle and respond to requests from client devices, which could be other computers, devices, or even software applications. Servers typically have more robust hardware and software configurations compared to regular desktop or client devices, as they are meant to handle multiple requests, tasks, and connections simultaneously.

Servers come in various types, each designed to perform specific functions:

* **Web Server:** A server that stores and delivers web pages and resources to users' browsers when they request a website.
* **File Server:** A server that stores and manages files, allowing clients to access, store, and share files within a network.
* **Database Server:** A server that manages databases and provides access to stored data for applications or clients.
* **Mail Server:** A server that handles email communication, sending, receiving, and storing emails for users.
* **Application Server:** A server that hosts software applications and provides the necessary computing resources for those applications to run and serve clients.

It has the capability to operate with different operating systems, including Windows Server, Linux Server, and macOS Server.

Servers are required to be accessed remotely by multiple clients, thus necessitating the server to be receptive and open connections on the designated listening port for the service.

However, vulnerabilities or bugs in services with open ports can potentially expose the entire server to attacks from malicious parties.

**Services:** In the context of computing, a service refers to a specific software functionality or capability that is provided by a server or application. Services are designed to perform specific tasks or functions and can be accessed and utilized by clients or other software applications over a network. Services are a way to modularize software functionality, allowing different components or systems to interact and communicate effectively.

Examples of services include:

* **Web Services:** These are services offered over the internet that allow different software applications to communicate and share data using standardized protocols like HTTP.
* **Cloud Services:** Services provided by cloud computing platforms that offer various computing resources like virtual machines, storage, databases, and more.
* **Authentication Service:** A service that handles user authentication, verifying user identities during login processes.
* **Payment Gateway Service:** A service that facilitates online payment transactions securely between customers, merchants, and banks.
* **Messaging Service:** A service that enables real-time messaging and communication between users or applications.

You can review common services reconnaissance here:

* [`SMB`](broken-reference)
* [`FTP`](broken-reference)
* [`SSH`](broken-reference)
* [`HTTP`](broken-reference)
* [`MYSQL`](broken-reference)
* [`SMTP`](broken-reference)

**Enumeration** plays a pivotal role during a penetration test as it involves gathering crucial information about assets within the defined scope. This process aids in identifying potential attack vectors and vulnerabilities that might exist.
