# FTP Enum

## What is FTP?

**FTP** stands for File Transfer Protocol. It is a standard network protocol used for transferring files between a client computer and a server on a computer network. FTP is widely used for sharing files over the internet and within local networks. It provides a way to upload, download, and manage files on a remote server.

Here are some key features and aspects of FTP:

1. **Two-Part System:** FTP involves two main components: the FTP client and the FTP server. The client is the software used by a user to connect to and interact with the server.
2. **Authentication:** FTP servers typically require authentication, which involves providing a username and password to access the server. However, the standard FTP protocol sends login credentials in plain text, making it less secure. For enhanced security, protocols like FTPS (FTP Secure) and SFTP (SSH File Transfer Protocol) use encryption to protect sensitive data.
3. **Commands and Responses:** FTP communication follows a command-response model. The client sends commands to the server to request specific actions, such as listing directories or uploading files. The server responds with messages indicating the success or failure of the requested actions.
4. **Modes of Transfer:** FTP supports two modes of data transfer: active mode and passive mode. In active mode, the server initiates the data connection to the client, while in passive mode, the client initiates the data connection to the server.
5. **Directory Listing:** FTP allows clients to view the contents of directories on the server, making it easy to navigate and select files for transfer.
6. **Binary and ASCII Mode:** FTP provides two transfer modes: binary and ASCII. Binary mode is used for transferring non-text files (e.g., images, executables), while ASCII mode is used for text-based files to ensure proper line-ending conversions.
7. **Anonymous FTP:** Some FTP servers support anonymous logins, allowing users to access public directories without requiring a username and password. This is often used for sharing public files, such as software updates or documentation.
8. **Extensions and Features:** FTP has been extended over the years with various features like resuming interrupted transfers, managing file permissions, and creating directories.
9. **Limitations and Security Concerns:** Traditional FTP lacks encryption, which can expose sensitive data and credentials to potential eavesdropping. This has led to the development of more secure alternatives like FTPS and SFTP.

## FTP Enumeration

