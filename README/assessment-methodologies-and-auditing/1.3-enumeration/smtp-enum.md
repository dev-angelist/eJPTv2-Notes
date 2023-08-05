# SMTP Enum

## What is SMTP?

**SMTP** stands for Simple Mail Transfer Protocol. It is a widely used network protocol that governs the transmission of email messages over the internet. SMTP is responsible for sending outgoing mail from a sender's email client or server to the recipient's email server.

Key features and aspects of SMTP include:

1. **Message Transfer:** SMTP is primarily designed to transfer email messages from a sender's mail server to the recipient's mail server. It's the protocol that powers the delivery of emails across different domains and email service providers.
2. **Client-Server Communication:** SMTP operates on a client-server model. The sender's email client or server acts as the client, while the recipient's email server acts as the server. The client initiates a connection to the server to transfer the email.
3. **Text-Based Protocol:** SMTP uses a simple text-based protocol for communication. It involves sending commands and receiving responses in a human-readable format.
4. **SMTP Commands:** SMTP commands include:
   * **HELO/EHLO:** Greeting the server and introducing the client.
   * **MAIL FROM:** Specifying the sender's email address.
   * **RCPT TO:** Specifying the recipient's email address.
   * **DATA:** Initiating the transfer of the email message content.
   * **QUIT:** Ending the session.
5. **SMTP Relay:** SMTP relay refers to the process of forwarding an email from one mail server to another to ensure proper delivery across different domains.
6. **Mail Queues:** SMTP servers often use mail queues to manage the flow of incoming and outgoing emails. Messages are placed in queues for processing and delivery.
7. **SMTP Authentication:** To prevent unauthorized use of email servers for sending spam, SMTP servers often require authentication before allowing email transmission.
8. **Port:** SMTP typically uses port 25 for communication. However, modern email servers often use encrypted connections via STARTTLS or SSL/TLS on port 587 (Submission) to enhance security.

## SMTP Enumeration

**SMTP** enumeration refers to the process of systematically gathering information about email addresses, user accounts, and mail server configuration using the Simple Mail Transfer Protocol (SMTP). It involves querying an SMTP server to collect details about its users, the domain's email structure, and potential vulnerabilities. SMTP enumeration is often conducted as part of security assessments, penetration testing, or ethical hacking to identify points of entry, misconfigurations, or other weaknesses that attackers could exploit.

During SMTP enumeration, a tester or analyst might perform the following activities:

1. **Username Enumeration:** Trying different usernames or email addresses along with the VRFY or RCPT TO commands to determine whether a specific email address is valid on the target SMTP server. A successful response indicates a valid user or email address.
2. **User Enumeration via Error Messages:** Analyzing error messages returned by the SMTP server when attempting to send emails to non-existent addresses. Some servers might provide specific error codes indicating invalid users.
3. **Email Address Structure:** Collecting information about the domain's email address structure (e.g., "[username@domain.com](mailto:username@domain.com)") to understand naming conventions and potentially predict valid email addresses.
4. **Mail Server Configuration:** Gathering information about the mail server software and version in use through the SMTP banner or other response headers. This can help in identifying potential vulnerabilities associated with that specific software version.
5. **Relay Testing:** Checking whether the SMTP server allows unauthorized email relaying, which could be exploited for sending spam or conducting phishing attacks.
6. **Mail Server Response Analysis:** Analyzing responses from the server to gain insights into the server's behavior, message formatting, and potential security settings.
7. **Domain Enumeration:** Identifying other domains or mail servers associated with the target organization by sending requests to the DNS (Domain Name System) server.
8. **SMTP User Enumeration Tools:** Using specialized tools or scripts that automate the process of sending commands to the SMTP server to enumerate users or email addresses.

