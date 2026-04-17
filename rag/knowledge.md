Port 21 - FTP
Service: File Transfer Protocol
What to look for: Anonymous login enabled, weak credentials, outdated FTP servers.
Exploitation: Anonymous access, brute force attacks, exploiting vulnerable FTP daemons.
Impact: Unauthorized file access, data exfiltration, upload of malicious files.

Port 22 - SSH
Service: Secure Shell
What to look for: Password authentication enabled, weak passwords, outdated OpenSSH versions.
Exploitation: Brute force, credential stuffing, exploiting known SSH vulnerabilities.
Impact: Full remote shell access, lateral movement.

Port 23 - Telnet
Service: Telnet
What to look for: Telnet enabled (unencrypted protocol), default or weak credentials.
Exploitation: Intercept credentials via sniffing, brute force login.
Impact: Full system compromise due to plaintext authentication.

Port 25 - SMTP
Service: Mail Transfer
What to look for: Open relay configuration, outdated mail servers, user enumeration.
Exploitation: Spam relay abuse, user enumeration, potential RCE in vulnerable services.
Impact: Spam abuse, data leaks, potential server compromise.

Port 53 - DNS
Service: Domain Name System
What to look for: Open recursion, zone transfers allowed.
Exploitation: DNS amplification attacks, data leakage via zone transfer.
Impact: Information disclosure, participation in DDoS.

Port 80 - HTTP
Service: Web Server
What to look for: Outdated server versions, admin panels, directory listing, default credentials.
Exploitation: SQL injection, XSS, file inclusion, remote code execution.
Impact: Data theft, website defacement, full server compromise.

Port 110 - POP3
Service: Mail Retrieval
What to look for: Unencrypted login, weak credentials.
Exploitation: Credential interception, brute force.
Impact: Email account compromise.

Port 139 - NetBIOS
Service: Windows Networking
What to look for: Open shares, weak permissions.
Exploitation: Enumeration, unauthorized file access.
Impact: Data exposure, lateral movement.

Port 143 - IMAP
Service: Mail Retrieval
What to look for: Weak authentication, unencrypted connections.
Exploitation: Credential theft, brute force.
Impact: Email compromise.

Port 443 - HTTPS
Service: Secure Web Server
What to look for: Vulnerable web apps behind TLS, weak SSL/TLS configs, outdated software.
Exploitation: Same as HTTP + SSL downgrade/misconfiguration abuse.
Impact: Data theft, session hijacking, server compromise.

Port 445 - SMB
Service: Windows File Sharing
What to look for: SMBv1 enabled, open shares, weak permissions, outdated Windows systems.
Exploitation: EternalBlue (MS17-010), lateral movement, share abuse.
Impact: Remote code execution, ransomware spread, full network compromise.

Port 3306 - MySQL
Service: Database
What to look for: Open database access, weak passwords, exposed to internet.
Exploitation: Unauthorized login, database dumping, injection attacks.
Impact: Data theft, application compromise.

Port 3389 - RDP
Service: Remote Desktop
What to look for: Exposed RDP, weak or reused credentials.
Exploitation: Brute force, credential stuffing, post-auth exploitation.
Impact: Full system control.

Port 5900 - VNC
Service: Remote Desktop
What to look for: No authentication or weak passwords.
Exploitation: Direct unauthorized access.
Impact: Full desktop control.

Port 8080 - HTTP Alt
Service: Web Server (Alternate)
What to look for: Admin panels, development servers, default credentials.
Exploitation: Same as HTTP, panel takeover.
Impact: Application compromise.

Port 8443 - HTTPS Alt
Service: Secure Web Server
What to look for: Admin dashboards, internal tools exposed.
Exploitation: Same as HTTPS.
Impact: Sensitive system compromise.

General Concept - Vulnerability
A vulnerability is a weakness in a system that can be exploited by an attacker to gain unauthorized access or cause harm.

General Concept - Enumeration
Enumeration is the process of gathering information about a target system, such as open ports, services, and users.

General Concept - Exploitation
Exploitation is the act of using a vulnerability to gain access, execute code, or manipulate a system.

General Concept - Impact
Impact describes the result of a successful attack, such as data theft, service disruption, or full system compromise.