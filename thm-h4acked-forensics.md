# Tryhackme - h4acked

## **Overview**

An incident investigation split into two phases: forensic analysis of a packet
capture to reconstruct how an attacker compromised a machine over FTP, then a
recovery/hardening phase. The focus is packet analysis and understanding the
attacker's full post-exploitation activity.

**Category:** Network Forensics / Blue Team / Incident Response  
**Target:** TryHackMe "h4acked"  
**Tools:** Wireshark  
**Focus:** FTP attack reconstruction, backdoor identification, rootkit awareness

---

### **What service was the attacker targeting?**

Traffic was concentrated on **port 21 → FTP**.

![image.png](image.png)

### **What username was used?**

We can see that the attacker tries to use the username jenny.

![image.png](image%201.png)

### **What was the password?**

We can see that there is a successful login here with the **password123**

![image.png](image%202.png)

### **FTP working directory after login?**

**Answer: /var/www/html**

When opening the packet 401 we can find all the info including the user and password.

![image.png](image%203.png)

![image.png](image%204.png)

### **The uploaded backdoor filename?**

**Answer: shell.php**

A client issues the **STOR** command after successfully establishing a data connection when it wishes to upload a copy of a local file to the server.

The **STOR** (STORE) command is a fundamental **FTP protocol command** used to upload files to a server.  When a client issues this command, the server accepts data transferred via the established data connection and stores it as a file at the server site. 

![image.png](image%205.png)

![image.png](image%206.png)

### The backdoor can be downloaded from a specific URL, as it is located inside the uploaded file. What is the full URL?

http://pentestmonkey.net/tools/php-reverse-shell

![image.png](image%207.png)

![image.png](image%208.png)

### Which command did the attacker manually execute after getting a reverse shell?

whoami

What is the computer's hostname?

 **wir3**

![image.png](image%209.png)

### Which command did the attacker execute to spawn a new TTY shell?

python3 -c ‘import pty; pty.spawn(“/bin/bash”)’

![image.png](image%2010.png)

### Which command was executed to gain a root shell?

sudo su

![image.png](image%2011.png)

### The attacker downloaded something from GitHub. What is the name of the GitHub project?

**Reptile**

**Reptile** is a Linux kernel mode rootkit with detection evasion, persistence, and a backdoor.

![image.png](image%2012.png)

### The project can be used to install a stealthy backdoor on the system. It can be very hard to detect. What is this type of backdoor called?

Rootkit

**Rootkit** malware is a collection of software designed to give malicious actors control of a computer network or application.

![image.png](image%2013.png)

## Phase 2 — Recovery & Hardening (Concept)

After identifying a kernel-mode rootkit, the correct response is not  simplecleanup — a compromised host with a rootkit should be treated as fully untrusted:- Isolate the host from the network- Preserve evidence (the PCAP, affected files) before remediation- Rebuild from known-good media rather than attempting in-place removal- Rotate all credentials exposed on the host (jenny, root, keys)- Patch the initial vector (weak FTP credentials) and disable plaintext FTP---## Attack Chain Reconstructed

FTP brute/weak creds (jenny:password123) → upload shell.php to /var/www/html → trigger PHP reverse shell → TTY upgrade → sudo su (root) → git clone Reptile (LKM rootkit) → persistence