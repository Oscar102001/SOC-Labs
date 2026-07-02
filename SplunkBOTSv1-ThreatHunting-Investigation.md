# Splunk BOTS v1 —  Threat Hunting Investigation

## **Overview**

Threat hunting investigation using the Splunk Boss of the SOC (BOTS) v1 dataset — a well-known industry challenge dataset simulating a real web server compromise and ransomware attack. This lab covers SIEM investigation across IDS alerts, HTTP traffic, Windows event logs, and endpoint telemetry.

**Category:** SIEM / Threat Hunting / Blue Team  
**Tool:** Splunk  
**Dataset:** BOTS v1 (Boss of the SOC)  
**Sourcetypes:** suricata, stream:http, xmlwineventlog  
**Scenario:** Web defacement + Cerber ransomware attack on imreallynotbatman.com

---

## **Investigation Questions**

### **1. Identify the CVE in the Attack**

```json
index=main sourcetype=suricata // filters only IDS alerts generated
| search CVE // finds alerts with a CVE identifier
| stats count by alert.signature

**ANSWER:** CVE 2014-6271
-------------------------------------------------------------------------
/*

Why CVE 2014-6271 because appears many times with alerts like: 
 ET WEB_SERVER Possible CVE-2014-6271 Attempt
 ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers
 That pattern indicates an active exploitation attempt, not just a single alert.

CVE 2014-6271
	Exploits the Bash shell via HTTP headers
	Appears repeatedly, meaning the attacker is actively trying to exploit it.

*/ 
```

![image.png](image.png)

### **2. Identify the CMS**

Determine the Content Management System the web server is running.

```json
index=botsv1 imreallynotbatman.com /*host*/
	sourcetype=stream:http // analyzing http trafic
| stats count by uri 
| sort - count

**ANSWER:** JOOMLA
-------------------------------------------------------------------------

/*

CMS -> Content Management System | A software application used to create, 
manage, and publish digital content—especially websites—without requiring 
coding expertise.

Why Joomla? Most repeated CMS

*/
```

![image.png](image%201.png)

### **3. Identify the Web Scanner**

Determine the commercial vulnerability scanner used for reconnaissance.

```json
index=botsv1 imreallynotbatman.com sourcetype=stream:http 
| stats count by http_user_agent // Every request has a user agent 
| sort - count // shows the most frequent first

**ANSWER:** Acuentix
-------------------------------------------------------------------------
/*

Gecko: This is the browser engine used by Firefox and several other browsers.
Acunetix: This is the Web Vulnerability Scanner

A User-Agent in an HTTP request is a string sent by the client 
(like a web browser, app, or scraper) to identify itself to the server.  
It typically includes details about the browser name and version, operating system,
device type, and rendering engine.  This helps the server deliver appropriate 
content—such as a mobile-optimized page for a smartphone or a desktop version 
for a PC.

*/
```

![image.png](image%202.png)

![image.png](image%203.png)

### **4. Identify the Server IP**

Find the IP address of [imreallynotbatman.co](http://imreallynotbatman.com/)

```json
index=botsv1 sourcetype=stream:http 
site="imreallynotbatman.com" // requested website
| stats count by dest_ip

**ANSWER:** 192.168.250.70
-------------------------------------------------------------------------
```

![image.png](image%204.png)

### **5. Count Unique Brute Force Passwords**

Determine how many unique passwords were attempted in the brute force attack.

```json
index=botsv1 sourcetype=stream:http http_method=POST form_data="*passwd*"
| stats dc(form_data) // distinct count ( only count once for evey unique version)

**ANSWER:** 413
-------------------------------------------------------------------------
/*
**POST** because the hacker is sending multiple user and password attempts.
**form_data** is the field that holds whatever was typed into the website's login box.
**passwd** between asterisks because I only want to see the events where the word 
passw appears anywhere inside the data. This ignores other POST requests
that might be for other things like searching or uploading files.

*/

```

![image.png](image%205.png)

![image.png](image%206.png)

### **6. Identify the Correct Admin Password**

Find the password that successfully authenticated to the CMS.

```json
index=botsv1 sourcetype=stream:http http_method=POST 
uri="/joomla/administrator/index.php" // This targets the exact login page
status=303 

**ANSWER:** batman
-------------------------------------------------------------------------
/*
HTTP status **303**  -> In web traffic, a 303 Redirect after a login attempt almost always means 
			"Login Successful—Redirecting you to the dashboard.

*/
```

![image.png](image%207.png)

![image.png](image%208.png)

### **7. Identify the URI Targeted by Brute Force**

Find which URI received multiple brute force attempts.

```json
index=botsv1 sourcetype=stream:http 
site="imreallynotbatman.com" // requested website
| stats count by dest_ip

**ANSWER:** 192.168.250.70
-------------------------------------------------------------------------

/*
 Brute forcing generates massive traffic to a single login endpoint.

*/
```

![image.png](image%204.png)

1. What was the URI which got multiple brute force attempts?
    
    ```json
    index=botsv1 imreallynotbatman.com sourcetype=stream:http http_method=POST 
    | stats count by uri // Counts all POST requests grouped
    | sort - count
    
    **ANSWER:** /joomla/index.php/component/search/
    -------------------------------------------------------------------------
    /*
    Brute forcing generates a massive amount of traffic to a single login portal.
    
    */
    ```
    
    ![image.png](image%209.png)
    

### **9. Find the MD5 Hash of a Suspicious Process**

```json
index="botsv1" 3791.exe md5  sourcetype=xmlwineventlog

**ANSWER:**
-------------------------------------------------------------------------
/*
MD5 (Message-Digest Algorithm 5) is a widely used cryptographic hash 
function that takes an input of any length and produces a fixed-size 
128-bit (16-byte) hash value, typically represented as a 32-character 
hexadecimal string.

*/
```

![image.png](image%2010.png)

![image.png](image%2011.png)

1. What is the name of the USB key inserted by Bob Smith?
    
    ```json
    index=botsv1 "bob.smith"
    | table _time, host, ComputerName, user
    
    **ANSWER:** MIRANDA
    -------------------------------------------------------------------------
    /*
    
    */
    ```
    
    ![image.png](image%2012.png)
    

### **15. Identify the Ransomware Payload File**

The malware downloaded a file containing the Cerber ransomware cryptor code.

```json
index=botsv1 "3791.exe" sourcetype="stream:http"
| table _time, uri, method

**ANSWER:** mhtr.jpg
-------------------------------------------------------------------------
/*
Attackers often use **Steganography**—hiding malicious code inside a 
harmless-looking file like a .jpg or .png. In this attack, the malware 
3791.exe reached out to a web server and downloaded mhtr.jpg. While it looks
 like an image, it actually contained the encrypted Cerber ransomware payload.

*/
```

## **Additional VPN Log Investigations**

### **16. Country with Most VPN Logins**

```json
index="vpn_logs" 
| iplocation src_ip 
| stats count by Source_Country 
| sort - count

**ANSWER:** United States
-------------------------------------------------------------------------
/*
`iplocation` enriches events with geographic data from IP addresses.

*/
```

![image.png](image%2013.png)

### **17. Most Connected Source IP**

```json

index="vpn_logs"
| stats count by Source_ip 
| sort - count

**ANSWER:** 172.201.60.191
-------------------------------------------------------------------------

```

![image.png](image%2014.png)

### **18. Users with More Than 100 Logins**

```json

index="vpn_logs" 
| stats count by UserName
| where count > 100 
| sort - count

**ANSWER:**  James
-------------------------------------------------------------------------
/*
`where count > 100` filters aggregated results — useful for anomaly detection.
*/
```

![image.png](image%2015.png)

---

- Reconnaissance ─> Acunetix scanner probes imreallynotbatman.com (Joomla CMS)
- Exploitation ─> Shellshock (CVE-2014-6271) attempts via HTTP headers
- Brute Force ─> 413 password attempts against Joomla admin login
- Compromise ─> Successful login with password "batman" (HTTP 303)
- Malware ─> 3791.exe executed on host
- Payload ─> mhtr.jpg (steganography) downloads Cerber ransomware

---

## Key Techniques & Commands Learned

| Command / Concept | Purpose |
| --- | --- |
| `stats dc(field)` | Distinct count of unique values |
| `iplocation` | Geo-enrich IP addresses |
| `where count > N` | Filter aggregated results |
| HTTP 303 analysis | Detect successful logins via redirects |
| Sysmon hash analysis | Correlate process hashes with threat intel |
| Steganography detection | Identify malware hidden in image files |

---

## Blue Team Takeaways

- IDS alerts (Suricata) are the first signal — repeated CVE alerts indicate active exploitation
- Successful logins can be detected via HTTP status codes (303 redirects)
- Process hashes from Sysmon enable threat intelligence correlation
- Steganography is a real evasion technique — image downloads warrant scrutiny
- Combining network (stream:http), IDS (suricata), and endpoint (Sysmon) data
gives full attack visibility — the essence of SOC work