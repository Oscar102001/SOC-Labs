# Splunk Assignment — VPN Log Analysis with SPL

## **Overview**

Hands-on Splunk exercise analyzing VPN log data using SPL (Search Processing
Language). This lab covers essential SIEM queries for filtering, aggregating,
and visualizing security event data — core skills for SOC analysts.

**Category:** SIEM / Blue Team  
**Tool:** Splunk  
**Language:**  SPL (Search Processing Language)  
**Dataset:** VPN logs (index="vpn_logs")

---

## **Query Reference**

### **1. Count All VPN Login Events**

**Result:** 2,862 events

![image.png](image.png)

### **2. Find Events for a Specific User**

Filter all events related to the user "Sam Browne".

![image.png](image%201.png)

### **3. Find VPN Sessions from a Specific IP**

IP 151.164.65.80

![image.png](image%202.png)

### **4. List All Unique Usernames**

![image.png](image%203.png)

### **5. Count Sessions Built vs. Torn Down**

```json
// CORRECT ANSWER
action_build OR torndown
```

![image.png](image%204.png)

### **6. Top 5 Most Frequent Source IPs**

```json
// top search for the number of the most something depending in the query
// head search for the 5 logs do not sort 
```

![image.png](image%205.png)

### **7. Top 5 Users with Most VPN Logins**

![image.png](image%206.png)

### **8. State with Most VPN Sessions**

![image.png](image%207.png)

### **9. Countries Generating Most VPN Sessions**

![image.png](image%208.png)

### **10. VPN Connections Using Port 443**

![image.png](image%209.png)

### **11. Time Chart of VPN Logins (Dashboard)**

![image.png](image%2010.png)

![image.png](image%2011.png)

![image.png](image%2012.png)

### **12. VPN Connections Built Per Hour**

![image.png](image%2013.png)

![image.png](image%2014.png)

### **13. Duration of Each VPN Session Per User**

![image.png](image%2015.png)

### **14. Successfully Built Sessions Using TCP**

![image.png](image%2016.png)

### **15. Events Built OR Torn Down (Exclude Others)**

![image.png](image%2017.png)

![image.png](image%2018.png)

### **16. VPN Connections from Ohio OR Florida**

![image.png](image%2019.png)

![image.png](image%2020.png)

## **Key Takeaways**

PL is the foundation of threat hunting and investigation in Splunk
- `stats`, `sort`, and `head` are the most common commands for building reports
- `timechart` is essential for visualizing trends and building dashboards
- Field-based filtering (UserName, Source_ip, action) enables precise  investigations
- These queries map directly to real SOC tasks: identifying top talkers, tracking  user activity, and detecting anomalies in VPN traffic

---

## **Real-World SOC Applications**

- **Anomaly detection:** Unusual login counts or source IPs may indicate brute force
- **Geo-analysis:** VPN connections from unexpected countries can flag compromised accounts
- **Session tracking:** Correlating built/teardown events helps reconstruct user activity
- **Dashboards:** Real-time monitoring of VPN activity for the SOC team