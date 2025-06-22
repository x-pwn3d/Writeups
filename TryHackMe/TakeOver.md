
![Capture d'écran 2025-06-22 121010](https://github.com/user-attachments/assets/82759c36-c8b5-40aa-9b70-90f58211b712)

This machine is part of **TryHackMe** and is rated as an **easy**-level Linux challenge. While its rating suggests a straightforward box, **TakeOver** delivers a great hands-on introduction to **SSL certificate inspection**, **subdomain enumeration**, and **host header exploitation**. We'll combine classical recon techniques with a bit of creativity to find hidden infrastructure and extract the final flag.

Let’s dive into the journey and explore the techniques used to crack **TakeOver**!

---

### Recon


We start with a full TCP port scan using `nmap`:
```
nmap 10.10.220.238 -Ss -sV -sC -p- -oN nmapres
```

**Results :**

![Capture d'écran 2025-06-22 123353](https://github.com/user-attachments/assets/8af2d187-b40a-4fed-9146-6bb4ef77df00)

#### Nmap results

- **Port 22 (SSH)** → OpenSSH 8.2p1
    
- **Port 80 (HTTP)** → Apache 2.4.41
    
- **Port 443 (HTTPS)** → Apache 2.4.41
    

Observations:

- HTTP (80) redirects to HTTPS.
    
- The SSL certificate on 443 is **expired**.
    
- The cert metadata shows:
    
    - `CN=futurevera.thm`
        
    - Organization: Futurevera
        
    - Location: Oregon, US
        

At this point, HTTPS appears to be the main attack surface.

---

### Initial enumeration (Gobuster & Dirsearch)

Initial attempts with `gobuster` failed due to an expired SSL certificate :

```
 gobuster dir -u https://futurevera.thm -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt > gobusterres
```
	Error: tls: failed to verify certificate: x509: certificate has expired

To bypass this, we need to add the `-k` flag to ignore certificate validation :

```
gobuster dir -u https://futurevera.thm -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt -k
```

Alternatively, `dirsearch` handles expired SSL certificates by default :

```
dirsearch -u https://futurevera.thm
```

![Capture d'écran 2025-06-22 125359](https://github.com/user-attachments/assets/9304e6ad-56c0-4113-a353-768887075fee)

Relevant findings:

- `/assets/` and `/js/` returned **200 OK** responses, confirming static frontend components.

- Multiple **403 Forbidden** hits on `.ht*` files (e.g., `.htaccess.bak1`, `.htpasswd_test`), which suggests **Apache hardening** but potentially leaked backup files.

- `/server-status` returned a 403, indicating that **mod_status** is enabled but access is restricted.

No sensitive files exposed, but the server is revealing some clues about its structure.


---

### SSL certificate analysis

Accessing `https://futurevera.thm` in the browser triggers a certificate warning due to expiration :

![Capture d'écran 2025-06-22 130932](https://github.com/user-attachments/assets/b4e9959e-6ce5-4e6d-b193-de70b1f760fd)

Using the “View Certificate” feature, we inspect the SSL certificate:

![Capture d'écran 2025-06-22 131220](https://github.com/user-attachments/assets/49ef7420-702d-40c1-aa6a-3dcf7238df79)

![Capture d'écran 2025-06-22 142216](https://github.com/user-attachments/assets/89ff4e3b-d48c-4345-a2f5-345f7d51d5e0)

Unfortunately, this certificate doesn’t reveal anything useful—no alternative names or interesting fields.

We move forward by enumerating virtual hosts, as HTTPS-based subdomains are often mapped via host headers.

---

### Subdomain enumeration 

We use `ffuf` with a wordlist and set the `Host` header manually:

```
ffuf -u https://10.10.220.238 \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt \
  -H "Host: FUZZ.futurevera.thm" -fs 4605
```

The `-fs 4605` flag filters out the default response size to reduce noise.

- `blog.futurevera.thm`
   
- `support.futurevera.thm`

We add both entries to `/etc/hosts` for local resolution.

---
### Inspecting `support.futurevera.thm`

Just like the main domain, visiting `support.futurevera.thm` shows another expired SSL certificate warning.

We again inspect the certificate in the browser.

This time, the certificate reveals a **Subject Alternative Name (SAN)** entry :

![Capture d'écran 2025-06-22 143146](https://github.com/user-attachments/assets/6f5c4773-f784-422f-9c24-7b58133bddcd)

![Capture d'écran 2025-06-22 143618](https://github.com/user-attachments/assets/c9fdfe9b-18e9-48b3-8a23-e2eccdc43dc2)

We now have a **hidden subdomain**!

We'll add this subdomain to our `/etc/hosts` file and investigate it further.

---

### Flag captured 

After identifying the hidden subdomain `{redacted}.support.futurevera.thm` from the SSL certificate of `support.futurevera.thm`, we accessed it using `curl`.

We were immediately redirected to an external URL containing the flag :

```
curl -v http://{redacted}.support.futurevera.thm
```

We receive an immediate HTTP 302 Found response. The response includes a **Location** header that contains the full URL, within which the flag is clearly visible, wrapped in **flag{}**:

![Capture d'écran 2025-06-22 145201](https://github.com/user-attachments/assets/9b00ca44-2a12-41a9-92d6-46145703b32b)

---


**Congratulations!** I hope you found this write-up insightful. This CTF was a solid exercise in **careful SSL inspection**, **subdomain enumeration**, and **host header manipulation**.

**TakeOver** shows how misconfigured certificates or overlooked metadata can expose hidden infrastructure, which can be leveraged to access unintended resources.

Thanks for reading, and happy hacking! 

![Capture d'écran 2025-06-22 145851](https://github.com/user-attachments/assets/9731f135-2c16-4167-88f5-b48c5636d52b)

