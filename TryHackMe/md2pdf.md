
![Capture d'écran 2025-06-09 125557](https://github.com/user-attachments/assets/1b63f6b9-59e5-4726-8c3e-e9a6f00724e1)

This machine is part of **TryHackMe** and is rated as an **easy**-level Linux challenge. Despite its rating, it offers a solid introduction to **web enumeration, access control bypass, and creative client-side exploitation**. Throughout the box, we’ll identify restricted resources, find clever ways to access them using browser-side vectors like **iframes**, and ultimately retrieve the flag hidden behind internal-only protections.

Let’s dive into the journey and explore the techniques used to crack **MD2PDF**!

---

### Recon

As always, we begin with a full port scan to see what services are exposed :

```
nmap 10.10.82.211 -sS -sV -p- -sC -oN nmapres
```

**Results:**

![Capture d'écran 2025-06-09 124240](https://github.com/user-attachments/assets/30107916-f3f8-4d88-9cd5-48f7c8aac97d)

- `22/tcp open  ssh     OpenSSH 8.2p1` 
- `80/tcp open  rtsp    (actually serving HTTP content)`

Although port 80 is fingerprinted as RTSP, it serves a web application (`MD2PDF`) over HTTP. That will be our entry point.

---

### Gobuster

To discover hidden or restricted paths, we use Gobuster : 

```
gobuster dir -u http://md2pdf.thm -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt
```

**Interesting findings :**

![Capture d'écran 2025-06-09 124334](https://github.com/user-attachments/assets/6966adc0-d379-4368-bf88-28e4e0f59fc5)

- `/admin` – **403 Forbidden**
    
- `/convert` – **405 Method Not Allowed**
    

The `/admin` path is especially interesting it exists but is **forbidden from external access**.

---

### Understanding the access control

When trying to access `/admin`, we are met with :

![Capture d'écran 2025-06-09 124535](https://github.com/user-attachments/assets/5b77d735-2ea7-455b-a969-1309fe7d588e)

> **Forbidden: This page can only be seen internally (localhost:5000)**

This suggests the application is using **host-based access control**, where `/admin` is only served to requests from `localhost`.

That’s a crucial clue. We’re dealing with a **server-side restriction** based on the request origin. This cannot be bypassed directly via the browser... but there may be a client-side trick.

---

### Exploiting client-side markdown rendering

The application allows Markdown input and converts it to PDF via the `/convert` endpoint. This is a possible injection point.

Instead of sending Markdown, we try injecting **raw HTML**. Many Markdown renderers allow inline HTML, especially in less secure configurations.

We inject the following into the Markdown input box :

![Capture d'écran 2025-06-09 124737](https://github.com/user-attachments/assets/e6702454-56e8-41b7-821d-34f7ae2fcd44)

```html
<iframe src="http://localhost:5000/admin"></iframe>
```

The idea is to **embed an internal page** within our rendered content, using an `<iframe>` that targets the `localhost` origin on the server itself. Since the PDF generation likely happens on the backend (as `localhost`), the iframe is fetched **internally**.


---

###  Flag captured


And it worked. The `/admin` page was rendered in the resulting document, **leaking its protected content** including the flag : 

![Capture d'écran 2025-06-09 125130](https://github.com/user-attachments/assets/e18d3968-d881-42ec-9615-4c2bce1deb40)

By injecting the iframe pointing to `http://localhost:5000/admin`, we successfully accessed and read the internal-only content and captured the flag.

This is a textbook example of a **Server-Side Request Forgery (SSRF)**-like behavior triggered via **client-side injection**. It's also a great demonstration of why rendering untrusted Markdown without sanitization can be dangerous.

---

**Congratulations!** I hope you found this write-up insightful. This CTF was a great challenge that demonstrated the value of careful **web enumeration**, identifying **host-based access controls**, and leveraging **client-side vectors to trick the server** into revealing restricted content.

**MD2PDF** highlights how simple misconfigurations can lead to unintended access paths and why sandboxing or sanitizing user input is critical.

Thanks for reading, and happy hacking!

![Capture d'écran 2025-06-09 125507](https://github.com/user-attachments/assets/7165fa68-0f62-4c09-a462-6aab50655988)
