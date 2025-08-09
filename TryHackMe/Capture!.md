<img width="129" height="111" alt="Capture d'écran 2025-08-09 211047" src="https://github.com/user-attachments/assets/703d833f-4e94-477a-b32b-961524da1f1e" />
Can you bypass the login form?

This machine, named **Capture!**, is part of **TryHackMe** and rated as an **easy** challenge. It offers a great opportunity to practice fundamental web enumeration and brute force techniques while dealing with common protections like captchas. Throughout this challenge, we’ll explore how to identify valid usernames, automate captcha solving, and brute force passwords to gain access. Let’s dive in and walk through the process of capturing the flag step-by-step!

You can find the full Python script used in this write-up at the following link :

---
### Initial enumeration

We begin with a full port scan in order to see what services are exposed : 

```
nmap capture.thm -sV -sC -Pn -p- -oN nmapres
```

**Results :**

<img width="857" height="424" alt="Capture d'écran 2025-08-09 174640" src="https://github.com/user-attachments/assets/47c5baff-a038-435c-9b7e-9b309b5aea2a" />

The scan reveals two open ports : 

- `22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)`
- `80/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.8.10) http-title: Site doesn't have a title (text/html; charset=utf-8).

Next, we can perform a directory enumeration using `gobuster`: 

<img width="945" height="485" alt="Capture d'écran 2025-08-09 180002" src="https://github.com/user-attachments/assets/514ee641-a24c-41b3-a95d-2f6c6b96f94c" />

The scan reveals that we can access to the **login** and **home** page. 

Then I try to send a HEAD request to the target domain using :

```
curl -I capture.thm
```

This allowed me to inspect the HTTP headers without downloading the full page content.

The server responded with : 

<img width="462" height="161" alt="Capture d'écran 2025-08-09 181237" src="https://github.com/user-attachments/assets/342e80ad-4c49-4cbc-b2a6-4df873f741e4" />

This tells us a few things :

- **302 Found** → The page redirects to another location (temporary redirect).

- **Werkzeug/2.2.2 Python/3.8.10** → The backend is running on Python, most likely using the Flask framework (Werkzeug is Flask’s underlying WSGI server).

- **Location: /login** → Any unauthenticated request is sent to the login page.

At this point, it’s clear we’re dealing with a Python/Flask web application, and authentication might be the first barrier to bypass.

After identifying the `/login` endpoint and noticing that the application explicitly tells us when a username does not exist 

> `Error: The user 'test' does not exist`

<img width="742" height="401" alt="Capture d'écran 2025-08-09 182729" src="https://github.com/user-attachments/assets/d110d730-b628-47d5-964d-495d9889a5b8" />

I decided to use **Hydra** to enumerate valid usernames.

The idea here is simple :

- If the server returns that exact error message → the username is invalid.   
- If that error is missing → we probably found a valid username.
- 
Hydra’s `http-post-form` module requires three parts separated by colons `:`:

1. **Path** to the login form → `/login`
2. **POST data** with placeholders → `username=^USER^&password=^PASS^`
3. **Failure condition** → a string from the server response that means “login failed”

Here’s the command I used :

```
hydra -L /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt -p fakepassword capture.thm http-post-form "/login:username=^USER^&password=^PASS^:Error\: The user" -t 10
```

<img width="939" height="583" alt="Capture d'écran 2025-08-09 183000" src="https://github.com/user-attachments/assets/f3fe09f8-ce70-4725-bdc0-d8b2b30be321" />

After many requests, the application activated a captcha system :

<img width="1905" height="674" alt="Capture d'écran 2025-08-09 185551" src="https://github.com/user-attachments/assets/a4526a0f-2dc2-43a4-9551-aa835960beab" />

At this point, all Hydra requests failed because it can’t solve captchas. The earlier list of usernames likely included **false positives** caused by the captcha page replacing the normal login error.

---

### Weaponization  

To continue the attack, a different approach was needed one that could:

1. Detect when the captcha is present
2. Parse the mathematical challenge (e.g., `418 * 84`)
3. Solve it and submit the result with the login attempt

Using Python with the `requests` and `re` modules, I wrote a script that:

- Submits each username with a dummy password
- If a captcha appears, extracts both numbers using a regex :

```python 
test_captcha = re.search(r"(\d+)\s*([+\-*/])\s*(\d+)", text)
```

This finds any `number (operator) number` pattern, ignoring spaces.

- Computes the product, resends the form including the captcha answer

- Checks if the “user does not exist” message is absent — indicating a possible valid username   

This script avoids the limitations of Hydra and can adapt to the captcha challenge, allowing the enumeration to continue despite the protection. 

---
### Exploitation

During the enumeration, we get output similar to this : 

<img width="665" height="584" alt="Capture d'écran 2025-08-09 193526" src="https://github.com/user-attachments/assets/72b02fec-f14d-4179-9e69-abcfdd4832c6" />

As we can see, the script correctly identifies `<REDACTED>` as a **possible valid username** because the login response for `<REDACTED>` does not contain the “user does not exist” error, unlike all the others.

Thanks to this approach, we bypass the captcha and avoid lockouts, enabling effective username enumeration.

When trying a wrong password for a valid user, the application responds with a different error message :

<img width="1909" height="688" alt="Capture d'écran 2025-08-09 195028" src="https://github.com/user-attachments/assets/ac4a2af1-ceae-4512-a5c3-d2848f1dc966" />

```
Error: Invalid password for user <REDACTED>
```

This distinct response allows us to differentiate between a non-existent user and a wrong password for an existing user.

To leverage this, we need to adjust our script so that once a probable username is found, it switches from enumerating usernames to brute forcing passwords specifically for that user.

The script should still handle the captcha challenge during each login attempt, as the protection remains active throughout the process.

By doing so, we will be able to systematically test passwords against the valid username until the correct password is discovered.

After updating the script we can see the script outputs feedback on each password attempt :

<img width="545" height="215" alt="Capture d'écran 2025-08-09 203539" src="https://github.com/user-attachments/assets/f801bd99-0290-4e5b-84d1-aa2e1aa689a4" />

Here, each `[-] Invalid password` message indicates the password was incorrect. Finally, after trying `<PASSWORD>`, the script detects a successful login :

```sh
############################################################
###  Password FOUND for user '<USERNAME>': '<PASSWORD>'  ###
############################################################
```

---
### Flag 

Once the valid credentials were found, we tested this combination on the login page on the login page : 

<img width="1069" height="277" alt="Capture d'écran 2025-08-09 204137" src="https://github.com/user-attachments/assets/a44887ad-69ad-4b15-94c0-95120f282531" />

Successfully logging in granted us access to the final page where we retrieved the flag, completing the challenge.

---

**Congratulations!** I hope you found this write-up insightful. This CTF challenge was an excellent exercise that emphasized the importance of understanding web application defenses, especially how captcha protections can be bypassed with a bit of clever scripting. By carefully analyzing server responses and automating requests with captcha solving, we were able to enumerate valid usernames and subsequently brute force passwords to gain access.

This challenge was a great reminder that even basic protections like captchas can sometimes be circumvented if you think outside the box and automate effectively. Beyond just manual testing, scripting becomes essential in penetration testing to handle repetitive tasks and dynamic defenses. Ultimately, this methodical approach led us to successfully retrieve the flag.

Thanks for reading, and happy hacking!

<img width="880" height="353" alt="Capture d'écran 2025-08-09 211726" src="https://github.com/user-attachments/assets/aa5c32da-121e-48ba-8733-420185328439" />
