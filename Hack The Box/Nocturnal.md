
![Capture d'écran 2025-04-20 142731](https://github.com/user-attachments/assets/5114138c-155c-4197-9d6e-72921d685272)

### Introduction

This machine is part of **Hack The Box (HTB)** and is rated as an **easy**-level Linux challenge. It's an excellent opportunity to practice skills in **web enumeration, exploiting file upload vulnerabilities, and privilege escalation**. Throughout this challenge, we will explore a vulnerable web application, uncover misconfigurations and ultimately escalate our privileges to gain root access. Let's dive into the journey and see how we can break into this system!

---

### Initial enumeration

To start, we add the target's IP address to our `/etc/hosts` file and perform a full port scan using **nmap** :

```
nmap nocturnal.htb -sV -sC -p- -oN nmapres
```
![Capture d'écran 2025-04-20 143358](https://github.com/user-attachments/assets/e014240b-d428-4531-8f7f-2c4d9ff5c9e1)

The scan reveals two open ports :

-  `22/tcp` : using `ssh` service
-  `80/tcp` : using `http` service

Next, we can perform a directory enumeration using `gobuster`. I opted for the `raft-medium-words.txt` wordlist from SecLists, which is a solid middle ground for discovering common and semi-obscure paths.

```
gobuster dir -u http://nocturnal.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt > gobusterres
```
![Capture d'écran 2025-04-20 144038](https://github.com/user-attachments/assets/f2dc4721-033c-4590-bb49-8ad8a1596b81)

The scan revealed several interesting directories :

- `/backups` – returned a 301 redirect (potentially interesting for file exposure or backup leaks)
    
- Multiple `/uploads_*` and `/uploads` directories – all returned 403 Forbidden, suggesting restricted access areas that might become useful later on
    
- `/uploadscript` – also 403, could hint at some form of file upload functionality

The `/backups` directory was the most promising lead at this stage due to its accessible status (301), so I decided to investigate it further.

To complement the initial findings from `gobuster`, I ran a second enumeration using `dirsearch`, which is often effective at identifying files and directories with different heuristics and more HTTP feedback.

```
dirsearch -u http://nocturnal.htb
```

![Capture d'écran 2025-04-20 145137](https://github.com/user-attachments/assets/04d133ed-dc6f-475f-b7b5-fbd0698e8aaf)

**Key findings:**

- `/admin.php` and `/dashboard.php` – both returned a `302` redirect to `login.php`, indicating protected admin or user panels.
    
- `/login.php` – accessible (200 OK), confirms there is an authentication mechanism.
    
- `/register.php` – also accessible, which might allow user registration.

Let's check the web page at `http://nocturnal.htb:80` :

![Capture d'écran 2025-04-20 150729](https://github.com/user-attachments/assets/1ad1d5d7-1a8c-44a7-b4ba-30836352242f)

Then we can acess to the `dashboard.php` : 

![Capture d'écran 2025-04-20 151440](https://github.com/user-attachments/assets/34f566fc-5c1e-4220-ad63-baca335acedc)

We can see that we can upload file. Let's see if we can uncover some interesting informations.

First, I tried to upload au `php` file : 

```php
<?php 
	print "test printing my php file"
?>
```

And then I get this error message  :

![Capture d'écran 2025-04-20 152336](https://github.com/user-attachments/assets/76f6d642-d47f-4280-bf6b-3685cc8d6d3b)

It's seems that there is a mechanism that check the file format...

So I tried to bypass this check by using the double extension format by adding `.pdf` extension : 

![Capture d'écran 2025-04-20 152916](https://github.com/user-attachments/assets/0d5493f1-6b64-40df-9686-31df36d9f50e)

We can visit the following link : `http://nocturnal.htb/view.php?username=test&file=test.php.pdf` 

![Capture d'écran 2025-04-20 160409](https://github.com/user-attachments/assets/691c6dcb-e56d-40a6-a166-09c73294f794)

We noticed that it lists all the files I’ve uploaded, which raises the question of whether we can view files uploaded by other users.

For this, we can `FUZZ` on the username parameter : 

```
ffuf -u "http://nocturnal.htb/view.php?username=FUZZ&file=test.php%00.pdf" -w /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt -H "Cookie: PHPSESSID=u92mhca6ftq8d9702thsuacfvi" -fw 1170
```
![Capture d'écran 2025-04-20 161023](https://github.com/user-attachments/assets/1be23c68-37cd-42ce-b689-d309e1c5155a)

The output shows us a list of valid users that we can investigate for any relevant information:

- `admin`: No files available for download.

- `greg`: An `accounts.xlsx` file was found, but I wasn't able to download it...

- `amanda` : There was a `privacy.odt` file available and I was able to download it : 

![Capture d'écran 2025-04-20 161727](https://github.com/user-attachments/assets/b7cc3772-1bd3-4247-9d1b-490c6af3624b)

After downloaded it, we have to unzip it : 

![Capture d'écran 2025-04-20 162223](https://github.com/user-attachments/assets/f9eaf0b0-134a-410c-a06d-da7583a9b882)

If we check the `content.xml` file, we can find the Amanda's password : 

![Capture d'écran 2025-04-20 162404](https://github.com/user-attachments/assets/28e7b90a-af0d-4565-ba66-5e91f1801d18)

And the message tells us that it has been configured for **all their services**. However, it is not possible to connect to SSH with Amanda's password...

Let's see if we can connect to the Amanda's account to the nocturnal website : 

![Capture d'écran 2025-04-20 163121](https://github.com/user-attachments/assets/254adc7b-091e-466a-9650-553a3ad5e983)

The login was successful, and we also noticed that Amanda has access to the **Admin Panel**.
This reflects a **Broken Access Control** (Vertical Privilege Escalation) issue, the application failed to enforce user-level restrictions, letting us access files uploaded by higher-privileged accounts like Amanda.

The **Admin Panel** includes a feature to perform backups, which might be useful for further enumeration : 

![Capture d'écran 2025-04-20 163322](https://github.com/user-attachments/assets/5b633227-e487-4486-9692-a5160faa4587)

So let's try to make a backup : 

![Capture d'écran 2025-04-20 165322](https://github.com/user-attachments/assets/8015b2fd-7501-4a7e-8291-0c5acf6c6edf)

By using Amanda's password, we can confirm that the backup process completes successfully. As part of this process, a file named `nocturnal_database.db` is saved within the generated ZIP archive. . This file is likely to contain valuable information that could be leveraged for further exploitation or privilege escalation.

Looking in the `nocturnal_database.db` file, we can find the password for the admin account : 

![Capture d'écran 2025-04-20 171304](https://github.com/user-attachments/assets/aece2631-d085-4bb0-af3b-d4f31f479868)

So I tried to brute forced it by using `john`. However, I didn't succeed to crack it. Thus, I tried to crack **tobias**'s password *(Obviously, I skipped Amanda because we already have her password)*.

--- 
### Initial foothold

![Capture d'écran 2025-04-20 171908](https://github.com/user-attachments/assets/42b38fc9-994d-4523-a926-e9dfbd8e163e)

And we can see that I've cracked it ! So now we can try to connect to his account by using **SSH** service : 

![Capture d'écran 2025-04-20 172131](https://github.com/user-attachments/assets/648edca4-8df1-499a-b499-9f582fac4af6)

--- 
### User flag 

Now that we have access, our next step is to retrieve the user flag.

![Capture d'écran 2025-04-20 172255](https://github.com/user-attachments/assets/6fdde9bf-3d81-48e4-9c8b-32599b54f51b)

By checking the running services, we found a web service running on **localhost:8080** on the target machine. Since it's only accessible locally, we used **SSH port forwarding** to map it to **localhost:8081** on our machine. This allowed us to access the web application running on port 8080 via **localhost:8081** in our browser.

![Capture d'écran 2025-04-20 175247](https://github.com/user-attachments/assets/d9e1fe48-fd91-4239-9184-a7a87cd3d792)

```
ssh -L 8081:127.0.0.1:8080 tobias@nocturnal.htb
```

The service turned out to be **ISPConfig**, a hosting control panel, which could potentially help us find more ways to escalate our privileges or gain access to other parts of the system.

![Capture d'écran 2025-04-20 175526](https://github.com/user-attachments/assets/51bac4d1-4033-4bf5-b3a5-07052ca9dcc8)

We used Tobias's password with the **admin** username to log into the website :

![Capture d'écran 2025-04-20 181554](https://github.com/user-attachments/assets/e839fdc2-4999-4cca-a789-690e1d9a10d8)

It seems that we cannot find any relevant information on the page itself. However, if we check the **View Page Source**, we can see the version used by the application :

![Capture d'écran 2025-04-20 180907](https://github.com/user-attachments/assets/cb83dd22-858a-441b-baa5-56be25d5b142)

--- 
### CVE-2023-46818 exploit

Searching on the Internet, I found an exploitation of this vulnerability via the following link : [exploit](https://github.com/bipbopbup/CVE-2023-46818-python-exploit)

![Capture d'écran 2025-04-20 182718](https://github.com/user-attachments/assets/6f9ff30e-ed57-4b9e-93c4-b5cf6e89a151)


--- 
### Root flag 

Finally, after successfully exploiting this vulnerability, we are able to read the **root flag** :

![Capture d'écran 2025-04-20 183401](https://github.com/user-attachments/assets/d2b6db73-440b-4ecc-9d92-b35b3469c47c)

--- 

**Congratulations!** This challenge provided an excellent opportunity to practice web enumeration, exploiting file upload vulnerabilities, and privilege escalation techniques. From discovering a Broken Access Control vulnerability in file access to exploiting a vulnerable ISPConfig service, this CTF demonstrated how persistence and methodical testing can lead to root access.

Thanks for reading, and happy hacking!

![Capture d'écran 2025-04-20 185020](https://github.com/user-attachments/assets/688c1210-d874-4039-aeb4-2fbdecc3512e)
