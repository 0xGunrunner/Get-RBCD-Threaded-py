# Get-RBCD-Threaded.py

A Python port of [Get-RBCD-Threaded](https://github.com/FatRodzianko/Get-RBCD-Threaded) by FatRodzianko — a tool to discover Resource-Based Constrained Delegation (RBCD) attack paths in Active Directory environments.

Built for offensive security professionals who need this capability natively on Linux/Kali without requiring a Windows host or .NET runtime.

## What It Does

The tool queries Active Directory via LDAP to enumerate all users, groups, and computer objects, then parses the raw DACL (security descriptor) on every computer object to identify principals with dangerous write permissions:

- **GenericAll** — Full control over the computer object
- **GenericWrite** — Write to any attribute, including `msDS-AllowedToActOnBehalfOfOtherIdentity`
- **WriteOwner** — Can take ownership and modify the DACL
- **WriteDacl** — Can modify the DACL to grant further access
- **WriteProperty** on `msDS-AllowedToActOnBehalfOfOtherIdentity` (GUID: `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79`) — Can directly configure RBCD
- **WriteAllProperties** — Unrestricted WriteProperty with no object type constraint

If any non-privileged user, group, or computer has these rights on a computer object, that computer is a potential RBCD attack target.

## Enhancements Over Original

| Feature | Original (C#) | This Port (Python) |
|---|---|---|
| Runtime | .NET 4+ / Windows | Python 3 / Any OS |
| Anonymous/Guest Check | ❌ | ✅ Checks if anonymous/guest can write to computer objects |
| Domain Controller Flagging | ❌ | ✅ Highlights DC targets separately |
| WriteAllProperties Detection | ❌ | ✅ Catches unrestricted WriteProperty |
| Auth Methods | NTLM | NTLM, Simple, Kerberos, Anonymous |
| Output Formats | CSV | CSV + JSON |
| Concurrency | Parallel.ForEach | ThreadPoolExecutor |
| Color Output | ❌ | ✅ Color-coded severity |

The **anonymous/guest access check** was inspired by a real-world scenario where anonymous LDAP access could write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a Domain Controller's computer object — a critical misconfiguration that would allow any unauthenticated attacker to perform RBCD, impersonate a Domain Admin via S4U2Self/S4U2Proxy, and DCSync the entire domain.

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/Get-RBCD-Threaded-py.git
cd Get-RBCD-Threaded-py

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip3 install ldap3
```

### Requirements

- Python 3.8+
- `ldap3` (automatically installs `pyasn1` as a dependency)

## Usage

```
python3 get-rbcd.py -d <DOMAIN> [options]
```

### Required Arguments

| Argument | Description |
|---|---|
| `-d`, `--domain` | Target domain FQDN (e.g., `corp.local`) |

### Optional Arguments

| Argument | Description |
|---|---|
| `-u`, `--username` | Username to authenticate as |
| `-p`, `--password` | Password or NTLM hash (`LM:NT`) |
| `--dc-ip` | IP address of the Domain Controller |
| `-i`, `--insecure` | Use LDAP (port 389) instead of LDAPS (port 636) |
| `-o`, `--output` | Save results to CSV file |
| `--json` | Save results to JSON file |
| `--pwdlastset N` | Filter out computers with `pwdLastSet` older than N days |
| `--anonymous` | Force anonymous LDAP bind |
| `--anon-only` | Only check anonymous/guest write access (skip full scan) |
| `-k`, `--kerberos` | Use Kerberos authentication |
| `--threads N` | Number of threads for ACL processing (default: 10) |
| `--no-anon-check` | Skip the bonus anonymous access check |
| `--no-color` | Disable colored terminal output |

### Examples

**Authenticated scan with NTLM:**

```bash
python3 get-rbcd.py -d corp.local -u jsmith -p 'P@ssw0rd!' --dc-ip 10.10.10.1 -i
```

**Anonymous/null session scan only:**

```bash
python3 get-rbcd.py -d corp.local --dc-ip 10.10.10.1 -i --anon-only
```

**Full scan with CSV and JSON output:**

```bash
python3 get-rbcd.py -d corp.local -u admin -p pass --dc-ip 10.10.10.1 -i -o results.csv --json results.json
```

**Filter stale computer objects (pwdLastSet within 90 days):**

```bash
python3 get-rbcd.py -d corp.local -u admin -p pass --dc-ip 10.10.10.1 -i --pwdlastset 90
```

**Pass-the-hash with NTLM (DOMAIN\user format):**

```bash
python3 get-rbcd.py -d corp.local -u 'CORP\admin' -p 'aad3b435b51404eeaad3b435b51404ee:ntlmhash' --dc-ip 10.10.10.1 -i
```

## Sample Output

```
======================================================================
[*] Phase 1: Enumerating domain objects...
======================================================================

[*] Enumerating users in corp.local...
[+] Found 489 users in corp.local
[*] Enumerating groups in corp.local...
[+] Found 40 non-privileged groups in corp.local
[*] Enumerating computers in corp.local...
[+] Found 15 computers in corp.local
[!] 2 of these are Domain Controllers

[+] Total enumerated SIDs: 544

======================================================================
[*] Phase 2: Analyzing DACLs on 15 computer objects...
======================================================================
[*] Processed 15/15 computer objects...

======================================================================
[*] BONUS: Checking anonymous/guest write access on computer objects...
======================================================================
[+] Anonymous bind successful
[*] Retrieved 15 computer objects via anonymous bind

[!!!] CRITICAL: Found 1 anonymous/guest writable computer objects!
  ANONYMOUS LOGON -> dc01.corp.local [DOMAIN CONTROLLER] (WriteAllProperties)

======================================================================
[+] Found 3 possible RBCD attack paths
======================================================================

[!!!] 2 paths target DOMAIN CONTROLLERS:
----------------------------------------------------------------------
  Source:      Guests (S-1-5-32-546)
  Domain:      corp.local
  Destination: dc01.corp.local [DC]
  DN:          CN=DC01,OU=Domain Controllers,DC=corp,DC=local
  Privilege:   WriteAllProperties
  ------------------------------------------------------------
  Source:      ANONYMOUS LOGON (S-1-5-7)
  Domain:      WELL-KNOWN
  Destination: dc01.corp.local [DC]
  DN:          CN=DC01,OU=Domain Controllers,DC=corp,DC=local
  Privilege:   WriteAllProperties
  ------------------------------------------------------------

[+] 1 paths on regular computer objects:
----------------------------------------------------------------------
  Source:      svc_backup
  Domain:      corp.local
  Destination: fileserver.corp.local
  Privilege:   GenericWrite
  ------------------------------------------------------------

[*] Execution time: 2.17 seconds
```

## How RBCD Works

Resource-Based Constrained Delegation allows a computer to specify which accounts are trusted to delegate to it, controlled by the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the computer object.

If an attacker can write to this attribute, they can:

1. Add a controlled account (e.g., a machine account they created) to the allowed delegation list
2. Use S4U2Self to obtain a service ticket as any user (e.g., Domain Admin) to themselves
3. Use S4U2Proxy to forward that ticket to the target computer
4. Authenticate to the target as the impersonated user

For exploitation, you'll need tools like [impacket](https://github.com/fortra/impacket) (`getST.py`, `secretsdump.py`) or [Rubeus](https://github.com/GhostPack/Rubeus). This tool only identifies the attack paths — it does not perform the attack.

### Recommended Reading

- [Elad Shamir — Wagging the Dog: Abusing Resource-Based Constrained Delegation](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [harmj0y — Another Word on Delegation](https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a)

## How Detection Works

This tool performs standard LDAP queries, which may be difficult to detect. Possible detection methods:

- **Netflow analysis** — Large volumes of LDAP queries to a single host
- **Honeypot accounts** — Computer objects with deliberately weak DACLs; monitor for modifications to `msDS-AllowedToActOnBehalfOfOtherIdentity`

## Credits

- **Original Tool**: [Get-RBCD-Threaded](https://github.com/FatRodzianko/Get-RBCD-Threaded) by [FatRodzianko](https://github.com/FatRodzianko)
- Built with assistance from Claude (Anthropic)

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
