# Disclaimer

## Legal Notice

**Get-RBCD-Threaded.py** is provided for **authorized security testing and educational purposes only**.

By using this tool, you acknowledge and agree to the following:

### Authorized Use Only

This tool is designed for use by security professionals conducting **authorized** penetration testing, red team engagements, and security assessments. You must have **explicit written permission** from the system owner before running this tool against any Active Directory environment.

Unauthorized access to computer systems is illegal in most jurisdictions, including but not limited to:

- **United States**: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **European Union**: Directive 2013/40/EU on attacks against information systems
- **United Kingdom**: Computer Misuse Act 1990
- **Vietnam**: Law on Cybersecurity (No. 24/2018/QH14)

### No Warranty

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

### Assumption of Risk

The user assumes all responsibility and risk for the use of this tool. The author(s) are not responsible for any misuse, damage, or legal consequences resulting from the use of this tool.

### What This Tool Does

By default, this tool **only performs read operations** against Active Directory via standard LDAP queries.

When the `--write-rbcd` or `--clear-rbcd` flags are explicitly used, the tool can **modify** the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on target computer objects. These write operations:

- Are never triggered automatically — they require explicit command-line flags
- Require interactive confirmation before execution
- Only modify a single attribute (`msDS-AllowedToActOnBehalfOfOtherIdentity`)

The tool does not:

- Perform S4U2Self/S4U2Proxy ticket delegation or any Kerberos attacks
- Execute DCSync, PSExec, or any post-exploitation techniques
- Create, delete, or alter any accounts, groups, or other AD objects
- Modify any attribute other than `msDS-AllowedToActOnBehalfOfOtherIdentity`

### Responsible Disclosure

If you discover RBCD misconfigurations in environments you are authorized to test, please report them to the system administrators through appropriate channels and provide remediation guidance.

### Acknowledgment

By downloading, installing, or using this tool, you acknowledge that you have read this disclaimer, understand its contents, and agree to be bound by its terms.
