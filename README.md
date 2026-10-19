# Wazuh DCSync Detection (MITRE ATT&CK T1003.006)

A custom Wazuh detection rule that identifies DCSync attacks against Active Directory
in real time, built and validated end-to-end in an isolated lab.

## Summary

DCSync abuses legitimate AD replication (MS-DRSR) to extract credential material —
including the krbtgt hash — from a domain controller without running code on it.
Because it uses a sanctioned protocol, the signal is narrow: a replication-rights
GUID requested by an account that is not a domain controller.

This project detects that signal with a chained Wazuh ruleset and proves it works
against a live attack.

## Detection logic

- **Event source:** Windows Security event 4662 (Directory Service Access),
  enabled via an audit SACL on the domain object.
- **Core match (rule 100100, level 12):** fires when one of the three
  replication-rights GUIDs appears in the event's `properties` field:
  - `DS-Replication-Get-Changes`
  - `DS-Replication-Get-Changes-All`
  - `DS-Replication-Get-Changes-In-Filtered-Set`
- **Noise suppression (rule 100101):** drops matches from machine accounts (`$`),
  since legitimate DC-to-DC replication is performed by computer accounts.

A temporary diagnostic rule (100199) was used during validation to confirm events
were arriving, then removed from the production ruleset.

## Result

Validated by running a live DCSync attack with Impacket `secretsdump`:

- The rule fired on all **10** malicious events (level-12 alerts from DC01).
- It isolated them from the **777** 4662 directory-access events in the same
  window — no false positives.

## Lab environment

Isolated VirtualBox host-only network (192.168.56.0/24):

- **DC01** — Windows Server 2022, domain controller, audit SACL + Sysmon + Wazuh agent
- **Wazuh** — Ubuntu, manager + indexer + dashboard
- **Kali** — attacker, Impacket secretsdump

## Files

- `local_rules.xml` — the deployed detection ruleset
- `Detecting_DCSync_with_Wazuh_Shariff_Mohamud_Goow.pdf` — full lab report (methodology, results, MITRE mapping)

## MITRE ATT&CK

- **Tactic:** TA0006 — Credential Access
- **Technique:** T1003.006 — OS Credential Dumping: DCSync

---

*Built as part of MSc Cyber Security coursework. All offensive tooling was used
exclusively within an isolated, authorised lab.*
