# Atomic Red Team test plan

A deliberately small, high-signal set of techniques — enough to cover a range of ATT&CK
tactics (execution, credential access, persistence, defense evasion, lateral movement)
without spending weeks on it. Run these on the **victim Windows VM**, one at a time, and
check the Wazuh dashboard after each before moving to the next — that isolation is what
lets you attribute a specific alert to a specific test.

For each technique, look up the current test numbers in the Atomics index before running
(test content gets added/renumbered over time):
https://github.com/redcanaryco/atomics/blob/master/Indexes/Indexes-Markdown/windows-index.md

## Execution

**T1059.001 — Command and Scripting Interpreter: PowerShell**
Run an obfuscated/encoded PowerShell command. Expected: Wazuh's default Sysmon rules
should flag `EncodedCommand` usage in the process command line (rule group `sysmon_eid1_detections`
or similar — check what actually fires and note the real rule ID in your table).

```powershell
Invoke-AtomicTest T1059.001 -GetPrereqs
Invoke-AtomicTest T1059.001
```

## Credential Access

**T1003.001 — OS Credential Dumping: LSASS Memory**
Simulates a process opening a handle to `lsass.exe` (e.g. via a comsvcs.dll MiniDump
technique — this atomic does NOT require an actual Mimikatz binary). This is one of the
highest-value detections in the whole lab: Sysmon Event ID 10 (ProcessAccess) with
`TargetImage` = lsass.exe and a `GrantedAccess` value associated with memory read is the
classic signature. Your custom rule in `custom-rules/local_rules.xml` targets this.

```powershell
Invoke-AtomicTest T1003.001 -GetPrereqs
Invoke-AtomicTest T1003.001
```

## Persistence

**T1053.005 — Scheduled Task/Job: Scheduled Task**
Creates a scheduled task via `schtasks.exe`. Expected: Sysmon Event ID 1 (process create)
for `schtasks.exe` with `/create` in the command line, or Windows Security Event 4698.

```powershell
Invoke-AtomicTest T1053.005 -GetPrereqs
Invoke-AtomicTest T1053.005
```

**T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys**
Adds a value under `HKCU\...\Run` or `HKLM\...\Run`. Expected: Sysmon Event ID 13
(RegistryEvent) targeting a `Run`/`RunOnce` key path.

```powershell
Invoke-AtomicTest T1547.001 -GetPrereqs
Invoke-AtomicTest T1547.001
```

## Defense Evasion

**T1562.001 — Impair Defenses: Disable or Modify Tools**
Attempts to disable Windows Defender via PowerShell cmdlets or registry. Expected: this
should be one of the loudest alerts in the lab — if it *doesn't* fire, that's worth writing
about too (a detection gap is a legitimate, honest finding for the write-up).

```powershell
Invoke-AtomicTest T1562.001 -GetPrereqs
Invoke-AtomicTest T1562.001
```

## Lateral Movement

**T1021.001 — Remote Services: RDP**
From the attacker VM, RDP into the victim. Expected: Windows Security Event 4624
(Logon Type 10) plus Wazuh's built-in brute-force/authentication rule group if you run
several failed attempts first.

```powershell
# Run from the attacker machine against the victim's IP
mstsc /v:<victim-ip>
```

## After each test

1. In the Wazuh dashboard, go to **Threat Hunting** (or **Alerts**) and filter by the
   approximate timestamp of your test.
2. Note the rule ID and description of whatever fired (or didn't).
3. Screenshot the alert detail view — this is your evidence for the write-up.
4. Fill in the corresponding row in the main README's coverage table.
5. If nothing fired and you believe it should have, that's your cue to write a custom rule
   — which is the actual detection-engineering part of this project, not a failure to hide.
