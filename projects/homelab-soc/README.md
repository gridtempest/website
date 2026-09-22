# Home Lab SOC — Threat Detection & Response

A self-hosted security operations lab built to practice detection engineering: deploy a SIEM,
simulate real adversary behaviour mapped to MITRE ATT&CK, and write custom detection rules
to catch it — then document the whole thing like a SOC analyst would.

This repo is the **project scaffold and runbook**. Screenshots, the filled-in ATT&CK coverage
table, and the write-up get added as you work through it on your own machine.

## Why this project

Most portfolio projects show you can build things. This one shows you can **defend** things —
the skillset a SOC analyst / detection engineer / blue teamer is actually hired for:
standing up a SIEM, understanding attacker tradecraft, writing detections, and triaging alerts.

## Architecture

```
                    ┌─────────────────────────────┐
                    │        Attacker VM           │
                    │  (Kali / Atomic Red Team)    │
                    └───────────────┬───────────────┘
                                    │ simulated attacks
                                    ▼
                    ┌─────────────────────────────┐
                    │        Victim VM(s)          │
                    │  Windows 10/11 + Sysmon      │
                    │  Wazuh Agent installed       │
                    └───────────────┬───────────────┘
                                    │ logs / telemetry
                                    ▼
        ┌───────────────────────────────────────────────────┐
        │                Wazuh Manager (Docker)              │
        │   - Rule engine (default + custom local_rules.xml) │
        │   - Decoders                                       │
        └───────────────────────┬─────────────────────────────┘
                                 ▼
        ┌───────────────────────────────────────────────────┐
        │         Wazuh Indexer + Dashboard (Docker)          │
        │   - Alert storage & search                          │
        │   - Visualisations, MITRE ATT&CK view                │
        └───────────────────────────────────────────────────┘
```

All three Wazuh components run in Docker on your host machine (or a Linux VM). The
victim endpoint is a separate VM with the Wazuh agent + Sysmon installed, so you get
realistic Windows telemetry rather than logs generated on the same box as the SIEM.

## Prerequisites

- Docker + Docker Compose on the SIEM host (4 GB+ RAM free, more is better)
- A hypervisor for VMs: VirtualBox, VMware, Proxmox, or Hyper-V
- One Windows 10/11 VM to act as the monitored endpoint
- ~40 GB free disk across host + VMs

## 1. Deploy Wazuh (SIEM)

Wazuh's official Docker deployment is maintained in their own repo — use it directly rather
than a hand-rolled compose file, so you always get the correct image versions and cert
generation logic.

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.12.0
cd wazuh-docker/single-node

# Generate the certificates the indexer/dashboard/manager use to talk to each other
docker-compose -f generate-indexer-certs.yml run --rm generator

# Bring the stack up
docker-compose up -d
```

Give it ~1 minute for the indexer to finish initialising. Then open the dashboard:

- URL: `https://localhost` (or your host's IP)
- Default login: `admin` / `SecretPassword`

**Before doing anything else**, change the default `admin`, `kibanaserver`, and `wazuh-wui`
passwords (`docker-compose/single-node/config/wazuh_indexer/internal_users.yml` +
Wazuh's `wazuh-passwords-tool`) — even in a home lab, don't leave default creds sitting
on a box that has an agent talking to it. Note this step in your write-up; it's exactly the
kind of hardening a reviewer wants to see you think about unprompted.

## 2. Enroll the victim endpoint

On the Windows VM:

1. Install [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) with a solid
   config (the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) or
   [Olaf Hartong's `sysmon-modular`](https://github.com/olafhartong/sysmon-modular) are the
   standard starting points — they log process creation, network connections, and registry
   changes with sensible noise filtering).
2. Install the Wazuh agent, pointing it at your manager's IP.
3. In `ossec.conf` on the agent, add a `<localfile>` block for the Sysmon Windows Event Log
   channel (`Microsoft-Windows-Sysmon/Operational`) so those events reach the manager.
4. Confirm the agent shows **Active** in the Wazuh dashboard under Agents.

## 3. Simulate attacks with Atomic Red Team

Install [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) on the
Windows VM and run individual technique tests. See [`atomic-tests.md`](./atomic-tests.md)
for the specific technique list and what you should expect to see fire in Wazuh.

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

Invoke-AtomicTest T1003.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 1
```

## 4. Write and tune detections

Wazuh ships strong default rules, but part of the point of this project is writing your
**own**. Start from the examples in [`custom-rules/local_rules.xml`](./custom-rules/local_rules.xml)
— they're deliberately left with comments explaining the logic so you can adapt the XPath/field
matches to whatever your Sysmon decoder actually outputs (check `Alerts > Alert Search` in the
dashboard for a fired default alert first, so you know the real field names before you write a
custom rule against them).

Drop your rules into the manager container's `/var/ossec/etc/rules/local_rules.xml`
(the compose setup mounts a config volume for this — see the wazuh-docker repo's
config docs) and restart the manager service to load them.

## 5. Document what you found

Fill in the table below as you go — this becomes both your GitHub write-up and your
source material for the LinkedIn post (draft in
[`linkedin-post-draft.md`](./linkedin-post-draft.md)).

| ATT&CK Technique | Atomic Test | Detected? | Rule (default/custom) | Notes |
|---|---|---|---|---|
| T1059.001 – PowerShell | T1059.001-1 | ☐ | | |
| T1003.001 – LSASS Memory | T1003.001-1 | ☐ | | |
| T1053.005 – Scheduled Task | T1053.005-1 | ☐ | | |
| T1562.001 – Disable Security Tools | T1562.001-1 | ☐ | | |
| T1547.001 – Registry Run Keys | T1547.001-1 | ☐ | | |
| T1021.001 – RDP | T1021.001-1 | ☐ | | |

Add screenshots to a `screenshots/` folder as you go: the agent dashboard, a fired alert
detail view, and your custom rule's XML side-by-side with the alert it produced are the
three that make a LinkedIn post land.

## Skills this demonstrates

- SIEM deployment & administration (Wazuh, Docker)
- Windows endpoint instrumentation (Sysmon)
- Adversary emulation mapped to MITRE ATT&CK
- Detection engineering — reading raw logs, writing custom correlation rules
- Security documentation / incident write-ups

## Next steps / extensions

- Add a second victim (Linux) and a corresponding attack set (T1548, T1136, etc.)
- Forward Wazuh alerts to Shuffle or TheHive for a lightweight SOAR/case-management layer
- Build a Sigma rule set and convert it to Wazuh rules with `sigma2wazuh` for portability
