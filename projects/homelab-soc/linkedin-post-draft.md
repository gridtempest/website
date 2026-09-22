# LinkedIn post draft

Fill in the bracketed parts once you've actually run the lab and have real numbers/screenshots.
Keep it specific — "I deployed a SIEM" is forgettable, "I caught [X] out of [Y] simulated
attacks and wrote a custom rule to close the gap" is not.

---

I built a home lab SOC to practice detection engineering end to end — deploying a SIEM,
simulating real attacker behaviour, and writing the rules to catch it.

**Setup:**
🔹 Wazuh (SIEM) deployed via Docker
🔹 Windows 10 endpoint instrumented with Sysmon
🔹 Attacks simulated with Atomic Red Team, mapped to MITRE ATT&CK

**What I tested:**
I ran [N] ATT&CK techniques across credential access, persistence, defense evasion, and
lateral movement — including LSASS memory access (T1003.001), scheduled task persistence
(T1053.005), and Defender tampering (T1562.001).

**What I found:**
[X] out of [N] were caught by Wazuh's default rules. For the gaps, I wrote custom detection
rules — like flagging processes that open a memory-read handle to lsass.exe, a classic
credential-dumping signature that isn't always obvious in raw Sysmon telemetry.

**Why this matters:**
This is the loop a SOC analyst / detection engineer runs constantly: understand the
attacker, check if you'd actually see it, close the gap, document it. Full write-up
(architecture, rules, and coverage table) on GitHub: [link]

#cybersecurity #SOC #blueteam #detectionengineering #wazuh #mitreattack

---

**Posting tips:**
- Attach 2-3 screenshots: the agent view, one fired alert detail, and your custom rule XML
  next to the alert it produced. That last pairing is the one that gets people to actually
  read the post.
- Tag it under the same post as a comment linking to your portfolio site, so recruiters who
  click through land somewhere with more context.
