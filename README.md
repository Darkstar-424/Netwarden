# NetWarden

NetWarden is a defensive network scanner and vulnerability assessment tool for Windows. It finds the devices on your network, works out which services they run, and checks them for known weaknesses. It then explains, in plain English, what to fix first and how.

It ships as **one portable `NetWarden.exe`**: no installer and no admin rights. It has a **Simple** mode for beginners and an **Advanced** mode for professionals, in light and dark themes.

> ## Responsible use
> Only scan networks and devices that you own or that you have **written permission** to assess. Scanning networks you don't control may be illegal where you are.
>
> NetWarden helps you stay on the right side of that line:
> - Every scope needs an explicit "I am authorized" confirmation.
> - Public internet addresses need a second confirmation.
> - Every scan, authorization and status change goes into an append-only audit log.
>
> NetWarden is **non-intrusive by design**. It never exploits anything, never guesses passwords and never delivers payloads. Its checks only read versions and settings, or send harmless read-only requests. The two checks that connect anonymously are off unless you turn them on.

---

## Contents
1. [Get NetWarden.exe](#1-get-netwardenexe)
2. [First run (Simple mode)](#2-first-run-simple-mode)
3. [Advanced mode](#3-advanced-mode)
4. [Command line and scheduled scans](#4-command-line-and-scheduled-scans)
5. [CVE database](#5-cve-database)
6. [What NetWarden checks](#6-what-netwarden-checks)
7. [Data, privacy and portability](#7-data-privacy-and-portability)
8. [Npcap note](#8-npcap-note)
9. [Solution layout](#9-solution-layout)
10. [Extending NetWarden](#10-extending-netwarden)
11. [Building and testing](#11-building-and-testing)
12. [Known limitations](#12-known-limitations)
13. [Third-party components](#13-third-party-components)

---

## 1. Get NetWarden.exe

The source builds into a single self-contained `NetWarden.exe` (about 100 MB, .NET runtime included). Pick either option.

**Option A: build on any Windows 10/11 PC (about 3 minutes)**
1. Install the free .NET 8 SDK: `winget install Microsoft.DotNet.SDK.8`, or download it from https://dotnet.microsoft.com/download/dotnet/8.0.
2. Unzip the source and double-click **`build.cmd`**, or run it from a terminal. It runs the tests, then publishes the app.
3. Your exe is at **`dist\NetWarden.exe`**. Copy it anywhere (a USB stick or a tools share) and run it.

Run `build.cmd notest` to skip the tests.

**Option B: let GitHub build it**

Push the folder to a GitHub repository. The included workflow (`.github/workflows/build.yml`) builds and tests on `windows-latest`. You can then download `NetWarden-win-x64` from the run's **Artifacts**. That download also contains a sample PDF report.

**Windows SmartScreen.** The exe isn't code-signed, so Windows may show "Windows protected your PC" the first time. Choose **More info → Run anyway**. To remove the warning for your organisation, sign the exe with your code-signing certificate:

```
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 dist\NetWarden.exe
```

## 2. First run (Simple mode)

1. **What to check.** NetWarden suggests the network your PC is on (for example `192.168.1.0/24`). You can also type addresses yourself: one per line, as `10.0.0.5`, `10.0.0.0/24`, `10.0.0.1-50` or `nas.local`.
   - Add devices to **Skip** if they shouldn't be touched (old printers, medical or factory equipment).
   - Tick **"I own these devices or am authorized to scan them"**. Who ticked it, and when, is recorded.
2. **Run a check.** Pick a goal:
   - *Find devices on my network*
   - *Quick health check*
   - *Deep check*
   - *Check my web servers*
   - *Check my Windows network*

   Press **Start scan**. You can pause, resume or cancel at any time. Results appear live.
3. **Fix these first.** The home page groups issues by the action that fixes them, worst first. For example, "Turn off SMBv1 on 2 devices" covers two findings. **Show me how** gives numbered steps.
4. **Issues.** Every issue explains what it means, shows the evidence and lists the fix. Mark each one as:
   - **Fixed.** It re-opens automatically if a later scan finds it again.
   - **Accepted risk**, with a reason.
   - **False positive**, with a reason.
5. **Reports.** Save a PDF (executive summary plus technical detail), an HTML page, a CSV spreadsheet or JSON.

Every technical term has a **?** tooltip with a plain-English explanation. Shortcuts:
- **Ctrl+N** starts a new scan.
- **Ctrl+1** to **Ctrl+4** jump between pages.

## 3. Advanced mode

Switch with **Simple | Advanced** in the top bar. Everything stays in the same place; Advanced adds:
- **A full profile editor:**
  - port lists (`top100`, `top1000`, `all`, `22,80,8000-8100`)
  - speed presets (Gentle, Polite, Normal, Fast) plus your own limits on concurrency, timeout and rate
  - ICMP and TCP ping, or treating every address as up
  - UDP probes, TLS inspection, OS detection
  - safe probes on or off
  - anonymous-login checks (opt-in)

  Save, import and export profiles as JSON.
- **Findings query bar**, for example `severity>=high kev:true host:10.0.0.5 port:445 cve:2023 status:accepted conf:confirmed smb`.
- **Sortable grids, raw protocol facts and evidence**, CVSS vectors and CPE names.
- **Compare scans**: new devices, newly opened ports, and new or resolved findings.
- **Network map**: devices grouped by /24 subnet and coloured by their worst open issue.
- **Copy as CLI command** for any scan setup.

**Confidence labels on findings**

| Label | Meaning |
|---|---|
| **Confirmed** | A safe probe or direct observation proved it, e.g. SMBv1 accepted, TLS 1.0 negotiated, Redis answered without a password. |
| **Configuration** | A setting read directly from the service, e.g. "SMB signing not required". |
| **Potential** | The software version matches a CVE. Vendors (Ubuntu, Synology…) sometimes back-port fixes without changing the version number, so check the vendor advisory. |

## 4. Command line and scheduled scans

The same exe runs headless when given arguments:

```
NetWarden.exe scan --scope "Head office" --profile "Standard" --report C:\Reports\office.pdf [--notify]
NetWarden.exe import-nmap --file results.xml --report results.html
NetWarden.exe update-cve [--api-key <NVD key>]
NetWarden.exe report --out latest.html [--scan <id>]
NetWarden.exe list-scopes | list-profiles | help
```

**Exit codes:**
- `0`: OK
- `1`: critical or actively exploited findings are open
- `2`: usage error
- `3`: scan failed

Scopes can only be created and authorized in the GUI, so a script can't scan anything that hasn't been authorized. Command-line output is also saved to `NetWarden-data\logs\cli-*.log`.

**Scheduled scans** (Settings → Scheduled scans):
- They create per-user Windows Task Scheduler tasks in a `NetWarden` folder; no admin rights needed.
- They run while you're signed in.
- If you move `NetWarden.exe`, re-create the schedule.

**Notifications** (Settings → Notifications):
- **Channels:** email over SMTP, and/or a Microsoft Teams **Workflows** webhook ("Post to a channel when a webhook request is received").
- **When:** a scan finds *new* issues at or above the severity you choose. Actively exploited (KEV) issues always notify.
- **Secrets:** the SMTP password and webhook URL are stored in **Windows Credential Manager**, not in the settings file.

## 5. CVE database

Version matching uses a local database built from:
- the **NVD API 2.0** (`services.nvd.nist.gov`)
- the **CISA Known Exploited Vulnerabilities** catalog (`www.cisa.gov`)

Go to **Settings → Vulnerability database → Download / update now**.

**How long it takes**
- **First download:** about 15–30 minutes without a key.
- **With a key:** a free NVD API key (link in Settings) makes it roughly 10× faster.
- **Later updates:** only fetch changes and take seconds.

**Integrity**
- Feeds are downloaded only over HTTPS, with normal certificate validation.
- Each response is checked for the expected format before anything is stored. Neither NVD nor CISA publishes signatures, so this format check is the best available.

**Air-gapped networks**
1. Use **Export bundle** on a connected PC.
2. Copy the zip across.
3. Use **Import bundle** on the offline PC.

Bundles carry a SHA-256 manifest that is verified before import.

## 6. What NetWarden checks

**Discovery**
- ICMP echo
- TCP "ping" on common ports (a refused connection also counts as alive)
- ARP on the local subnet via the Windows `SendARP` API
- Reverse DNS and NetBIOS names
- MAC vendor lookup

**Services**
- TCP connect scan with "polite" defaults
- UDP probes: DNS, NTP, NetBIOS, SNMPv3 engine discovery (no community strings), IPMI/RMCP, SSDP
- Banner and version detection: HTTP(S), SSH (including algorithm lists), FTP, SMTP (including STARTTLS/AUTH), Telnet, SMB 1/2/3, RDP (NLA negotiation), MySQL/MariaDB, MSSQL (TDS PRELOGIN), PostgreSQL, Redis, VNC, Elasticsearch
- TLS inspection with raw ClientHello probes: SSLv2/3, TLS 1.0–1.3, cipher suites, DH group size, certificate details
- OS guess from TTL, ports and banners, with its basis and confidence shown

**Apps and device identification** (on by default; "Identify apps and device models" in Advanced settings)
- **Web apps and admin pages:** 87 signatures matched against the page NetWarden already fetched (title, headers, cookies, page markers). One redirect is followed only if it stays on the same device and port, to reach a login page. Examples include NAS units (Synology, QNAP, TrueNAS, Unraid), hypervisors (Proxmox, ESXi), Home Assistant, Plex/Jellyfin, Pi-hole, routers and firewalls (UniFi, pfSense, OPNsense, OpenWrt, NETGEAR, TP-Link, ASUS), printers (HP, Brother, Canon, Epson), cameras (Hikvision, Dahua, Axis), Jenkins, GitLab, Grafana, Portainer, Webmin, iLO and iDRAC. A version that can be read reliably (Jenkins, Grafana, Webmin, Kibana, WordPress, Tomcat) is fed into CVE matching.
- **Bonjour / mDNS:** asks each device which services it advertises (AirPlay, Google Cast, printers and scanners, SMB, Time Machine, HomeKit and Matter, SSH and more). The answers include the device's model and name.
- **UPnP:** reads the device description at the address the device itself gives in its SSDP reply. That address is only fetched if it is the device being scanned. The description gives the manufacturer, model, friendly name and roles (internet gateway or port forwarding, media server or renderer, printer).
- **Result:** each device gets a device type (Printer, NAS, Router, Media player, Camera, Windows computer, Domain controller and so on), a make and model where available, and a readable "Apps and services" list. The list appears in the Devices view and in the HTML, PDF and CSV reports.
- **No sign-in:** this uses the same discovery your phone or printer dialog uses, so it only sees what devices advertise or expose on the network. Installed programs that don't listen on the network can only be listed with a signed-in (credentialed) inventory, which NetWarden does not do yet.

**Vulnerability checks.** Each one is a separate class or JSON template.

| Area | Checks |
|---|---|
| Windows / SMB | SMBv1 enabled · SMB signing not required · MS17-010 (EternalBlue), using the same status-code probe as Nmap's `smb-vuln-ms17-010` (opt-in, anonymous session) |
| Remote access | RDP without NLA · RDP legacy encryption · Telnet open · VNC without password · weak SSH algorithms · SSH Terrapin (CVE-2023-48795) |
| TLS | SSLv2/v3, TLS 1.0/1.1 · RC4/3DES/DES/EXPORT/NULL/anonymous suites · no forward secrecy · weak DH (Logjam) · expired, expiring, not-yet-valid, self-signed or untrusted certificates · weak keys/signatures |
| Web (read-only GET/HEAD/OPTIONS) | exposed `.git` and `.env` · Apache server-status/info · phpinfo · directory listing · Tomcat Manager · phpMyAdmin · Spring Actuator `/env` · TRACE advertised · default pages · missing security headers |
| Databases & services | database ports reachable · Redis without a password (`INFO` only) · Elasticsearch without auth · Docker API without TLS · anonymous FTP (opt-in, one login, no listing) · cleartext FTP |
| Network services | SNMP reachable · UPnP/SSDP · IPMI/BMC · open DNS resolver (public addresses only) |
| Known CVEs | CPE/version match against NVD, with CVSS 3.1 severity and **"Actively exploited"** for KEV-listed CVEs |

Each finding includes:
- a description and the affected host and port
- the evidence
- CVSS score and vector, and references
- concrete remediation steps

## 7. Data, privacy and portability

**Where data is stored**
- Everything goes in a **`NetWarden-data`** folder next to the exe: `history.db`, `cve.db`, settings, profiles, logs (Serilog, 30 days) and reports.
- If that folder can't be written to (for example under Program Files), NetWarden uses `%LocalAppData%\NetWarden` instead.
- Set the `NETWARDEN_DATA` environment variable to force a location.

**Moving NetWarden.** Copy the exe and the data folder together; history comes with it. Saved passwords stay behind, because they live in Windows Credential Manager on the original PC.

**Keep the data folder safe.** Scan results are a map of your network's weak spots.

**No telemetry.** The only outbound traffic NetWarden ever sends is:
- your scans, to targets you authorized
- the NVD and CISA feed downloads
- the notification channels you configure

## 8. Npcap note

**NetWarden does not need Npcap, WinPcap or admin rights.**
- **ARP discovery** uses the built-in Windows `SendARP` API.
- **Ping** uses the OS ICMP API.
- **Scanning** uses ordinary TCP/UDP sockets (full TCP connect, not SYN scanning).

A raw-packet (Npcap) module was considered and deliberately left out. It would need a driver install and elevation, and gains little for an authorized defensive inventory. If Npcap is already installed, nothing changes.

## 9. Solution layout

```
NetWarden.sln
├─ src/
│  ├─ NetWarden.Core        Scanning engine. No UI, no database, no NuGet dependencies.
│  │   ├─ Targeting/        IP/CIDR/range/hostname parsing, port specs, ScanScope (enforces authorization + exclusions)
│  │   ├─ Discovery/        ICMP, TCP ping, SendARP, reverse DNS/NetBIOS, MAC vendor (OUI) lookup
│  │   ├─ Scanning/         token-bucket throttle, TCP connect scanner, UDP probes
│  │   ├─ Protocols/        read-only packet builders/parsers: SMB1/2, RDP, SSH, TDS, MySQL, DNS, NTP, SNMPv3, NetBIOS, SSDP, IPMI, VNC
│  │   ├─ Tls/              raw ClientHello prober, cipher table, certificate inspection
│  │   ├─ Fingerprinting/   service detection, banner parsing, CPE mapping, OS guess
│  │   ├─ Checks/           IVulnerabilityCheck interface, CheckContext, ICveRepository
│  │   └─ ScanOrchestrator  pipeline: scope → discovery → ports → UDP → services/TLS → OS → checks (async, pausable, cancellable)
│  ├─ NetWarden.Checks      All vulnerability checks, CVE/CPE matcher, JSON check-pack engine (+ built-in web pack)
│  ├─ NetWarden.Data        SQLite stores (history, finding status, scopes, append-only audit log, CVE db),
│  │                        NVD 2.0 + KEV clients, offline bundles, Nmap XML import, settings/profile files
│  ├─ NetWarden.Reporting   Report model, "fix these first" grouping, scan diff, PDF (QuestPDF), HTML, CSV, JSON, email/Teams
│  ├─ NetWarden.UI          View models, MVVM helpers, glossary, CLI runner. No WPF types, so it is unit-testable.
│  └─ NetWarden.App         WPF shell: views, light/dark themes, Windows services (Credential Manager,
│                           Task Scheduler, Serilog). Builds the single NetWarden.exe (GUI + CLI).
├─ tests/NetWarden.Tests    xUnit tests (parsers, CIDR, CPE/version matching, checks with scripted network responses, reports…)
├─ tools/SampleReport       Regenerates samples/ from a fictional Nmap file
└─ samples/                 Sample report output (HTML, CSV, JSON)
```

## 10. Extending NetWarden

**New check (C#).** Add a class to `NetWarden.Checks` that derives from `CheckBase` (or implements `IVulnerabilityCheck`) and has a parameterless constructor. `CheckRegistry` finds it automatically; the engine doesn't change. Choose the right level:
- `ProbeLevel.VersionOnly` for checks that only use collected facts.
- `ProbeLevel.SafeProbe` for checks that send their own read-only requests (and set `RequiresAnonymousLogin` if they log in anonymously).

**New web check (JSON, no code).** Put `my-pack.json` and a matching `my-pack.json.sha256` (its SHA-256 hex) in `NetWarden-data\checks`. Templates follow the format of `src/NetWarden.Checks/Packs/http-default.json`. The validator rejects:
- any method other than GET, HEAD or OPTIONS
- paths with `..`
- templates without matchers

Matched content is never stored, because it may contain secrets.

## 11. Building and testing

```
dotnet test tests\NetWarden.Tests\NetWarden.Tests.csproj -c Release        # 136 tests
dotnet publish src\NetWarden.App\NetWarden.App.csproj -c Release -o dist    # portable exe
dotnet run --project tools\SampleReport -- tests\NetWarden.Tests\TestData\sample-nmap.xml samples --pdf
```

The tests cover:
- CIDR/range/hostname parsing, scope enforcement and the public-address rule
- port specs
- every protocol parser, using hand-built packets
- version comparison and CPE/CVE matching
- each check, using a scripted fake network: SMB, MS17-010, RDP, SSH/Terrapin, TLS, certificates, web templates, Redis, anonymous FTP
- the check-pack validator
- Nmap import, NVD/KEV parsing and offline-bundle tamper detection
- report grouping, CSV formula-injection escaping, HTML encoding and scan diffs
- the query language, CLI parsing, and an end-to-end loopback scan

## 12. Known limitations

- **First build of the GUI.** The engine, checks, data, reporting and view-model layers were compiled and tested (136 passing tests), and the scanner was run against live HTTP, TLS and SSH services. The WPF window itself (XAML and the Windows-only code) could not be compiled in the authoring environment, because NuGet was unreachable. If the first `build.cmd` run reports a XAML or compile error, it will be a small, local fix.
- **Old TLS servers.** For servers that *only* speak TLS 1.0/1.1, NetWarden still detects the protocols, ciphers and certificate using raw probes. It can't fetch the web page itself, because Windows disables those versions for its own connections. HTTP-level web checks are therefore skipped for those servers.
- **Version-based CVE matches can be false positives** when vendors back-port fixes. They are labelled **Potential**. Use *False positive* with a note when the vendor advisory confirms the fix.
- **Scale and protocols.** IPv4 ranges up to /16 per scope. IPv6 is supported as single addresses only.
- **MAC vendors.** The built-in list covers common vendors. Import the IEEE `oui.csv` for full coverage.
- **Scheduled tasks** run only while the user is signed in. Running while signed out would need a stored password, which NetWarden deliberately doesn't ask for.
- **Original spec deviations.** Some choices differ from the original spec, to keep a single portable exe with fewer moving parts:
  - small built-in MVVM helpers instead of CommunityToolkit.Mvvm
  - a hand-built Fluent-style theme instead of WPF-UI
  - built-in donut and bar charts instead of LiveCharts2
  - plain ADO.NET instead of an ORM
  - SendARP instead of Npcap
  - a portable exe instead of MSIX/Inno Setup

## 13. Third-party components

| Component | License | Use |
|---|---|---|
| Microsoft.Data.Sqlite / SQLitePCLRaw | MIT / Apache-2.0 | Local databases |
| QuestPDF | QuestPDF Community License: free for individuals, non-profits and companies under USD 1M annual revenue; larger companies need a commercial licence | PDF reports |
| Serilog, Serilog.Sinks.File | Apache-2.0 | Logging |
| xUnit (tests only) | Apache-2.0 | Tests |

CVE data comes from the NIST National Vulnerability Database. KEV data comes from CISA. Both are US-government public data.
