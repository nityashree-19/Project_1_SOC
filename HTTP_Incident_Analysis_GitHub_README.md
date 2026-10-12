# HTTP Incident Analysis: Brute-Force Attempts, Sensitive File Access, and Web-Shell Activity

> **Project type:** Cybersecurity incident-report analysis\
> **Purpose:** GitHub portfolio presentation / SOC Analyst L1 learning
> project\
> **Incident date reported in source:** 23 December 2025\
> **Reported severity:** Critical\
> **Status:** Analysis based on the supplied incident report; raw logs
> and forensic artifacts were not provided.

------------------------------------------------------------------------

## Table of Contents

1.  [Project Overview](#1-project-overview)
2.  [Incident at a Glance](#2-incident-at-a-glance)
3.  [Executive Summary](#3-executive-summary)
4.  [Assets and Indicators](#4-assets-and-indicators)
5.  [Attack Timeline](#5-attack-timeline)
6.  [Attack-Chain Diagram](#6-attack-chain-diagram)
7.  [System and Evidence Flow
    Diagram](#7-system-and-evidence-flow-diagram)
8.  [Detailed Event Analysis](#8-detailed-event-analysis)
9.  [MITRE ATT&CK Mapping](#9-mitre-attck-mapping)
10. [Impact Assessment](#10-impact-assessment)
11. [Root Cause Analysis](#11-root-cause-analysis)
12. [SOC Analyst Investigation
    Workflow](#12-soc-analyst-investigation-workflow)
13. [Containment, Eradication, and
    Recovery](#13-containment-eradication-and-recovery)
14. [Preventive Controls](#14-preventive-controls)
15. [Evidence to Collect](#15-evidence-to-collect)
16. [Findings and Limitations](#16-findings-and-limitations)
17. [Conclusion](#17-conclusion)
18. [GitHub Presentation Guide](#18-github-presentation-guide)

------------------------------------------------------------------------

## 1. Project Overview

This project reviews a reported web-server security incident involving
repeated login attempts, requests for sensitive files, a SQL-injection
attempt, a suspicious PHP file upload, and a request to execute a
command through a possible web shell.

The goal is to explain the incident in a way that is useful for a
beginner SOC analyst: identify the reported events, arrange them into a
timeline, map relevant activity to security concepts, assess potential
impact, and recommend investigation and response steps.

### Objectives

-   Understand a multi-stage web-application incident.
-   Separate reported observations from conclusions that still need
    evidence.
-   Build an event timeline.
-   Review possible MITRE ATT&CK mappings.
-   Recommend practical detection, containment, and prevention actions.
-   Present the analysis as a readable GitHub portfolio project.

### Scope and methodology

This document is based on the supplied three-page incident report. No
raw HTTP access logs, authentication logs, endpoint telemetry, packet
captures, file hashes, or forensic images were supplied. Therefore, the
report's events are treated as **reported observations**, not
independently verified facts.

------------------------------------------------------------------------

## 2. Incident at a Glance

  ---------------------------------------------------------------------------
  Field                               Details from the source report
  ----------------------------------- ---------------------------------------
  Incident title                      HTTP using brute-force attempts and
                                      command execution

  Detection date                      23 December 2025

  Severity                            Critical

  Target server                       `WIN-SERVER`

  Host named as compromised           `Nityashree` --- identity requires
                                      confirmation

  User account mentioned              `admin`

  Reported source IPs                 `192.168.1.50`, `10.0.0.88`,
                                      `172.16.1.24`, `10.0.0.90`

  Reported sensitive paths            `/backup.zip`, `/secret/company.db`

  Reported upload endpoint            `/admin/upload.php`

  Reported uploaded file              `malicious_shell.php`

  Reported command request            `/uploads/malicious_shell.php?cmd=id`
  ---------------------------------------------------------------------------

### Important interpretation

The source report describes a potentially serious incident. However, a
request to a suspicious URL does not by itself prove that the request
succeeded. Successful authentication, file download, file upload,
command execution, and data exfiltration must each be confirmed with
logs or forensic evidence.

------------------------------------------------------------------------

## 3. Executive Summary

The supplied report describes a sequence of HTTP-related events on 23
December 2025. It records successful login events among repeated login
attempts, requests for a backup archive and database file, a
SQL-injection-style request, a suspicious PHP upload, and a later
request to a PHP file with a `cmd=id` parameter.

If confirmed, this sequence could indicate that an attacker obtained or
used credentials, accessed sensitive files, uploaded a server-side
script, and attempted to execute a command. These activities can lead to
unauthorized access, exposure of confidential data, and further
compromise of the server.

The primary weaknesses identified by the source report are weak
authentication, weak password policy, inadequate access controls, and
insecure file-upload handling. The report also identifies a possible
lack of effective real-time monitoring.

**Current conclusion:** The sequence is suspicious and warrants
investigation. The supplied report alone does not prove that all actions
succeeded, that the server was fully compromised, or that data was
exfiltrated.

------------------------------------------------------------------------

## 4. Assets and Indicators

### 4.1 Assets mentioned

-   **Target server:** `WIN-SERVER`
-   **Host named as compromised:** `Nityashree`
-   **Account:** `admin`
-   **Web application paths:** `/index.php`, `/admin/upload.php`,
    `/uploads/malicious_shell.php`

Confirm whether `Nityashree` is a machine hostname, a username, or a
person's name before publishing the report. For a public GitHub
portfolio, use a sanitized placeholder such as `AFFECTED-HOST-01` if the
name is personal or identifying.

### 4.2 IP addresses listed in the report

  -----------------------------------------------------------------------
  IP address              Where it appears        Investigation note
  ----------------------- ----------------------- -----------------------
  `192.168.1.50`          Asset list and          Validate the source
                          containment list        system and related
                                                  events.

  `10.0.0.88`             Asset list and          Validate the source
                          containment list        system and related
                                                  events.

  `172.16.1.24`           Asset list              The containment section
                                                  uses a different value;
                                                  verify before acting.

  `10.0.0.90`             Asset list and          Validate the source
                          containment list        system and related
                                                  events.

  `172.161.124`           Containment list only   Does not match
                                                  `172.16.1.24`; likely a
                                                  reporting
                                                  inconsistency, but do
                                                  not assume the intended
                                                  correction.
  -----------------------------------------------------------------------

**Network note:** These addresses are in private IPv4 space except
`172.161.124`, which is not a complete IPv4 address as written. The
value `172.161.124` contains only three octets and is invalid as a
normal IPv4 address. Verify the original logs before adding any IP to a
block list. Private addresses may represent internal hosts, lab
machines, proxies, or NAT addresses rather than internet-based
attackers.

------------------------------------------------------------------------

## 5. Attack Timeline

The following timeline preserves the times and event descriptions in the
source report.

  ---------------------------------------------------------------------------------------
  Time                    Reported event                          What a SOC analyst
                                                                  should verify
  ----------------------- --------------------------------------- -----------------------
  13:10:01                Successful login                        Account, source IP,
                                                                  authentication method,
                                                                  and login result

  13:10:04                Second brute-force attempt using        Username, source IP,
                          another user ID                         response code, and
                                                                  whether the attempt
                                                                  failed

  13:10:06                Third attempt using a different         Authentication outcome
                          password                                and relationship to
                                                                  earlier events

  13:10:09                Fourth brute-force attempt using a      Failure count, rate,
                          different password                      and any lockout or
                                                                  rate-limit action

  13:10:14                Successful login                        Account and source IP;
                                                                  determine whether this
                                                                  is related to the prior
                                                                  attempts

  13:11:25                Request for `/backup.zip`               HTTP status code,
                                                                  response bytes, and
                                                                  whether the file was
                                                                  returned

  13:11:27                Request for `/secret/company.db`        HTTP status code,
                                                                  response bytes, and
                                                                  whether the database
                                                                  was returned

  13:12:40                SQL-injection-style request to          Application/WAF logs,
                          `/index.php?id=' OR 'a'='a`             query handling,
                                                                  database errors, and
                                                                  response

  13:13:25                Upload reported at `/admin/upload.php`  Upload response, file
                                                                  creation, hash, owner,
                                                                  and timestamp

  13:14:20                Request to                              Whether the file
                          `/uploads/malicious_shell.php?cmd=id`   existed, whether it
                                                                  executed, and what
                                                                  process or output was
                                                                  produced
  ---------------------------------------------------------------------------------------

**Time caveat:** The source does not specify a time zone or the log
source for these times. Confirm both before correlating the events with
other systems.

------------------------------------------------------------------------

## 6. Attack-Chain Diagram

This diagram represents the **reported possible sequence**, not a
confirmed reconstruction.

``` mermaid
flowchart TD
    A["Repeated HTTP login attempts"] --> B["Successful login reported"]
    B --> C["Sensitive-file requests"]
    C --> D["SQL-injection-style request"]
    D --> E["Suspicious PHP upload reported"]
    E --> F["Web-shell command request"]
    F --> G["Potential server compromise"]
    G --> H["Potential data exposure or further access"]

    style A fill:#fff2cc,stroke:#a67c00,color:#222
    style B fill:#fff2cc,stroke:#a67c00,color:#222
    style C fill:#fce4d6,stroke:#b85450,color:#222
    style D fill:#fce4d6,stroke:#b85450,color:#222
    style E fill:#f4cccc,stroke:#990000,color:#222
    style F fill:#f4cccc,stroke:#990000,color:#222
    style G fill:#f4cccc,stroke:#990000,color:#222
    style H fill:#d9ead3,stroke:#38761d,color:#222
```

### How to read this diagram

1.  **Login attempts:** Repeated authentication attempts may indicate
    password guessing. The source report also lists successful login
    events, but does not show which account or IP was involved in each
    event.
2.  **Sensitive-file requests:** Requests to backup and database paths
    may expose information if the application serves those files without
    appropriate authorization.
3.  **Injection attempt:** The URL contains a SQL-injection-style input.
    Logs and application behavior are needed to determine whether the
    input affected a database query.
4.  **Suspicious upload:** A PHP file named `malicious_shell.php` is
    reported as uploaded. Verify whether the file was actually saved and
    whether the web server could execute it.
5.  **Command request:** The `cmd=id` parameter resembles a request to
    execute the `id` command through a web shell. Confirm execution
    through process telemetry, application logs, or other evidence.
6.  **Potential impact:** If these steps succeeded, the incident could
    have exposed data or enabled additional access. The final impact
    must be based on evidence.

------------------------------------------------------------------------

## 7. System and Evidence Flow Diagram

The source report does not provide a verified network architecture. The
following is a **conceptual investigation diagram** showing the systems
and evidence sources a SOC team would normally review.

``` mermaid
flowchart LR
    U["Client or source system"] -->|HTTP requests| W["Web server: WIN-SERVER"]
    W --> A["Web application"]
    A --> DB["Database / sensitive files"]
    W --> L["Web access and error logs"]
    A --> AL["Application logs"]
    W --> E["Endpoint telemetry"]
    L --> S["SIEM / log analysis"]
    AL --> S
    E --> S
    S --> SOC["SOC analyst investigation"]
    SOC --> IR["Incident response and containment"]

    style W fill:#cfe2f3,stroke:#0b5394,color:#222
    style S fill:#d9ead3,stroke:#38761d,color:#222
    style IR fill:#f4cccc,stroke:#990000,color:#222
```

### Diagram explanation

-   **Client or source system:** The origin recorded in HTTP logs. Do
    not assume it is the true attacker without checking proxies, NAT,
    and network routing.
-   **Web server:** Receives the requests and may host the application
    and uploaded files.
-   **Web application:** Processes login requests, URL parameters, and
    file uploads.
-   **Database and sensitive files:** Potential targets for unauthorized
    access. Confirm actual file location and access controls.
-   **Web/application logs:** Can show request paths, timestamps, status
    codes, user agents, and application errors, depending on logging
    configuration.
-   **Endpoint telemetry:** May show process creation, file writes,
    command execution, and other host activity.
-   **SIEM:** Correlates logs and raises alerts. The source report does
    not identify a specific SIEM product.
-   **SOC and incident response:** Validate evidence, determine scope,
    contain the incident, and document findings.

------------------------------------------------------------------------

## 8. Detailed Event Analysis

### 8.1 Repeated login attempts

**Reported evidence:** Several attempts are described between 13:10:04
and 13:10:09, with successful login events at 13:10:01 and 13:10:14.

**Why it matters:** A high volume of failed logins can indicate password
guessing or credential abuse. A successful login near those attempts
increases the need to investigate, but does not automatically prove that
the successful login resulted from brute force.

**Questions to investigate:** - Which usernames were attempted? - Which
IP address generated each attempt? - Were the successful and failed
attempts associated with the same account? - Were MFA, rate limits, or
account lockout controls active? - Did the login lead to administrative
actions?

**Recommended detection:** Alert on repeated failures followed by a
successful login from the same source or against the same account within
a short period. Tune thresholds to the environment to reduce false
positives.

### 8.2 Sensitive file access

**Reported paths:** - `/backup.zip` - `/secret/company.db`

**Why it matters:** Backup archives and database files may contain
sensitive information, configuration data, user records, or credentials.
Files exposed through a web root can sometimes be retrieved directly.

**What to verify:** - HTTP status code and response size. - Whether the
server returned the actual file or an error page. - File access-control
configuration and web-root placement. - Whether the same session or
source requested other sensitive paths. - Whether outbound traffic
indicates a transfer of data.

**Recommended control:** Store sensitive backups outside publicly served
directories and require appropriate authorization for sensitive
resources.

### 8.3 SQL-injection-style request

**Reported URI:** `/index.php?id=' OR 'a'='a`

**Why it matters:** The parameter contains an input pattern commonly
associated with testing or attempting SQL injection. If an application
builds SQL queries unsafely, user input may change the intended query
logic.

**What to verify:** - WAF and application logs. - HTTP response code and
response body. - Database errors or unusual query activity. - Whether
the application uses parameterized queries. - Whether any records were
accessed or modified.

**Recommended control:** Use parameterized queries or prepared
statements, safe database APIs, server-side input validation, and
appropriate error handling. Input filtering alone is not a sufficient
defense.

### 8.4 Suspicious PHP upload

**Reported endpoint:** `/admin/upload.php`\
**Reported filename:** `malicious_shell.php`

**Why it matters:** If a server accepts and executes an
attacker-controlled PHP file, the file may provide a route to run
commands under the web-server account.

**What to verify:** - Whether the upload request succeeded. - Whether
the file exists and its hash. - Creation and modification timestamps. -
File ownership and permissions. - Whether the upload directory allows
script execution. - Related process creation and outbound network
connections.

**Recommended control:** Allow only required file types, inspect file
content, generate server-side filenames, limit size, store uploads
outside the web root where feasible, and disable script execution in
upload directories.

### 8.5 Possible web-shell command execution

**Reported URI:** `/uploads/malicious_shell.php?cmd=id`

**Why it matters:** The `id` command on Unix-like systems displays
identity and group information for the executing account. A request with
a `cmd` parameter may indicate an attempt to pass a command to a web
shell.

**Important distinction:** The URI alone does not prove that a command
ran. Verify execution using endpoint telemetry, process records,
web-server logs, or other host evidence. Also confirm the server
operating system because the source report names `WIN-SERVER`, while the
example command is commonly associated with Unix-like systems. The name
alone is not sufficient to determine the operating system.

**Recommended response:** Preserve relevant evidence, restrict access to
the affected system, determine whether the file executed, identify the
execution context, and investigate persistence or additional access.

------------------------------------------------------------------------

## 9. MITRE ATT&CK Mapping

The source report lists several technique IDs. The table below keeps the
reported mapping visible and adds review notes. Validate mappings
against the current MITRE ATT&CK knowledge base before final submission.

  -----------------------------------------------------------------------
  Activity                ID in source report     Interpretation and
                                                  review
  ----------------------- ----------------------- -----------------------
  Brute-force login       `T1110`                 Broadly consistent with
                                                  the Brute Force
                                                  technique family.
                                                  Determine the specific
                                                  sub-technique only when
                                                  the evidence supports
                                                  it.

  Successful login        `T1078`                 Valid Accounts may be
                                                  relevant if an existing
                                                  account was used. A
                                                  successful login alone
                                                  does not prove
                                                  malicious use.

  SQL-injection attempt   `T1190`                 Exploit Public-Facing
                                                  Application may apply
                                                  if the application was
                                                  exploited. The input
                                                  pattern alone does not
                                                  prove exploitation.

  Sensitive file access   `T1005`                 The source uses Data
                                                  from Local System.
                                                  Confirm where the data
                                                  was stored and how it
                                                  was accessed; a web
                                                  request for a file is
                                                  not enough to establish
                                                  the full technique.

  Suspicious file upload  `T1190`                 Review this mapping. A
                                                  file upload is not
                                                  automatically an
                                                  exploit; determine
                                                  whether a vulnerability
                                                  was used and whether
                                                  the file was executed.

  Web-shell activity      `T1505`                 The Web Shell
                                                  sub-technique,
                                                  `T1505.003`, may be
                                                  relevant if a web shell
                                                  is confirmed.
  -----------------------------------------------------------------------

### Why ATT&CK mapping matters

MITRE ATT&CK provides a shared vocabulary for describing adversary
behavior. It helps SOC analysts organize detections, identify telemetry
gaps, and communicate how observed activity may fit into an attack
sequence. Mapping should describe behavior supported by evidence, not
simply label every suspicious event as a confirmed technique.

------------------------------------------------------------------------

## 10. Impact Assessment

The source report lists the following impacts. Their status should be
validated.

  -----------------------------------------------------------------------
  Potential impact        Current status from     Evidence needed
                          supplied material       
  ----------------------- ----------------------- -----------------------
  Unauthorized access     Reported / requires     Authentication logs,
                          validation              session records,
                                                  account activity

  Web-shell deployment    Reported / requires     File evidence, hash,
                          validation              upload result,
                                                  file-system timestamps

  Sensitive data exposure Possible                Successful file
                                                  response, data
                                                  classification, access
                                                  records

  Backup-file access      Reported request        HTTP status, response
                                                  bytes, file-access
                                                  evidence

  Data exfiltration       Risk identified, not    Network flow, proxy
                          proven                  logs, outbound transfer
                                                  records, destination
                                                  analysis

  Further server          Possible                Endpoint telemetry,
  compromise                                      persistence checks,
                                                  process and account
                                                  review
  -----------------------------------------------------------------------

Do not describe data exfiltration as confirmed unless evidence shows
that data left the environment or was otherwise transferred to an
unauthorized destination.

------------------------------------------------------------------------

## 11. Root Cause Analysis

### Primary root cause reported

-   Weak authentication controls.

### Contributing weaknesses reported

-   Weak password policy.
-   Improper access controls.
-   Insecure file-upload mechanism.
-   Potentially executable upload directory.
-   A stated lack of effective real-time monitoring.

### Root-cause diagram

``` mermaid
flowchart TD
    R["Security weaknesses reported"] --> A["Weak authentication"]
    R --> B["Inadequate access controls"]
    R --> C["Unsafe file-upload handling"]
    R --> D["Potential monitoring gaps"]
    A --> E["Possible unauthorized account access"]
    B --> F["Potential access to sensitive files"]
    C --> G["Potential script upload and execution"]
    D --> H["Delayed detection or investigation"]
    E --> I["Potential combined incident impact"]
    F --> I
    G --> I
    H --> I
```

### Explanation

The incident may have involved several weaknesses rather than one
isolated failure. Authentication controls help prevent unauthorized
access; access controls restrict sensitive resources; secure upload
handling prevents uploaded content from becoming executable; and
monitoring helps detect suspicious behavior early.

This is a preliminary root-cause model based on the source report. It
should be updated after reviewing configuration, application code, logs,
and forensic findings.

------------------------------------------------------------------------

## 12. SOC Analyst Investigation Workflow

The following workflow is a practical investigation sequence for an L1
analyst, with escalation to the incident-response team when necessary.

``` mermaid
flowchart TD
    A["Alert or incident report received"] --> B["Validate time, host, IPs, and affected account"]
    B --> C["Collect web, authentication, application, and endpoint logs"]
    C --> D["Build event timeline and correlate indicators"]
    D --> E{"Evidence of successful compromise?"}
    E -->|Not established| F["Document gaps and continue validation"]
    E -->|Likely or confirmed| G["Escalate to incident response"]
    G --> H["Contain affected host and accounts using approved process"]
    H --> I["Preserve evidence and investigate scope"]
    I --> J["Eradicate cause and recover safely"]
    J --> K["Monitor, validate, and close with lessons learned"]
    F --> L["Record findings and escalation criteria"]
```

### Investigation checklist

-   [ ] Confirm incident date, time zone, hostname, and source IPs.
-   [ ] Check whether the login attempts succeeded or failed.
-   [ ] Identify account names, sessions, and administrative activity.
-   [ ] Review HTTP access and error logs for the listed paths.
-   [ ] Confirm whether sensitive files were returned successfully.
-   [ ] Validate the SQL-injection attempt using application and
    database evidence.
-   [ ] Determine whether the suspicious PHP file was uploaded and
    executed.
-   [ ] Search endpoint telemetry for command execution and persistence.
-   [ ] Review outbound traffic for possible data transfer.
-   [ ] Preserve evidence and record every action taken.
-   [ ] Escalate suspected compromise according to the organization's
    incident-response procedure.

------------------------------------------------------------------------

## 13. Containment, Eradication, and Recovery

### 13.1 Containment

The source report recommends isolating the affected server, blocking
source IPs, resetting credentials, and removing the web shell.

Before acting: - Verify the affected host and IP indicators. -
Coordinate containment with the authorized incident-response lead. -
Preserve logs and forensic evidence where feasible. - Avoid blocking an
unverified or malformed IP address. - Reset affected credentials and
revoke active sessions/tokens as appropriate.

### 13.2 Eradication

-   Identify and remove unauthorized scripts after preserving relevant
    evidence.
-   Check for additional web shells, backdoors, unauthorized accounts,
    scheduled tasks, and persistence mechanisms.
-   Patch the vulnerable application or server components.
-   Correct file permissions and disable execution in upload
    directories.
-   Rotate any secrets or credentials that may have been exposed.

### 13.3 Recovery

-   Restore from a trusted backup if required.
-   Validate application integrity and access controls.
-   Re-enable services through an approved change process.
-   Increase monitoring for repeated login attempts, suspicious uploads,
    and unexpected child processes.
-   Document the recovery checks and monitor for recurrence.

**Operational note:** Do not destroy evidence by immediately deleting
suspicious files or rebuilding the server unless urgent containment
requires it. Follow the organization's evidence-handling process.

------------------------------------------------------------------------

## 14. Preventive Controls

  -----------------------------------------------------------------------
  Control                 Purpose                 Example implementation
  ----------------------- ----------------------- -----------------------
  Multi-factor            Reduce risk from stolen Require MFA for
  authentication          or guessed passwords    administrators and
                                                  remote access

  Brute-force protection  Reduce repeated         Rate limits,
                          password guessing       progressive delays,
                                                  lockout safeguards,
                                                  alerting

  Least privilege         Limit damage from       Restrict administrative
                          compromised accounts    roles and
                                                  service-account
                                                  permissions

  Secure file storage     Prevent direct access   Keep backups outside
                          to sensitive files      the public web root

  Secure uploads          Prevent malicious files Allowlist file types,
                          from executing          inspect content, rename
                                                  files, disable
                                                  execution

  Parameterized queries   Prevent SQL injection   Use prepared statements
                                                  and safe database APIs

  Web application         Detect or block some    Deploy rules with
  firewall                malicious HTTP patterns monitoring and regular
                                                  tuning

  Centralized logging     Support detection and   Collect web,
                          investigation           authentication,
                                                  application, endpoint,
                                                  and network logs

  Endpoint monitoring     Detect suspicious       Alert on web-server
                          process and file        processes spawning
                          activity                unexpected shells or
                                                  tools

  Incident-response plan  Improve containment and Maintain a tested
                          recovery                escalation and
                                                  evidence-preservation
                                                  procedure
  -----------------------------------------------------------------------

A single control is not enough. Defense in depth combines
authentication, application security, access restrictions, endpoint
monitoring, and incident-response readiness.

------------------------------------------------------------------------

## 15. Evidence to Collect

  -----------------------------------------------------------------------
  Evidence source         Useful fields or        Why it helps
                          artifacts               
  ----------------------- ----------------------- -----------------------
  Web access logs         Timestamp, source IP,   Establishes request
                          URI, method, status     sequence and response
                          code, user agent, bytes outcomes
                          sent                    

  Web error logs          Errors, stack traces,   May reveal injection
                          application failures    attempts or application
                                                  behavior

  Authentication logs     Account, source,        Validates brute-force
                          success/failure, MFA    and successful-login
                          result                  claims

  Application logs        Upload result,          Helps establish whether
                          validation failures,    application actions
                          session ID              succeeded

  File-system metadata    File path, owner,       Helps validate
                          timestamps, permissions suspicious upload and
                                                  file access

  File hash               SHA-256 or another      Supports evidence
                          approved hash           tracking and file
                                                  identification

  Endpoint telemetry      Process tree, command   Helps confirm whether a
                          line, parent process,   web shell executed
                          network connections     commands

  Database logs           Query errors, unusual   Helps investigate
                          access, modifications   SQL-injection claims
                                                  and data access

  Firewall/proxy/DNS logs Connections,            Helps investigate
                          destinations, byte      possible outbound data
                          counts, DNS queries     transfer

  SIEM alerts             Rule name, event        Shows detection
                          details, alert          coverage and alert
                          timestamps              sequence
  -----------------------------------------------------------------------

Store evidence according to organizational policy. Avoid uploading raw
logs, personal data, secrets, credentials, or sensitive internal details
to a public GitHub repository.

------------------------------------------------------------------------

## 16. Findings and Limitations

### Findings supported by the source report

-   The report records repeated login attempts and successful login
    events.
-   It records requests for `/backup.zip` and `/secret/company.db`.
-   It records a SQL-injection-style request.
-   It reports an upload named `malicious_shell.php`.
-   It reports a request to that PHP path with `cmd=id`.
-   It identifies authentication, access-control, upload-handling, and
    monitoring weaknesses.

### Claims that remain unverified

-   Whether the login events were malicious and linked to the same
    actor.
-   Whether the sensitive files were successfully returned.
-   Whether the SQL-injection attempt succeeded.
-   Whether the PHP file was uploaded, executed, or used as a web shell.
-   Whether commands ran on the server.
-   Whether data was exfiltrated.
-   Whether the system experienced full compromise.

### Data-quality issues to resolve

1.  **IP mismatch:** `172.16.1.24` and `172.161.124` do not match. The
    latter is malformed as written.
2.  **Host identity:** Confirm whether `Nityashree` is a hostname or a
    personal identifier.
3.  **Operating system:** The server name `WIN-SERVER` suggests Windows
    naming, but it does not prove the OS. The `id` command is commonly
    associated with Unix-like systems; confirm the actual server
    environment and execution context.
4.  **Timeline:** The source does not specify time zone, log source,
    account details, or HTTP response codes.
5.  **Severity:** The source marks the incident Critical. Preserve this
    as the reported severity, but document the organization's severity
    criteria and evidence supporting the final classification.

------------------------------------------------------------------------

## 17. Conclusion

The supplied incident report describes a potentially critical web-server
security incident. Its reported sequence includes authentication
attempts, sensitive-file requests, a SQL-injection-style request, a
suspicious PHP upload, and a possible web-shell command request.

The main learning point is to **distinguish suspicious activity from
confirmed compromise**. A SOC analyst should correlate authentication,
web, application, endpoint, and network evidence; validate indicators;
preserve evidence; and escalate when compromise is suspected. Long-term
improvements should address authentication, access control, secure file
uploads, injection prevention, monitoring, and incident-response
readiness.

This document is an analysis of the supplied report, not an
independently verified forensic investigation.

------------------------------------------------------------------------

## 18. GitHub Presentation Guide

### Suggested repository name

`http-incident-analysis`

### Suggested repository description

`A SOC Analyst L1 portfolio project analyzing a reported HTTP incident involving brute-force attempts, sensitive-file requests, SQL-injection-style activity, suspicious PHP upload, and possible web-shell execution.`

### Suggested repository structure

``` text
http-incident-analysis/
├── README.md
├── diagrams/
│   └── README.md
├── evidence/
│   └── README.md
└── docs/
    └── investigation-checklist.md
```

You can keep the entire project in a single `README.md` initially.
GitHub renders Mermaid diagrams in Markdown on supported pages, so the
diagrams in this file should appear automatically when viewed on GitHub.

### What to say when presenting the project

> "This project analyzes a reported HTTP security incident from a SOC
> Analyst L1 perspective. I organized the reported events into a
> timeline, reviewed the possible attack chain, assessed the MITRE
> ATT&CK mappings, identified evidence gaps, and recommended
> investigation, containment, and preventive controls. I also
> distinguished reported activity from conclusions that require raw logs
> or forensic evidence."

### Before publishing

-   Replace personal or identifying host names with sanitized labels.
-   Do not publish internal company data, real credentials, tokens,
    private logs, or confidential files.
-   Confirm the IP mismatch and other data-quality issues if you have
    access to the original evidence.
-   Label unverified outcomes as **reported**, **suspected**, or
    **requires validation**.
-   Add actual screenshots or sanitized sample logs only if you are
    authorized to share them.

------------------------------------------------------------------------

## References and Further Reading

These are general references for further study; they were not cited as
evidence that any specific event in this report succeeded.

1.  **MITRE ATT&CK:** https://attack.mitre.org/
2.  **OWASP Top 10:** https://owasp.org/www-project-top-ten/
3.  **OWASP File Upload Cheat Sheet:**
    https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
4.  **OWASP SQL Injection Prevention Cheat Sheet:**
    https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
5.  **NIST Computer Security Incident Handling Guide (SP 800-61):**
    https://csrc.nist.gov/pubs/sp/800/61/r2/final

------------------------------------------------------------------------

*Prepared as a learning and portfolio document from the supplied
incident report. Validate all incident claims against original logs and
forensic evidence before treating them as confirmed findings.*
