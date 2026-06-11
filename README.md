# Threat Model: SecureNotes Web Application
**Methodology:** STRIDE per element, DREAD risk scoring  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope and Assumptions](#2-scope-and-assumptions)
3. [Methodology](#3-methodology)
4. [System Architecture](#4-system-architecture)
5. [STRIDE Analysis](#5-stride-analysis)
6. [Risk Register](#6-risk-register)
7. [Mitigation Register](#7-mitigation-register)
8. [Conclusion and Next Steps](#8-conclusion-and-next-steps)

---

## 1. Executive Summary

This document presents a threat model for **SecureNotes**, a hypothetical web application that allows users to register, authenticate, and store private notes. The assessment was conducted using the STRIDE per-element methodology applied to a Level 1 Data Flow Diagram, with threats scored using the DREAD risk scoring framework.

**46 threats** were identified across 7 system components. Of these, **26 are rated High risk** and require immediate remediation, **18 are rated Medium risk** and should be addressed within the current quarter, and **2 are rated Low risk** and can be scheduled for future remediation.

The three most critical findings are:

- **Insecure Direct Object Reference (IDOR)** on the Notes API — any authenticated user can read, modify, or delete any other user's notes by manipulating note IDs in API requests. DREAD score: 3.0 (Critical).
- **SQL Injection** on the database layer — absence of parameterized queries allows an attacker to read, modify, or destroy all data with a single crafted request. DREAD score: 3.0 (Critical).
- **Stored Cross-Site Scripting (XSS)** via note content — malicious scripts stored in notes execute in any viewer's browser, enabling session hijacking and account takeover at scale. DREAD score: 3.0 (Critical).

Addressing these three findings, alongside implementing MFA and centralized logging, would reduce the overall risk posture of this application significantly.

---

## 2. Scope and Assumptions

### In Scope

| Component | Type | Description |
|-----------|------|-------------|
| User browser | External entity | Client-side interface for all user interactions |
| CDN | Process | Serves static assets (HTML, CSS, JavaScript) |
| Load balancer | Process | TLS termination and traffic routing |
| Web server | Process | Request routing, session management, authentication enforcement |
| Auth service | Process | Registration, login, JWT issuance, password reset |
| Notes API | Process | CRUD operations on user notes |
| PostgreSQL database | Data store | Persistent storage for users and notes |
| Email service | External entity | SMTP delivery of password reset emails |

### Out of Scope

- Cloud infrastructure layer (IaaS — VPC, IAM, security groups)
- CI/CD pipeline and developer workstations
- Third-party email provider internal security
- Physical security of hosting facilities
- Client-side browser security (extensions, OS, antivirus)

### Assumptions

| # | Assumption |
|---|------------|
| A1 | TLS 1.2 or higher is enforced at the load balancer |
| A2 | The database is not directly accessible from the internet |
| A3 | The email service provider is a trusted third party (e.g. AWS SES, SendGrid) |
| A4 | Application code is not publicly available to attackers |
| A5 | The operating system and underlying infrastructure are regularly patched |
| A6 | Secrets (JWT signing keys, DB credentials) are stored in a secrets manager, not in code |

### Privacy Considerations

This application handles personally identifiable information (PII) including email addresses and private user-generated content. Under Canada's **PIPEDA** (and the forthcoming **Bill C-27 — Consumer Privacy Protection Act**), any breach of this data may trigger mandatory notification obligations. A supplementary **LINDDUN privacy threat model** is recommended to fully address privacy risks beyond the scope of this security-focused assessment.

---

## 3. Methodology

### Framework: STRIDE per Element

This threat model applies the **STRIDE** framework, developed by Microsoft, to each element of the system's Level 1 Data Flow Diagram. STRIDE categorizes threats by the security property they violate:

| Category | Violates | Core question |
|----------|----------|---------------|
| **S**poofing | Authentication | Can an attacker impersonate a user or service? |
| **T**ampering | Integrity | Can data be modified without authorization? |
| **R**epudiation | Non-repudiation | Can an action be denied because no record exists? |
| **I**nformation Disclosure | Confidentiality | Can sensitive data reach unauthorized parties? |
| **D**enial of Service | Availability | Can the service be made unavailable? |
| **E**levation of Privilege | Authorization | Can a user gain more access than permitted? |

STRIDE categories are applied based on element type:

| Element type | S | T | R | I | D | E |
|-------------|---|---|---|---|---|---|
| External entity (browser, email provider) | ✓ | ✓ | ✓ | | | |
| Process | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data store | | ✓ | ✓ | ✓ | ✓ | |
| Data flow | ✓ | ✓ | | ✓ | ✓ | |

### Risk Scoring: DREAD

Each identified threat is scored using the **DREAD** model across five dimensions, each rated 1–3:

| Dimension | 1 — Low | 2 — Medium | 3 — High |
|-----------|---------|-----------|---------|
| **D**amage potential | Minimal impact | Significant impact | Full system compromise |
| **R**eproducibility | Rare conditions required | Some effort required | Always reproducible |
| **E**xploitability | Advanced skill required | Some skill required | Trivial — tools available |
| **A**ffected users | Individual | Some users | All users |
| **D**iscoverability | Source code access needed | Monitoring reveals it | Visible to any attacker |

**Final score** = average of five dimensions.  
**High:** 2.5–3.0 | **Medium:** 1.5–2.4 | **Low:** 1.0–1.4

> *DREAD scores represent the assessor's judgment at the time of assessment. Scores should be reviewed when the system architecture or threat landscape changes.*

### Complementary Frameworks

While STRIDE was selected for this assessment due to its broad applicability and industry recognition, the following frameworks are noted for future consideration:

- **LINDDUN** — recommended for a dedicated privacy threat assessment (PIPEDA/Bill C-27 alignment)
- **PASTA** — recommended if a full risk-centric assessment aligned to business impact is required
- **Attack Trees** — recommended for deep analysis of the highest-risk attack chains identified here

---

## 4. System Architecture

### Application Overview

SecureNotes is a multi-tier web application consisting of a browser-based frontend, an API backend split into authentication and notes management services, a PostgreSQL database, and an external email delivery service. All user-facing traffic is served over HTTPS via a load balancer that terminates TLS before forwarding requests to internal services over HTTP.

### Trust Boundaries

Three trust boundaries are defined:

| Boundary | Between | Rationale |
|----------|---------|-----------|
| TB1 — Internet | User browser ↔ Load balancer | Fully untrusted external zone — all input assumed hostile |
| TB2 — DMZ | Load balancer ↔ Web server | Semi-trusted perimeter — TLS terminated, traffic inspected |
| TB3 — Private network | All internal services ↔ Database / Email service | Trusted internal zone — but implicit trust between services must not be assumed |

> **Key principle:** Trust boundaries are not only defined by network zones. Any component boundary where one process's output becomes another process's input represents a trust boundary that requires input validation, regardless of network location.

### Level 0 — Context Diagram

```
                    ┌─────────────────────────────┐
                    │                             │
    [User] ────────►│       SecureNotes App       │────────► [Email Provider]
                    │                             │
                    └─────────────────────────────┘
```

The system accepts input from end users via browser and outputs password reset emails via an external email provider. All other data flows are internal.

### Level 1 — Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ TB1 — Internet (untrusted)                                      │
│                                                                 │
│  [User Browser] ──HTTPS request──► [CDN / Load Balancer]       │
│  [User Browser] ◄─HTTPS response── [CDN / Load Balancer]       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │ HTTP (internal)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ TB2 — DMZ                                                       │
│                                                                 │
│                      [Load Balancer]                            │
│                      TLS termination                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │ HTTP (internal)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ TB3 — Private Network (trusted)                                 │
│                                                                 │
│                      [Web Server]                               │
│                  Auth check / routing                           │
│                    /           \                                │
│          auth request           notes request                   │
│               /                       \                         │
│     [Auth Service]              [Notes API]                     │
│   Login, JWT, sessions         CRUD, ownership check            │
│          |    \                      |                          │
│    user lookup \               note read/write                  │
│          |      reset token          |                          │
│          |           \               |                          │
│  ╔═══════════════════════════════╗   |                          │
│  ║  PostgreSQL Database          ║◄──┘                          │
│  ║  users + notes + reset_tokens ║                              │
│  ╚═══════════════════════════════╝                              │
│                    \                                            │
│                     └──reset token──► [Email Service] ─────────┼──► Internet
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Data Classification

| Data type | Sensitivity | Storage location |
|-----------|-------------|-----------------|
| User email addresses | PII — Medium | Database (users table) |
| Password hashes | Critical | Database (users table) |
| MFA secrets | Critical | Database (users table) |
| Note content | Sensitive — user defined | Database (notes table) |
| JWT tokens | Critical — session credential | Client memory / HttpOnly cookie |
| Password reset tokens | Critical — account takeover risk | Database (reset_tokens table) |

---

## 5. STRIDE Analysis

### 5.1 Browser / External Entity

> External entities receive S, T, R analysis only. I, D, E threats are modeled at the server components where impact is realized.

| ID | STRIDE | Threat | Attack Scenario | Risk |
|----|--------|--------|----------------|------|
| BR-S1 | Spoofing | Session token theft | Attacker steals JWT via XSS or browser extension and replays it from a different machine, impersonating the victim for the token's remaining lifetime. | High |
| BR-S2 | Spoofing | Credential phishing | Attacker clones the SecureNotes login page on a lookalike domain. Victim enters real credentials. No technical flaw in SecureNotes required. | High |
| BR-S3 | Spoofing | CSRF — forged state-changing requests | Attacker tricks authenticated user into visiting a malicious page that silently fires requests to SecureNotes. Browser automatically sends session cookie, making requests appear legitimate. | Medium |
| BR-T1 | Tampering | Request parameter manipulation / IDOR | Attacker modifies `note_id` or `user_id` in API requests via proxy. Server performs no ownership check, allowing modification of another user's data. | High |
| BR-T2 | Tampering | Stored XSS via note content | Attacker saves a note containing malicious script tags. When any user renders the note, script executes — stealing session tokens or redirecting to phishing pages. | High |
| BR-T3 | Tampering | TLS downgrade / MITM | On untrusted network, attacker performs SSL stripping if HSTS not enforced. Credentials and tokens transmitted in plaintext. | Medium |
| BR-R1 | Repudiation | Action deniability | User performs destructive actions then denies them. Without immutable server-side audit logs tied to authenticated sessions, no tamper-proof evidence exists. | Medium |
| BR-R2 | Repudiation | Shared device session abuse | Actions performed on shared device attributed to wrong user. Without device/IP correlation in logs, attribution is impossible. | Medium |

---

### 5.2 Load Balancer

| ID | STRIDE | Threat | Attack Scenario | Risk |
|----|--------|--------|----------------|------|
| LB-S1 | Spoofing | MITM via TLS misconfiguration | Attacker on same network intercepts traffic by exploiting weak TLS versions or expired certificates, impersonating the server. | Medium |
| LB-T1 | Tampering | Internal HTTP interception post-TLS termination | Attacker with internal network access intercepts unencrypted HTTP traffic between load balancer and web server, modifying requests or responses. | Medium |
| LB-R1 | Repudiation | Missing or inadequate access logs | No tamper-proof record of connections. After an attack, source and sequence of malicious requests cannot be reconstructed. | Medium |
| LB-I1 | Info Disclosure | Server version leakage via HTTP headers | Response headers expose software name and version (e.g. `Server: nginx/1.18`). Attacker identifies applicable CVEs. | Low |
| LB-I2 | Info Disclosure | Weak TLS cipher suite | Load balancer accepts outdated cipher suites. Attacker captures and decrypts traffic offline. | High |
| LB-D1 | Denial of Service | Volumetric DDoS | Attacker floods load balancer with millions of requests from a botnet, exhausting connection table. | High |
| LB-D2 | Denial of Service | Slowloris — slow HTTP connection exhaustion | Attacker opens thousands of connections sending data very slowly, exhausting connection slots without triggering volumetric thresholds. | Medium |
| LB-E1 | Elevation of Privilege | X-Forwarded-For header injection | Attacker injects `X-Forwarded-For: 127.0.0.1`. Backend trusts header for IP-based access control, granting access to admin endpoints. | High |

---

### 5.3 Web Server

| ID | STRIDE | Threat | Attack Scenario | Risk |
|----|--------|--------|----------------|------|
| WS-S1 | Spoofing | Session token replay | Attacker replays stolen JWT against web server, impersonating victim without knowing their password. | High |
| WS-S2 | Spoofing | Credential stuffing against login route | Attacker uses breached credential pairs. No rate limiting allows thousands of attempts per minute. | High |
| WS-T1 | Tampering | IDOR — unauthorized note modification | Attacker changes `note_id` in update request. Web server forwards without ownership verification. | High |
| WS-T2 | Tampering | Mass assignment — role escalation | Attacker includes `{"role":"admin"}` in request body. Server binds full request to user model granting admin rights. | High |
| WS-T3 | Tampering | SQL injection via unsanitized input | Attacker injects SQL into search fields. Direct string concatenation allows arbitrary data access or destruction. | High |
| WS-R1 | Repudiation | No audit log on sensitive actions | No structured logging of authentication events or data modifications. Attack sequence cannot be reconstructed post-incident. | Medium |
| WS-R2 | Repudiation | Logs stored locally — tampered post-compromise | Attacker deletes logs after compromising server. No SIEM forwarding means audit trail is permanently lost. | High |
| WS-I1 | Info Disclosure | Verbose error messages | Unhandled exceptions return stack traces with file paths, DB schema, and internal IPs. | Medium |
| WS-I2 | Info Disclosure | IDOR — reading another user's note | Same vulnerability as WS-T1 in read direction. Attacker reads any note by enumerating IDs. | High |
| WS-D1 | Denial of Service | No rate limiting on API endpoints | High-volume requests exhaust CPU and connection pool. | High |
| WS-D2 | Denial of Service | Large payload — memory exhaustion | No input size limit. Repeated oversized requests exhaust server memory. | Medium |
| WS-D3 | Denial of Service | ReDoS — catastrophic regex backtracking | Crafted input causes catastrophic backtracking in validation regex, freezing server thread. | Medium |
| WS-E1 | Elevation of Privilege | Directory traversal | Attacker sends `../../../etc/passwd` in file path parameter, reading sensitive system files. | High |
| WS-E2 | Elevation of Privilege | JWT algorithm confusion | Server accepts RS256 and HS256. Attacker changes header to HS256 and signs with public key, forging any role. | High |

---

### 5.4 Auth Service

| ID | STRIDE | Threat | Attack Scenario | Risk |
|----|--------|--------|----------------|------|
| AS-S1 | Spoofing | Credential stuffing | Attacker uses breached credential pairs from other services. Password reuse allows silent account compromise. | High |
| AS-S2 | Spoofing | JWT token theft and replay | Attacker steals valid JWT via XSS and replays it for the token's remaining lifetime. | High |
| AS-S3 | Spoofing | MFA fatigue attack | Attacker bombards user with MFA push notifications until they approve one out of frustration. (Uber 2022 pattern.) | High |
| AS-S4 | Spoofing | Insecure password reset token | Predictable, non-expiring, or reusable reset token allows account takeover without email access. | High |
| AS-T1 | Tampering | JWT payload tampering | Server fails to verify JWT signature. Attacker modifies `role: user` to `role: admin`. | High |
| AS-T2 | Tampering | JWT algorithm confusion | Server accepts RS256 and HS256. Attacker forges token signed with public key, granting arbitrary role. | Medium |
| AS-R1 | Repudiation | No audit log on auth events | Failed logins, resets, and token issuances unlogged. No evidence after credential stuffing attack. | High |
| AS-R2 | Repudiation | Logs tampered post-compromise | Auth logs on compromised server deleted. No SIEM forwarding means trail permanently lost. | High |
| AS-I1 | Info Disclosure | Weak password hashing (MD5/SHA1) | Database breach exposes passwords crackable with GPU rainbow tables in minutes. | High |
| AS-I2 | Info Disclosure | Username enumeration | Different error messages for wrong email vs wrong password allow attackers to confirm valid accounts. | High |
| AS-I3 | Info Disclosure | Reset token in URL | Token in URL query parameter logged in browser history, server logs, and proxies. | High |
| AS-I4 | Info Disclosure | Timing attack on password comparison | Non-constant-time comparison leaks information statistically across thousands of requests. | Medium |
| AS-D1 | Denial of Service | Login endpoint flooding | High-volume requests exhaust Auth Service CPU and connection pool. | High |
| AS-D2 | Denial of Service | Account lockout abuse | Attacker intentionally triggers lockout on all known accounts, denying access system-wide. | High |
| AS-D3 | Denial of Service | Password reset email flooding | Hundreds of reset requests flood victim inbox and may exhaust email service rate limits. | Medium |
| AS-E1 | Elevation of Privilege | JWT role escalation | Attacker modifies JWT payload to elevate from `user` to `admin`. No server-side role enforcement. | High |
| AS-E2 | Elevation of Privilege | Privilege escalation via registration | Registration endpoint accepts `role` field. Server binds full request body — attacker registers as admin. | High |

---

### 5.5 Notes API

| ID | STRIDE | Threat | Attack Scenario | Risk |
|----|--------|--------|----------------|------|
| NA-S1 | Spoofing | Direct API access bypassing web server | API performs no auth itself. Attacker calls internal API directly, bypassing all web server controls. | High |
| NA-S2 | Spoofing | JWT not re-validated at API layer | API trusts web server already validated JWT. Compromised web server or direct call with forged token grants full access. | High |
| NA-T1 | Tampering | IDOR — unauthorized note modification | Attacker changes `note_id` in update request. No ownership check — any note can be overwritten. | High |
| NA-T2 | Tampering | Mass deletion via iterated DELETE requests | Attacker iterates all note IDs firing DELETE. Without ownership checks, entire database destroyed permanently. | High |
| NA-R1 | Repudiation | No per-operation audit log | No record of which session performed which CRUD operation, when, or from where. | High |
| NA-R2 | Repudiation | Logs lost after compromise | Local logs deleted post-compromise. No SIEM means permanent audit trail loss. | High |
| NA-I1 | Info Disclosure | IDOR — unauthorized note read | Attacker enumerates sequential note IDs in GET requests, reading all users' private notes. | High |
| NA-I2 | Info Disclosure | Stored XSS via note content | Malicious script in note content executes in any viewer's browser — session theft at scale. | High |
| NA-I3 | Info Disclosure | API returns excess data fields | GET response includes internal fields exposing database schema to attacker. | Medium |
| NA-D1 | Denial of Service | Authenticated application-layer DoS | Authenticated attacker sends thousands of valid requests. Passes perimeter rate limits. Overwhelms API and database. | High |
| NA-D2 | Denial of Service | Oversized note content | No maximum note size. Repeated 100MB submissions exhaust database storage. | Medium |
| NA-E1 | Elevation of Privilege | Feature-level authorization bypass | Free-tier user accesses pro-tier endpoints. API checks authentication but not subscription tier. | Medium |
| NA-E2 | Elevation of Privilege | Admin endpoint accessible without admin role | Admin-only endpoints accessible to any authenticated user — role check missing. | High |

---

### 5.6 Database

> Data stores receive T, R, I, D analysis only.

| ID | STRIDE | Threat | Attack Scenario | Risk |
|----|--------|--------|----------------|------|
| DB-T1 | Tampering | SQL injection | Unsanitized user input in queries. Attacker reads, modifies, or destroys arbitrary data with crafted input. | High |
| DB-T2 | Tampering | Over-privileged service account | Notes API connects with account having DROP/CREATE permissions. SQL injection blast radius extends to full database destruction. | Medium |
| DB-R1 | Repudiation | No database audit logging | No log of queries, connections, or modifications. Post-breach forensics impossible. | High |
| DB-R2 | Repudiation | Logs not forwarded to SIEM | Local logs deleted post-compromise. Audit trail permanently lost. | High |
| DB-I1 | Info Disclosure | Weak password hashing | MD5/SHA1 hashed passwords crackable in minutes after breach. | High |
| DB-I2 | Info Disclosure | Sensitive data unencrypted at rest | Plaintext note content and PII immediately readable after any storage-level breach. | Medium |
| DB-I3 | Info Disclosure | Missing row and column level security | Any DBA can read all user data. No granular access control within the database. | High |
| DB-I4 | Info Disclosure | Unencrypted database backups | Backup files less protected than production. Breach of backup storage exposes entire database. | Medium |
| DB-I5 | Info Disclosure | Verbose database errors | Raw error messages reveal table names, column names, and query structure. | Medium |
| DB-D1 | Denial of Service | Connection pool exhaustion | Flood of requests exhausts PostgreSQL connection limit — all queries fail. | High |
| DB-D2 | Denial of Service | Oversized data exhausting storage | No note size limit. Disk exhaustion causes write failures for all users. | Medium |
| DB-D3 | Denial of Service | Expensive query DoS | Wildcard-heavy search queries cause full-table scans, pegging CPU at 100% with a single request. | Medium |

---

### 5.7 Email Service

> External entities receive S, T, R analysis only.

| ID | STRIDE | Threat | Attack Scenario | Risk |
|----|--------|--------|----------------|------|
| EM-S1 | Spoofing | Domain spoofing — fake reset emails | Attacker sends emails appearing from securenotes.com pointing to phishing login page. No SPF/DKIM/DMARC means indistinguishable from legitimate mail. | High |
| EM-S2 | Spoofing | Email header injection | Unsanitized user input in email headers. Attacker injects `BCC:` header via newline characters, silently copying reset tokens to attacker-controlled address. | High |
| EM-T1 | Tampering | Reset token interception — missing TLS | Email transmitted without TLS between mail servers. Reset token readable in plaintext on network path. | Medium |
| EM-T2 | Tampering | Email content modified in transit without DKIM | Without DKIM, intercepted email reset link can be replaced with phishing URL undetected. | High |
| EM-T3 | Tampering | Guessable reset token — IDOR on accounts | Predictable tokens (timestamp, sequential ID) allow attacker to generate valid tokens for arbitrary accounts without email access. | High |
| EM-R1 | Repudiation | No log of reset emails sent | No record of which addresses received tokens or when. Attack via reset flow leaves no trail. | Medium |
| EM-R2 | Repudiation | Logs not retained for compliance period | Logs deleted before PIPEDA-required retention period. Regulatory investigation cannot be supported. | Medium |

---

## 6. Risk Register

> Sorted by DREAD score descending. D=Damage, R=Reproducibility, E=Exploitability, A=Affected users, D2=Discoverability.

| ID | Threat | D | R | E | A | D2 | Score | Risk |
|----|--------|---|---|---|---|-----|-------|------|
| BR-T1 | IDOR — request parameter manipulation | 3 | 3 | 3 | 3 | 3 | **3.0** | 🔴 High |
| BR-T2 | Stored XSS via note content | 3 | 3 | 3 | 3 | 3 | **3.0** | 🔴 High |
| LB-D1 | Volumetric DDoS | 3 | 3 | 3 | 3 | 3 | **3.0** | 🔴 High |
| LB-E1 | X-Forwarded-For header injection | 3 | 3 | 3 | 3 | 3 | **3.0** | 🔴 High |
| AS-S1 | Credential stuffing | 3 | 3 | 3 | 3 | 3 | **3.0** | 🔴 High |
| AS-D2 | Account lockout abuse | 3 | 3 | 3 | 3 | 3 | **3.0** | 🔴 High |
| NA-T1 | IDOR — unauthorized note modification | 3 | 3 | 3 | 3 | 3 | **3.0** | 🔴 High |
| NA-I2 | Stored XSS via note content | 3 | 3 | 3 | 3 | 3 | **3.0** | 🔴 High |
| DB-T1 | SQL injection | 3 | 3 | 3 | 3 | 3 | **3.0** | 🔴 High |
| BR-S1 | Session token theft | 3 | 3 | 3 | 2 | 3 | **2.8** | 🔴 High |
| AS-I2 | Username enumeration | 2 | 3 | 3 | 3 | 3 | **2.8** | 🔴 High |
| NA-D1 | Application-layer DoS | 3 | 3 | 3 | 3 | 2 | **2.8** | 🔴 High |
| EM-S1 | Domain spoofing | 3 | 3 | 3 | 3 | 2 | **2.8** | 🔴 High |
| AS-S3 | MFA fatigue attack | 3 | 3 | 3 | 2 | 2 | **2.6** | 🔴 High |
| BR-S2 | Credential phishing | 3 | 3 | 3 | 2 | 2 | **2.6** | 🔴 High |
| AS-I1 | Weak password hashing | 3 | 3 | 3 | 3 | 1 | **2.6** | 🔴 High |
| WS-T1 | IDOR — note modification | 3 | 3 | 3 | 3 | 3 | **3.0** | 🔴 High |
| WS-E2 | JWT algorithm confusion | 3 | 2 | 2 | 3 | 2 | **2.4** | 🟡 Medium |
| AS-T2 | JWT algorithm confusion | 3 | 2 | 2 | 3 | 2 | **2.4** | 🟡 Medium |
| NA-S1 | Direct API access bypass | 3 | 2 | 2 | 3 | 2 | **2.4** | 🟡 Medium |
| NA-E1 | Feature-level authorization bypass | 2 | 3 | 3 | 2 | 2 | **2.4** | 🟡 Medium |
| LB-S1 | MITM via TLS misconfiguration | 3 | 1 | 2 | 3 | 2 | **2.2** | 🟡 Medium |
| LB-I1 | Server version header leakage | 1 | 3 | 3 | 1 | 3 | **2.2** | 🟡 Medium |
| BR-S3 | CSRF — forged requests | 3 | 2 | 2 | 2 | 2 | **2.2** | 🟡 Medium |
| AS-S4 | Insecure password reset token | 3 | 2 | 2 | 1 | 2 | **2.0** | 🟡 Medium |
| DB-T2 | Over-privileged service account | 3 | 2 | 1 | 3 | 1 | **2.0** | 🟡 Medium |
| DB-I2 | Sensitive data unencrypted at rest | 3 | 2 | 1 | 3 | 1 | **2.0** | 🟡 Medium |
| DB-I4 | Unencrypted database backups | 3 | 2 | 1 | 3 | 1 | **2.0** | 🟡 Medium |
| EM-S2 | Email header injection | 3 | 2 | 2 | 1 | 2 | **2.0** | 🟡 Medium |
| EM-T1 | Reset token interception — no TLS | 3 | 1 | 2 | 1 | 1 | **1.6** | 🟡 Medium |
| LB-I1 | Server version header leakage | 1 | 3 | 3 | 1 | 3 | **2.2** | 🟡 Medium |
| WS-I1 | Verbose error messages | 2 | 3 | 3 | 2 | 2 | **2.4** | 🟡 Medium |
| AS-I4 | Timing attack on password comparison | 2 | 1 | 1 | 3 | 1 | **1.6** | 🟡 Medium |

---

## 7. Mitigation Register

### Priority 1 — Fix Immediately (High Risk, Score ≥ 2.5)

| Threat IDs | Threat | Control type | Control | Where |
|-----------|--------|-------------|---------|-------|
| BR-T1, NA-T1, NA-I1, WS-T1 | IDOR | Prevent | Server-side ownership check on every CRUD operation: `note.owner_id == token.user_id` | Notes API |
| BR-T1, NA-T1 | IDOR | Prevent | Use UUIDs instead of sequential integers for note IDs — removes enumeration | Database schema |
| BR-T1, NA-T1 | Detect | Alert on users accessing note IDs outside their ownership list | SIEM / WAF |
| BR-T2, NA-I2 | Stored XSS | Prevent | HTML encode all user-supplied content before rendering | Web server |
| BR-T2, NA-I2 | Prevent | Content Security Policy header: `script-src 'self'` blocking inline scripts | Web server |
| BR-T2, NA-I2 | Prevent | Sanitize note content server-side on input using allowlist | Notes API |
| DB-T1, WS-T3 | SQL injection | Prevent | Parameterized queries / prepared statements on all database calls — no string concatenation ever | All DB-connected services |
| DB-T1 | Mitigate | Least privilege DB service account — READ/WRITE on notes and users tables only, no DDL | Database config |
| DB-T1 | Detect | WAF rules detecting SQL injection patterns | WAF |
| AS-S1, AS-D2 | Credential stuffing + lockout abuse | Prevent | MFA required for all accounts | Auth service |
| AS-S1 | Mitigate | Progressive delays on failed logins — not hard lockout (prevents abuse) | Auth service |
| AS-S1 | Detect | Alert on distributed failed login patterns across multiple IPs | SIEM |
| AS-S3 | MFA fatigue | Prevent | Number matching MFA — user enters code shown on screen, not just approves push | Auth service / MFA provider |
| AS-S3 | Prevent | Limit push notifications to 3 per session, then require alternative factor | Auth service |
| AS-I1, DB-I1 | Weak hashing | Prevent | Use Argon2id with appropriate work factor for all password storage | Auth service |
| AS-I2 | Username enumeration | Prevent | Return identical message for wrong email and wrong password: "Invalid email or password" | Auth service |
| AS-I2 | Prevent | Constant-time comparison for all authentication checks | Auth service |
| LB-D1 | DDoS | Prevent | DDoS mitigation service (Cloudflare, AWS Shield) | Load balancer / CDN |
| LB-D1 | Mitigate | Autoscaling under load | Infrastructure |
| LB-E1 | Header injection | Prevent | Load balancer strips and rewrites `X-Forwarded-For` — never trusts client-supplied value | Load balancer config |
| BR-S1 | Token theft | Prevent | `HttpOnly` + `Secure` cookie flags — prevent JavaScript access to tokens | Web server |
| BR-S1 | Mitigate | Short JWT expiry (15 minutes) + refresh token rotation | Auth service |
| EM-S1 | Domain spoofing | Prevent | SPF record authorizing approved sending servers | DNS config |
| EM-S1 | Prevent | DKIM signing on all outbound email | Email provider config |
| EM-S1 | Prevent | DMARC policy set to `reject` | DNS config |
| EM-T3 | Guessable token | Prevent | Cryptographically random reset tokens — minimum 32 bytes from CSPRNG | Auth service |
| EM-T3 | Prevent | Token expires in 15 minutes, single use, invalidated immediately after click | Auth service |

### Priority 2 — Fix This Quarter (Medium Risk, Score 1.5–2.4)

| Threat IDs | Threat | Control | Where |
|-----------|--------|---------|-------|
| WS-E2, AS-T2 | JWT algorithm confusion | Pin JWT algorithm to RS256 in server configuration — reject all other algorithms | Auth service |
| NA-S1, NA-S2 | Direct API bypass | Notes API validates JWT independently on every request — never relies on upstream validation | Notes API |
| DB-I2 | Unencrypted data | AES-256 encryption at rest for database files | Database config |
| DB-I4 | Unencrypted backups | Encrypt backup files before storage — keys stored separately from backup files | Backup system |
| DB-I3 | Missing row-level security | Implement PostgreSQL row-level security policies | Database config |
| AS-S4 | Insecure reset token | Enforce token expiry and single-use invalidation (see Priority 1 EM-T3 — same control) | Auth service |
| EM-S2 | Header injection | Strip newline characters from all user-supplied fields used in email headers | Auth service |
| WS-R2, AS-R2, NA-R2, DB-R2 | Log tampering | Forward all application and database logs to centralized SIEM in real time | All services |
| LB-R1, WS-R1, NA-R1, DB-R1 | Missing audit logs | Structured logging: user ID + action + resource ID + timestamp + IP on every significant operation | All services |
| LB-I2 | Weak cipher suites | Configure load balancer to accept TLS 1.2+ only with strong cipher suites (disable RC4, 3DES) | Load balancer config |
| NA-E1 | Feature authorization | Enforce subscription tier check on all pro-tier endpoints | Notes API |
| NA-D1 | App-layer DoS | Per-user rate limiting on note creation and update endpoints | Notes API / API gateway |
| WS-D1 | Endpoint flooding | Rate limiting on all authentication and write endpoints | Web server / WAF |

### Universal Controls — Apply to All Components

These controls address systemic risks across the entire application and should be implemented as baseline requirements:

| Control | Addresses | Priority |
|---------|-----------|----------|
| MFA on all user accounts | AS-S1, AS-S3, BR-S2 | Immediate |
| HTTPS everywhere + HSTS with long max-age | BR-T3, LB-S1, EM-T1 | Immediate |
| Parameterized queries — no exceptions | DB-T1, WS-T3 | Immediate |
| Output encoding + CSP header | BR-T2, NA-I2 | Immediate |
| Centralized immutable logging + SIEM forwarding | All R threats | This quarter |
| Rate limiting on all public endpoints | WS-D1, AS-D1, NA-D1 | This quarter |
| Least privilege on all service accounts | DB-T2 | This quarter |
| Encryption at rest + encrypted backups | DB-I2, DB-I4 | This quarter |
| Generic error messages — no stack traces in production | WS-I1, DB-I5 | This quarter |
| Secrets management — no credentials in code or config files | All components | Immediate |

---

## 8. Conclusion and Next Steps

### Summary of Findings

This threat model identified **46 threats** across 7 components of the SecureNotes web application. The most significant finding is a systemic **absence of server-side authorization checks** — the same IDOR vulnerability appears across the browser, web server, and Notes API layers, indicating a design-level gap rather than an isolated implementation issue. This pattern suggests authorization was not considered during the initial design phase and should be addressed at the architecture level, not patched component by component.

The second systemic finding is **inadequate logging and monitoring** — repudiation threats appear in every component, indicating that the system would be unable to support incident response or forensic investigation following a breach.

### Recommended Remediation Order

1. **Immediate (this sprint):** IDOR ownership checks, parameterized queries, XSS output encoding + CSP, MFA enforcement, Argon2id password hashing
2. **Short term (this quarter):** Centralized SIEM logging, JWT algorithm pinning, API-level rate limiting, encryption at rest, DMARC/DKIM/SPF configuration
3. **Medium term (next quarter):** Row-level database security, backup encryption, subscription tier authorization, privacy threat assessment (LINDDUN)

### Review Cadence

Threat models are point-in-time assessments. This document should be reviewed and updated:

- When a new component or data flow is added to the system
- When authentication or authorization logic changes
- When a security incident occurs
- Annually at minimum as part of a security review cycle

### Suggested Next Assessments

| Assessment | Rationale |
|------------|-----------|
| LINDDUN privacy threat model | PIPEDA / Bill C-27 compliance — PII handling requires dedicated privacy analysis |
| Cloud infrastructure threat model | AWS/Azure layer not covered here — IAM, VPC, S3 bucket policy, and secrets management require separate assessment |
| Penetration test | Validate findings from this threat model with hands-on exploitation — particularly IDOR and injection findings |
| Dependency audit | Third-party libraries introduce supply chain risk not covered in this model |

---

## Appendix A — STRIDE Quick Reference

| Letter | Threat | Violates | Key question |
|--------|--------|----------|-------------|
| S | Spoofing | Authentication | Can an attacker pretend to be someone else? |
| T | Tampering | Integrity | Can data be modified without authorization? |
| R | Repudiation | Non-repudiation | Can an action be denied because no record exists? |
| I | Information Disclosure | Confidentiality | Can sensitive data reach unauthorized parties? |
| D | Denial of Service | Availability | Can the service be made unavailable? |
| E | Elevation of Privilege | Authorization | Can a user gain more access than permitted? |

## Appendix B — DREAD Scoring Reference

| Score | Damage | Reproducibility | Exploitability | Affected Users | Discoverability |
|-------|--------|----------------|---------------|----------------|----------------|
| 1 | Minimal | Rare conditions | Advanced skill | Individual | Source code only |
| 2 | Significant | Some effort | Some skill + tools | Some users | Monitoring reveals |
| 3 | Severe / full compromise | Always reproducible | Trivial — no skill | All users | Obvious to any attacker |

## Appendix C — References

- STRIDE methodology: [Microsoft Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- OWASP Top 10 (2021): [owasp.org/Top10](https://owasp.org/www-project-top-ten/)
- OWASP Threat Modeling Cheat Sheet: [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- DREAD scoring: [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- PIPEDA — Canada's privacy law: [priv.gc.ca](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/)
- Adam Shostack — Threat Modeling: Designing for Security (Wiley, 2014)

---

*This threat model was produced as a portfolio demonstration of STRIDE-based threat modeling methodology applied to a hypothetical web application. All components and scenarios are fictional.*
