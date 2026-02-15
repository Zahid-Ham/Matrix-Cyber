# CVSS v3.1 Scoring Methodology

## Overview

This system calculates the **CVSS v3.1 Base Score** for discovered vulnerabilities. By collecting granular security context from our detection agents, we generate precise, deterministic scores rather than relying on generic severity bands. This approach mirrors the internal logic of enterprise-grade scanners like Nessus and Qualys.

> **Note:** This implementation focuses on the **Base Score**. Temporal and Environmental metrics may be layered in future versions to further refine risk analysis based on exploit maturity and specific environmental factors.

---

## Metric Determination Logic

Our calculator uses a context-driven approach where specific findings trigger deterministic metric values.

### 1. Attack Vector (AV)
- **Network (N)**: Vulnerabilities exploitable over the network (e.g., SQLi, XSS). Default for web flaws.
- **Local (L)**: Requires local shell access or file system manipulation (e.g., local file inclusion without upload).
- **Physical (P)**: Requires physical access (rare in web context).

### 2. Attack Complexity (AC)
- **Low (L)**: The attack is repeatable and requires no special conditions. (Most web vulnerabilities).
- **High (H)**: Exploitation requires non-deterministic conditions (race windows, specific timing, environmental dependencies) or complex bypass chains (e.g., evading a WAF or double-submit cookie). **Simple keyword bypasses do not qualify as High.**

### 3. Privileges Required (PR)
- **None (N)**: Attack can be performed without authentication (e.g., login page SQLi).
- **Low (L)**: Requires a standard user account (e.g., Stored XSS in a user profile).
- **High (H)**: Requires administrative privileges.

> **Correction Note:** Privileges Required weighting is automatically adjusted based on Scope (Unchanged vs. Changed), per the official CVSS v3.1 specification.

### 4. User Interaction (UI)
- **None (N)**: Vulnerability triggers without user action (e.g., SQLi, Command Injection).
- **Required (R)**: Victim must interact with the payload (e.g., Reflected XSS, CSRF).

### 5. Scope (S)
- **Unchanged (U)**: Impact is limited to the vulnerable component (e.g., SQLi affecting the DB used by the app).
- **Changed (C)**: The vulnerable component breaches a security boundary (e.g., XSS execution in a user's browser, SSRF accessing internal cloud metadata). **This is the single most significant factor in high-severity scoring.**

### 6. Impact Metrics (C/I/A)
- **Confidentiality (C)**:
  - **High**: Total disclosure of data (e.g., dumping user table).
  - **Low**: Partial disclosure (e.g., tech stack version).
- **Integrity (I)**:
  - **High**: Total loss of integrity (e.g., write access to DB).
  - **Low**: Limited modification (e.g., modifying own profile data).
- **Availability (A)**:
  - **High**: Total denial of service (e.g., crashing the server).
  - **Low**: Partial/intermittent performance impact.

---

## Verdict & Philosophy

> **“CVSS reflects potential impact severity, while Matrix confidence scoring reflects detection certainty — both are reported independently to avoid severity inflation.”**

This distinction ensures we do not degrade a Critical vulnerability to Medium simply because we are unsure if it exists. A specific SQL Injection pattern is always a **Critical** risk (CVSS ~9.8), even if our detection confidence is only 75%.

## Output Artifacts

For every finding, we store and expose the full **CVSS Vector String**, allowing for easy integration with bug bounty platforms and enterprise vulnerability management systems.

**Example Vector:**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

## Implementation Details

The scoring engine is isolated in `backend/scoring/` and imported by individual security agents. Each agent constructs a `VulnerabilityContext` object populated with evidence-based findings, which is then passed to the `CVSSCalculator` to derive the final score and justification.
