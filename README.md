# HuntCyberArk - CyberArk Security Audit Suite

A comprehensive PowerShell-based security assessment tool for CyberArk Privileged Access Management (PAM) platforms. **Designed for offensive security professionals, red teamers, and penetration testers.**

**Version 4.3** - This tool is designed to run **REMOTELY** against CyberArk servers via network. It does NOT need to be executed on the CyberArk servers themselves. All checks are performed over the network using PVWA API, port scanning, and web testing.

This tool performs **250+ security checks** including CIS Benchmark compliance, vendor best practices, blackbox testing, network security analysis, CVE-specific vulnerability checks (including 2025 CVEs), machine identity security, secrets management, zero standing privileges (ZSP) assessment, identity governance, host security assessments, and enhanced security checks inspired by CyberArk's open-source security tools (zBang, CYBRHardeningCheck, Evasor, Conjur).

## Key Features

| Feature | Description |
|---------|-------------|
| **Remote Auditing** | All checks performed remotely via network - no need to install on CyberArk servers |
| **OPSEC Mode** | Stealth scanning with configurable delays, jitter, and reduced detection footprint |
| **Proxy Support** | Route all traffic through Burp Suite, ZAP, or other intercepting proxies |
| **Timing Attacks** | Detect user enumeration and blind injection via response timing analysis |
| **JWT Security** | Test for none algorithm bypass, key confusion, weak signing algorithms |
| **WebSocket Testing** | Discover real-time endpoints and test for Cross-Site WebSocket Hijacking |
| **WAF Evasion** | Test encoding bypasses, HTTP Parameter Pollution, request smuggling |
| **User-Agent Rotation** | Randomized or custom User-Agent strings to evade fingerprinting |
| **Parallel Execution** | Optional parallel execution for faster scans |
| **Quiet Mode** | Reduced console output for automation and scripting |
| **Credential Security** | Secure handling with memory cleanup after use |
| **Comprehensive Reporting** | HTML dashboard, 7 CSV files, and structured JSON for programmatic use |

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Audit Phases & Authentication Requirements](#audit-phases--authentication-requirements)
- [Features](#features)
- [Usage](#usage)
- [Parameters](#parameters)
- [Output](#output)
  - [HTML Report](#1-html-report-interactive-dashboard)
  - [CSV Reports](#2-csv-reports-7-separate-files)
  - [JSON Report](#3-json-report-structured-data)
  - [Risk Scoring](#risk-scoring)
- [Security Considerations](#security-considerations)
- [Known Vulnerable CyberArk Versions](#known-vulnerable-cyberark-versions)
- [Troubleshooting](#troubleshooting)
- [References](#references)

## Prerequisites

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| PowerShell | 7.0 | 7.x (latest) |
| .NET Framework | 4.5 | 4.8+ |
| Operating System | Windows 10/Server 2016 | Windows 11/Server 2022 |
| Memory | 2 GB available | 4 GB available |

### Required Access

| Audit Phase | Access Required |
|-------------|-----------------|
| Phase 1 (Unauthenticated) | Network access to PVWA (HTTPS/443) |
| Phase 2 (Authenticated) | CyberArk API credentials with Vault Admin or Auditor role |
| Phase 3 (Host Security) | Local administrator on CyberArk server (optional - use `-IncludeLocalHostChecks`) |

### Network Requirements

- Outbound HTTPS (TCP/443) access to the PVWA server
- For comprehensive port scanning: access to ports 1858, 1859, 3389, 5985, 5986
- DNS resolution for the target PVWA hostname

## Installation

### No External Tools Required

This script is **fully self-contained** and uses only native PowerShell and .NET Framework capabilities. No additional tools or modules need to be installed.

The script leverages:
- **Native .NET Classes**: `System.Net.Sockets.TcpClient`, `System.Net.Security.SslStream` for network and TLS analysis
- **Built-in Cmdlets**: `Invoke-WebRequest`, `Invoke-RestMethod` for HTTP/API testing
- **Windows Management**: `Get-WmiObject`, `Get-CimInstance`, `Get-Service` for host security checks

### Step 1: Verify PowerShell Version

Open PowerShell and run:

```powershell
$PSVersionTable.PSVersion
```

Ensure the Major version is **7 or higher**. If not, [download PowerShell 7.x](https://github.com/PowerShell/PowerShell/releases).

> **Note:** This script requires PowerShell 7.0 or later. Windows PowerShell 5.1 is not supported.

### Step 2: Download the Script

**Option A: Clone the repository**

```powershell
git clone https://github.com/your-org/HuntCyberArk.git
cd HuntCyberArk
```

**Option B: Download directly**

```powershell
# Download to current directory
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/your-org/HuntCyberArk/main/CyberArk-Security-Audit.ps1" -OutFile "CyberArk-Security-Audit.ps1"
```

### Step 3: Set Execution Policy (if needed)

If you encounter script execution errors, temporarily allow script execution:

```powershell
# Check current policy
Get-ExecutionPolicy

# Set for current session only (recommended)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Or unblock the downloaded script
Unblock-File -Path .\CyberArk-Security-Audit.ps1
```

### Step 4: Verify SSL/TLS Configuration

For proper TLS testing, ensure your PowerShell session supports TLS 1.2+:

```powershell
# Enable TLS 1.2 (recommended to add to your profile)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

### Step 5: Test Connectivity

Verify you can reach the PVWA server:

```powershell
# Test basic connectivity
Test-NetConnection -ComputerName pvwa.domain.com -Port 443

# Test HTTPS endpoint
Invoke-WebRequest -Uri "https://pvwa.domain.com/PasswordVault/" -UseBasicParsing -TimeoutSec 10
```

### Optional: Install PowerShell 7 (Recommended)

PowerShell 7 provides improved performance and better TLS support:

```powershell
# Windows (winget)
winget install Microsoft.PowerShell

# Windows (manual)
# Download from: https://github.com/PowerShell/PowerShell/releases
```

## Audit Phases & Authentication Requirements

The audit runs in three phases, each with different authentication requirements:

### Phase 1: Unauthenticated Checks (No credentials required)
External/blackbox testing that can be run without any credentials:
- Network security (port scanning, vault port exposure)
- TLS/SSL configuration and certificate analysis
- Blackbox web security (exposed endpoints, information disclosure)
- PVWA security headers and cookie security
- CVE-specific vulnerability testing (including 2025 CVEs)
- API security testing (unauthenticated endpoints)
- Component version detection
- Timing attack detection
- JWT/OAuth2 security testing
- WebSocket endpoint discovery
- WAF evasion testing

**Use Case**: Penetration testing, external security assessments, quick reconnaissance

### Phase 2: Authenticated Checks (CyberArk API credentials required)
Deep configuration audits requiring CyberArk REST API access:
- Safe configurations and permissions
- Account and credential management settings
- Platform configurations
- User accounts and vault permissions
- Authentication method settings
- Component health status
- Master Policy, PSM, CPM, PTA configurations
- Machine Identity Security (service accounts, AppIDs)
- Secrets Management (CP/CCP configuration)
- Zero Standing Privileges (JIT access assessment)
- Identity Governance (orphaned identities, permission drift)
- Cloud Security (AWS/Azure/GCP integration)
- Disaster Recovery (DR Vault, HA cluster health)
- Compliance Mapping (NIST, SOC 2, PCI-DSS)
- Secrets Hub integration (cloud-native secrets sync)
- Remote Access / Alero security
- Kubernetes secrets security
- DevSecOps pipeline security
- Privilege Cloud / SaaS-specific checks
- CyberArk Identity / Idaptive integration
- Custom plugins security
- Backup security
- HSM integration
- PTA advanced detection
- Third-party integrations (SIEM, ITSM, SOAR)
- Operational hygiene metrics
- Attack path simulation
- Supply chain integrity
- Network segmentation

**Required Permissions**: Vault Admin or Auditor role recommended

### Phase 3: Host Security Checks (Optional - Local admin on CyberArk server)
Windows host hardening checks requiring local execution. **These are skipped by default** for remote audits since this tool is designed to run remotely.

To enable host checks, use `-IncludeLocalHostChecks` **only when running the script directly on a CyberArk server**.

Host checks include:
- Windows Firewall configuration
- CyberArk service account settings
- Credential caching (WDigest, LSA Protection)
- Windows Event Log configuration
- Antivirus/EDR status
- CyberArk service health
- Server hardening (CYBRHardeningCheck-inspired)
- Component-specific hardening (Vault, PSM, PVWA, CPM)
- Application control bypass detection (Evasor-inspired)

**Requirement**: Run script directly on CyberArk server with admin rights and `-IncludeLocalHostChecks`

## Features

### Security Check Categories

| Category | Control Prefix | Description |
|----------|---------------|-------------|
| CIS Benchmark | 1.x - 8.x | CIS CyberArk PAM Benchmark v1.0 compliance |
| Vendor Best Practices | V1.x - V8.x | CyberArk security hardening recommendations |
| Blackbox Testing | BB1 - BB11 | External security testing without authentication |
| Network Security | NET1 - NET7 | Port scanning and network exposure analysis |
| TLS Security | TLS1 - TLS4 | SSL/TLS configuration and cipher analysis |
| CVE Checks | CVE1 - CVE15 | Known CyberArk vulnerability detection (2021-2025) |
| Security Bulletins | CA25-x | CyberArk security bulletin checks |
| API Security | API1 - API5 | REST API security testing |
| Host Security | HOST1 - HOST5 | Windows host hardening checks |
| **Advanced Security** | | |
| Machine Identity | MID1 - MID9 | Service account, AppID, and AIM Provider security |
| Secrets Management | SEC1 - SEC14 | Credential Provider/CCP and Conjur security |
| Zero Standing Privileges | ZSP1 - ZSP5 | JIT access and privilege assessment |
| Identity Governance | IGA1 - IGA8 | Lifecycle and permission management |
| EPM Integration | EPM1 - EPM6 | Endpoint Privilege Manager checks |
| Cloud Security | CLD1 - CLD6 | Secure Cloud Access checks |
| Disaster Recovery | DR1 - DR5 | HA and DR configuration |
| Compliance Mapping | COMP1 - COMP4 | NIST, SOC2, PCI-DSS alignment |
| Audit Logging | AUD1 - AUD4 | SIEM and logging validation |
| **CyberArk Tools Integration** | | |
| AD Security (zBang) | AD1 - AD7 | Shadow admins, Skeleton Key, SID History, SPNs, Kerberos delegation |
| Server Hardening (CYBRHardeningCheck) | HARD1 - HARD8 | Server roles, audit policy, RDP, registry, filesystem |
| Vault Hardening | VAULT1 - VAULT6 | NIC hardening, static IP, domain membership, firewall, certificates |
| PSM Hardening | PSMH1 - PSMH10 | AppLocker, RDP users, drives hidden, RDS, SMB |
| PVWA Hardening | PVWAH1 - PVWAH8 | WebDAV, IIS config, app pool, MIME types, cryptography |
| CPM Hardening | CPMH1 - CPMH4 | FIPS, DEP, credential files, service accounts |
| Application Control (Evasor) | APPCTL1 - APPCTL5 | DLL injection/hijacking, AppLocker bypasses |
| **Security Posture Expansion** | | |
| Secrets Hub | SH1 - SH6 | Cloud secrets sync health, latency, version drift |
| Remote Access / Alero | RA1 - RA6 | Vendor invitation, MFA, session limits, device binding |
| Kubernetes Secrets | K8S1 - K8S8 | Secrets Provider, RBAC, pod security, Conjur follower |
| DevSecOps Pipeline | DSO1 - DSO6 | CI/CD secrets retrieval, sprawl detection, short-lived tokens |
| Privilege Cloud | PC1 - PC5 | Connector health, tenant isolation, ISP integration |
| CyberArk Identity | IDN1 - IDN6 | SSO integration, adaptive MFA, session risk scoring |
| Custom Plugins | PLG1 - PLG5 | PSM/CPM plugin security, digital signatures, ACLs |
| Backup Security | BKP1 - BKP5 | Encryption, file permissions, restoration testing |
| HSM Integration | HSM1 - HSM4 | HSM health, key wrapping, partition isolation |
| PTA Deep Dive | PTAD1 - PTAD6 | Custom rules, ML quality, UEBA, alert fatigue |
| Third-Party Integration | TPI1 - TPI5 | SIEM/ITSM/SOAR connectivity, credential health |
| Operational Hygiene | OPS1 - OPS8 | Onboarding queue, CPM failures, PSM metrics, license |
| Attack Path Simulation | APS1 - APS6 | PtH, NTLM relay, Kerberoasting, privilege escalation |
| Supply Chain Integrity | SCI1 - SCI5 | File hashes, patch currency, code signing |
| Network Segmentation | NSG1 - NSG5 | Vault isolation, component ACLs, East-West monitoring |

### Detailed Check Coverage

#### CIS Benchmark Compliance (1.x - 8.x)
- Dedicated Vault server configuration
- Firewall rules and service hardening
- Master Policy password settings
- Password complexity and expiration
- Safe access and permissions
- Automatic password management
- MFA and LDAP security
- PSM session recording
- Audit logging and SIEM integration
- TLS configuration

#### Vendor Best Practices (V1.x - V8.x)
- Master Policy settings (validity period, one-time passwords, exclusive access)
- PSM recording, keystroke logging, clipboard restrictions
- Account discovery and onboarding rules
- PTA anomaly detection
- Connection component security
- Linked accounts (logon/reconcile)
- PVWA HTTP security headers
- CPM service configuration

#### Blackbox Security Testing (BB1 - BB11)
- Exposed sensitive endpoints (Swagger, API docs, admin pages)
- Information disclosure (version, stack traces)
- Default credential testing
- Dangerous HTTP methods (PUT, DELETE, TRACE)
- Cookie security attributes (Secure, HttpOnly, SameSite)
- CORS misconfiguration
- Backup/config file exposure
- Directory listing
- SSL/TLS certificate issues
- Rate limiting detection
- Known vulnerability patterns

#### Network Security (NET1 - NET7)
- **Port Scanning**: Comprehensive scan of CyberArk-specific ports
  - PVWA (443, 80)
  - Vault (1858, 1859)
  - Administrative (RDP, SSH, WinRM)
  - Database (MSSQL, MySQL, PostgreSQL, Oracle)
  - Protocols (SMB, NetBIOS, LDAP, SNMP)
- Vault port (1858) security analysis
- DNS security configuration

#### TLS/SSL Security (TLS1 - TLS4)
- Weak protocol detection (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- Cipher suite strength analysis
- Weak cipher detection (RC4, DES, 3DES, MD5, NULL, EXPORT)
- Certificate validation
- Key size verification
- Signature algorithm check

#### CVE-Specific Vulnerability Checks (CVE1 - CVE15)
- **CVE-2021-31796**: SSRF vulnerability testing
- **CVE-2022-22536**: Authentication bypass patterns
- **CVE-2023-43903**: XSS vulnerability patterns
- **CVE-2024-42340**: DOM XSS detection
- **CVE-2024-42339**: HTML injection testing
- **CVE-2024-38996**: PVWA prototype pollution
- **CVE-2025-22270**: EPM HTML injection in role management
- **CVE-2025-22271**: EPM X-Forwarded-For spoofing
- **CVE-2025-22272**: EPM XSS via modalDlgMsgInternal
- **CVE-2025-22273**: EPM password change brute force
- **CVE-2025-22274**: EPM application definition injection
- **CVE-2025-49827**: Secrets Manager IAM authenticator bypass (Critical)
- **CVE-2025-49828**: Secrets Manager remote code execution
- **CVE-2025-49831**: Secrets Manager network bypass
- Security Bulletins: CA25-25, CA25-29, CA25-32, CA25-34, CA25-35
- Additional checks: Path traversal, Log4Shell indicators, legacy API versions

#### API Security Testing (API1 - API5)
- **BOLA/IDOR**: Broken object level authorization
- **Injection Testing**: SQL injection, LDAP injection
- **Mass Assignment**: Privileged property injection
- **API Versioning**: Legacy API endpoint detection

#### Host Security (HOST1 - HOST5)
*Requires `-IncludeLocalHostChecks` and local execution on CyberArk server*
- Windows Firewall configuration
- CyberArk service account analysis
- Credential caching (WDigest, cached logons)
- LSA Protection verification
- Event log configuration
- Audit policy verification
- Antivirus/EDR status
- CyberArk service health

#### Advanced Security Checks
- Component version detection and CVE mapping
- Session security (fixation, concurrent sessions)
- Header injection (Host header, CRLF)
- XXE vulnerability testing on SOAP endpoints

#### Machine Identity Security (MID1 - MID9)
- Service account enumeration and privilege analysis
- Machine identity password rotation validation
- Over-privileged service account detection
- Certificate-based authentication configuration
- AppID security validation (allowed machines, OS user restrictions)
- Stale machine identity detection
- AIM Provider deployment verification
- AIM Provider configuration security
- AIM Provider vault connectivity

#### Secrets Management (SEC1 - SEC14)
- Credential Provider (CP/CCP) deployment verification
- AppID authentication method strength analysis
- Allowed machines configuration validation
- Cache TTL and refresh interval settings
- CCP TLS/mTLS configuration
- Secret rotation policy enforcement
- Orphan/unmanaged secrets detection
- Credential sprawl analysis
- Conjur integration health
- MAML policy validation
- Authenticator configuration (LDAP, OIDC, IAM, K8s)
- Conjur database encryption
- API key rotation policy
- Conjur audit logging

#### Zero Standing Privileges (ZSP1 - ZSP5)
- Permanent privileged access detection
- Dual control workflow validation
- Concurrent session limit checks
- Check-in/check-out enforcement
- Standing privilege reduction recommendations
- JIT readiness scoring

#### Identity Governance (IGA1 - IGA8)
- Orphaned identity detection
- Permission drift analysis
- Inactive user account detection
- Excessive safe membership analysis
- Access certification status
- Role/group membership sprawl
- Pending account queue age
- Account ownership gap detection

#### EPM Integration (EPM1 - EPM6)
*Requires EPM URL and optional authentication*
- EPM integration status verification
- Default policy security assessment
- Application control mode validation
- Credential theft protection status
- Elevation request justification requirements
- EPM audit logging configuration

#### Cloud Security (CLD1 - CLD6)
- Cloud provider integration status (AWS, Azure, GCP)
- Federated identity configuration
- Cloud secret sync policy validation
- CIEM integration assessment
- Cloud IAM role binding analysis
- Multi-cloud policy consistency

#### Disaster Recovery (DR1 - DR5)
- DR Vault replication status
- HA cluster health verification
- Component redundancy assessment
- Backup configuration validation
- Break-glass account availability

#### Compliance Mapping (COMP1 - COMP4)
- NIST Cybersecurity Framework mapping
- SOC 2 Type II alignment indicators
- PCI-DSS relevant controls
- CyberArk Blueprint maturity scoring

#### Audit Logging (AUD1 - AUD4)
- SIEM integration health
- Audit log retention configuration
- Critical event alerting validation
- Audit data integrity verification

#### Active Directory Security (AD1 - AD7) - zBang-inspired
*Requires domain connectivity and `-IncludeADChecks` parameter*
- **Shadow Admin Discovery**: Detect accounts with direct ACL permissions on privileged objects
- **Skeleton Key Detection**: Check for Skeleton Key malware indicators on Domain Controllers
- **SID History Analysis**: Identify accounts with privileged SID History attributes
- **Risky SPN Configuration**: Find user accounts with SPNs (Kerberoasting targets)
- **Unconstrained Delegation**: Discover accounts with unconstrained Kerberos delegation
- **Constrained Delegation with Protocol Transition**: Detect S4U2Self abuse potential
- **Delegation Privilege Audit**: Comprehensive delegation configuration summary

#### Server Hardening (HARD1 - HARD8) - CYBRHardeningCheck-inspired
*Runs automatically on CyberArk servers with `-IncludeLocalHostChecks`*
- Unnecessary Windows Server roles detection
- Screen saver configuration validation
- Advanced audit policy completeness
- Remote Desktop hardening (NLA, encryption, timeout)
- Registry permissions on security keys
- Registry auditing configuration
- File system permissions on Config directories
- File system auditing on critical paths

#### Vault Hardening (VAULT1 - VAULT6)
*Runs automatically on Vault servers*
- NIC hardening (single NIC, minimal protocols)
- Static IP configuration (no DHCP)
- Domain membership check (should be workgroup)
- Logic Container service account validation
- Firewall non-standard rules detection
- Vault server certificate validation

#### PSM Hardening (PSMH1 - PSMH10)
*Runs automatically on PSM servers*
- PSM user configuration validation
- Remote Desktop Users group cleared
- AppLocker policy enforcement
- Local drives hidden from sessions
- IE Developer Tools blocked
- RDS hardening (clipboard, drive, printer redirection)
- PSM user access restrictions
- SMB services hardening

#### PVWA Hardening (PVWAH1 - PVWAH8)
*Runs automatically on PVWA servers*
- WebDAV disabled verification
- Anonymous authentication disabled
- Application pool configuration
- MIME types security
- Cryptography settings (FIPS)
- Installation location (non-system drive)

#### CPM Hardening (CPMH1 - CPMH4)
*Runs automatically on CPM servers*
- FIPS cryptography mode
- DEP (Data Execution Prevention) configuration
- Credential file permissions
- Service account configuration

#### Application Control (APPCTL1 - APPCTL5) - Evasor-inspired
*Requires `-IncludeAppControlChecks` parameter*
- **DLL Injection Vulnerability**: Check for processes vulnerable to DLL injection via MavInject
- **DLL Hijacking Risk**: Identify writable directories in CyberArk paths
- **Resource Hijacking**: Detect replaceable configuration and script files
- **AppLocker Bypass Paths**: Check for writable bypass locations
- **Writable System Paths**: Identify writable paths in system directories

#### Secrets Hub (SH1 - SH6)
*Requires `-IncludeSecretsHubChecks` and optionally `-SecretsHubUrl`*
- Secrets Hub sync health monitoring
- Sync latency measurement
- Version drift detection between source and targets
- Sync failure rate analysis
- Target configuration validation
- Secrets Hub audit logging

#### Remote Access / Alero (RA1 - RA6)
*Requires `-IncludeRemoteAccessChecks` and optionally `-AleroUrl`*
- Vendor invitation workflow security
- Session time limits configuration
- Biometric/device binding requirements
- Remote access audit log completeness
- Periodic access review enforcement
- MFA enforcement for remote access

#### Kubernetes Secrets (K8S1 - K8S8)
*Requires `-IncludeK8sChecks` and optionally `-K8sNamespace`, `-ConjurApplianceUrl`*
- Secrets Provider deployment mode verification
- Pod security context validation
- Service Account JWT authentication
- Kubernetes secrets rotation
- RBAC configuration for secrets
- Mounted secret permissions
- Conjur follower health
- Kubernetes audit logging

#### DevSecOps Pipeline (DSO1 - DSO6)
*Requires `-IncludeDevSecOpsChecks`*
- CI/CD secrets retrieval patterns
- Pipeline secrets sprawl detection
- Short-lived token usage validation
- Pipeline audit logging
- Secrets in build artifacts detection
- Pipeline identity binding

#### Privilege Cloud (PC1 - PC5)
*Requires `-IncludePrivilegeCloudChecks` or `-PrivilegeCloudTenant` or `-IsPrivilegeCloud`*
- Privilege Cloud connector health
- Identity Security Platform integration
- Privilege Cloud API security
- Tenant isolation validation
- Cloud connector redundancy

#### CyberArk Identity (IDN1 - IDN6)
*Requires `-IncludeIdentityChecks` or `-IdentityTenantUrl`*
- SSO integration with PVWA
- Adaptive MFA policy configuration
- Identity lifecycle synchronization
- Session risk scoring
- Identity audit integration
- Privileged application catalog policies

#### Custom Plugins (PLG1 - PLG5)
*Requires `-IncludePluginChecks`*
- Custom PSM connector security
- Custom CPM plugin injection risks
- Unauthorized/outdated component detection
- Plugin digital signature validation
- Custom script file permissions

#### Backup Security (BKP1 - BKP5)
*Requires `-IncludeBackupSecurityChecks` and optionally `-BackupPath`*
- Vault backup encryption
- Backup file permissions
- Backup in-transit encryption
- Backup restoration testing
- Backup retention policy

#### HSM Integration (HSM1 - HSM4)
*Requires `-IncludeHSMChecks` and optionally `-HSMProvider`*
- HSM connectivity and health
- HSM key wrapping configuration
- HSM partition isolation
- HSM firmware currency

#### PTA Deep Dive (PTAD1 - PTAD6)
*Requires `-IncludePTADeepDive`*
- PTA custom detection rules
- PTA ML model quality
- PTA alert fatigue (false positive analysis)
- PTA detection rule coverage
- PTA UEBA integration
- PTA automated response actions

#### Third-Party Integration (TPI1 - TPI5)
*Requires `-IncludeThirdPartyChecks` and optionally `-ServiceNowUrl`, `-SIEMUrl`*
- ITSM (ServiceNow) integration
- SOAR automated response playbooks
- SIEM PAM event correlation
- SIEM log forwarder health
- Integration credential health

#### Operational Hygiene (OPS1 - OPS8)
*Requires `-IncludeOperationalChecks`*
- Account onboarding queue metrics
- CPM password change failure rates
- PSM session success/failure ratios
- CPM reconciliation backlog
- Platform connection errors
- Vault utilization and capacity
- License compliance
- Component uptime

#### Attack Path Simulation (APS1 - APS6)
*Requires `-IncludeAttackPathChecks`*
- Workstation to PAM escalation paths
- Pass-the-Hash attack surface
- NTLM relay risks
- Cached credential extraction resilience
- Kerberoasting exposure
- Privilege escalation paths

#### Supply Chain Integrity (SCI1 - SCI5)
*Requires `-IncludeSupplyChainChecks`*
- Component file hash validation
- Patch currency verification
- Third-party library vulnerabilities
- Digital signature validation
- Component origin verification

#### Network Segmentation (NSG1 - NSG5)
*Requires `-IncludeNetworkSegmentationChecks`*
- Vault network isolation
- PSM to Vault communication restrictions
- PVWA to backend segmentation
- East-West traffic monitoring
- Component-specific network ACLs

## Requirements

### Software Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| PowerShell | 7.0+ | PowerShell 7.x required (Windows PowerShell 5.1 not supported) |
| .NET Framework | 4.5+ | Required for TLS/SSL and network operations |
| CyberArk PVWA | v12+ | REST API v12 or later for full compatibility |

### Access Requirements by Phase

| Phase | Requirement | Purpose |
|-------|-------------|---------|
| Phase 1 | Network access to PVWA | Blackbox testing, port scanning, TLS analysis |
| Phase 2 | CyberArk API credentials | Configuration audits, policy checks |
| Phase 3 | Local admin on CyberArk server | Windows security, service, and registry checks |

### Credential Requirements for Authenticated Checks

For Phase 2 (Authenticated Checks), you need CyberArk credentials with one of these roles:
- **Vault Admin**: Full access to all configuration and security settings
- **Auditor**: Read-only access to audit configurations (recommended for security assessments)
- **Safe Owners**: Limited to safes they own (partial audit coverage)

### Windows Features Used

The script uses these Windows/PowerShell features (no installation required):

| Feature | Used For |
|---------|----------|
| `System.Net.Sockets.TcpClient` | Port scanning, Vault port security |
| `System.Net.Security.SslStream` | TLS/SSL protocol and cipher enumeration |
| `Invoke-WebRequest` / `Invoke-RestMethod` | HTTP testing, API calls |
| `Get-WmiObject` / `Get-CimInstance` | Service account analysis, AV status |
| `Get-Service` | CyberArk service health checks |
| `Get-NetFirewallRule` | Windows Firewall configuration |
| Registry access | Credential caching, LSA protection checks |

## Quick Start

```powershell
# 1. Verify PowerShell version (need 7.0+)
$PSVersionTable.PSVersion

# 2. Enable TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 3. Run unauthenticated scan (no credentials needed)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -UnauthenticatedOnly

# 4. Run full scan with authentication
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP
```

## Usage

### Unauthenticated Only (Blackbox Testing)

Run external security checks without any credentials:

```powershell
# No credentials required - great for penetration testing
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -UnauthenticatedOnly
```

### Full Audit with Authentication

```powershell
# Full audit with LDAP authentication
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP

# Full audit with pre-supplied credentials
$cred = Get-Credential
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -Credential $cred
```

### Skip Specific Check Types

```powershell
# Skip port scanning (faster execution)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -SkipPortScan

# Skip authenticated checks (only blackbox)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -SkipAuthenticatedChecks

# Skip CVE checks
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -SkipCVEChecks

# Skip multiple check categories
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" `
    -SkipSecretsChecks `
    -SkipMachineIdentity `
    -SkipIGAChecks `
    -SkipCloudChecks
```

### Include Local Host Checks (On CyberArk Server Only)

```powershell
# Only use when running directly on a CyberArk server
.\CyberArk-Security-Audit.ps1 -PVWA "https://localhost" -AuthType CyberArk -IncludeLocalHostChecks
```

### Full Options Example

```powershell
.\CyberArk-Security-Audit.ps1 `
    -PVWA "https://pvwa.domain.com" `
    -AuthType LDAP `
    -OutputPath "C:\Reports" `
    -Credential $cred `
    -SkipPortScan `
    -SkipCVEChecks `
    -SkipAPITests `
    -PortScanTimeout 2000 `
    -VerboseOutput

# Full audit with compliance mapping
.\CyberArk-Security-Audit.ps1 `
    -PVWA "https://pvwa.domain.com" `
    -AuthType LDAP `
    -OutputPath "C:\Reports" `
    -ComplianceMapping `
    -IncludeEPMChecks `
    -EPMUrl "https://epm.domain.com"
```

### Common Scenarios

```powershell
# External penetration test (no access, no credentials)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -UnauthenticatedOnly

# Internal security audit (with CyberArk credentials)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP

# Full audit on CyberArk server (run locally with admin)
.\CyberArk-Security-Audit.ps1 -PVWA "https://localhost" -AuthType CyberArk -IncludeLocalHostChecks

# Quick check (skip intensive scans)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -SkipPortScan -SkipCVEChecks
```

### Red Team Scenarios

```powershell
# OPSEC Mode - Stealth scanning for red team operations
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -OPSECMode -UnauthenticatedOnly

# Route traffic through Burp Suite proxy
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -Proxy "http://127.0.0.1:8080" -IgnoreCertificateErrors

# Advanced timing attack detection
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -IncludeTimingAttacks -UnauthenticatedOnly

# Full JWT/OAuth2 security testing
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -IncludeJWTTests

# WebSocket endpoint discovery and CSWSH testing
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -IncludeWebSocketTests

# WAF evasion testing (encoding bypasses, HPP, smuggling)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -IncludeWAFEvasion

# Custom timing with jitter and randomized User-Agent
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -RequestDelay 3 -Jitter 30 -RandomizeUserAgent

# Quiet mode for automation/scripting
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -QuietMode -NoLogo -UnauthenticatedOnly

# Complete red team assessment
.\CyberArk-Security-Audit.ps1 `
    -PVWA "https://pvwa.domain.com" `
    -OPSECMode `
    -Proxy "http://127.0.0.1:8080" `
    -IncludeTimingAttacks `
    -IncludeJWTTests `
    -IncludeWebSocketTests `
    -IncludeWAFEvasion `
    -UnauthenticatedOnly
```

### CyberArk Tools Integration Scenarios

```powershell
# AD Security Audit (zBang-inspired) - detect shadow admins, Kerberos issues
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP -IncludeADChecks

# AD Security with specific Domain Controller
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -IncludeADChecks -DomainController "dc01.domain.com"

# Full hardening check on CyberArk server (CYBRHardeningCheck-inspired)
.\CyberArk-Security-Audit.ps1 -PVWA "https://localhost" -AuthType CyberArk -IncludeLocalHostChecks

# Application control bypass detection (Evasor-inspired)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -IncludeAppControlChecks -IncludeLocalHostChecks

# Conjur/Secrets Manager integration check
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -IncludeConjurChecks -ConjurUrl "https://conjur.domain.com"

# Comprehensive audit with CyberArk tools integration
.\CyberArk-Security-Audit.ps1 `
    -PVWA "https://pvwa.domain.com" `
    -AuthType LDAP `
    -IncludeADChecks `
    -IncludeConjurChecks `
    -ConjurUrl "https://conjur.domain.com" `
    -ComplianceMapping

# Skip hardening checks (faster scan)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -SkipHardeningChecks
```

### Reporting & Output Scenarios

```powershell
# Generate comprehensive reports to a specific directory
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -OutputPath "C:\SecurityReports\CyberArk"

# Quick unauthenticated scan with minimal output for automation
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" `
    -UnauthenticatedOnly -QuietMode -NoLogo `
    -OutputPath "C:\Reports"

# Full audit for compliance reporting
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -ComplianceMapping -OutputPath "C:\ComplianceReports"

# Generate reports and capture results for further processing
$auditResults = .\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP

# Access the returned data programmatically
$auditResults.ReportMetadata.RiskScore
$auditResults.Findings | Where-Object { $_.Severity -eq "Critical" }
$auditResults.Reports.HTML  # Path to HTML report
$auditResults.Reports.CSV   # Array of CSV file paths
$auditResults.Reports.JSON  # Path to JSON report
```

**Output Files Generated:**

After running an audit, you'll find these files in your output directory:

```
C:\SecurityReports\CyberArk\
├── CyberArk_Security_Audit_20260116_143022.html          # Interactive HTML dashboard
├── CyberArk_Security_Audit_20260116_143022.json          # Comprehensive JSON data
├── CyberArk_Security_Audit_20260116_143022_Executive_Summary.csv
├── CyberArk_Security_Audit_20260116_143022_Full_Findings.csv
├── CyberArk_Security_Audit_20260116_143022_Failed_Findings.csv
├── CyberArk_Security_Audit_20260116_143022_Remediation_Tracker.csv
├── CyberArk_Security_Audit_20260116_143022_Skipped_Checks.csv
├── CyberArk_Security_Audit_20260116_143022_CIS_Compliance_Matrix.csv
└── CyberArk_Security_Audit_20260116_143022_Component_Summary.csv
```

### Security Posture Expansion Scenarios

```powershell
# Secrets Hub - Cloud secrets sync validation
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeSecretsHubChecks -SecretsHubUrl "https://secretshub.cyberark.cloud"

# Remote Access / Alero - Vendor access security
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeRemoteAccessChecks -AleroUrl "https://alero.cyberark.cloud"

# Kubernetes Secrets - Container security and Secrets Provider
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeK8sChecks -K8sNamespace "cyberark" -ConjurApplianceUrl "https://conjur.domain.com"

# DevSecOps - CI/CD pipeline security
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeDevSecOpsChecks

# Privilege Cloud - SaaS-specific checks
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IsPrivilegeCloud -PrivilegeCloudTenant "my-tenant"

# CyberArk Identity - SSO and adaptive MFA
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeIdentityChecks -IdentityTenantUrl "https://aab1234.id.cyberark.cloud"

# Backup Security - Encryption and file permissions
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeBackupSecurityChecks -BackupPath "D:\VaultBackups"

# HSM Integration - Hardware security module checks
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeHSMChecks -HSMProvider "Thales"

# PTA Deep Dive - Advanced threat detection analysis
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludePTADeepDive

# Third-Party Integration - SIEM/ITSM/SOAR connectivity
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeThirdPartyChecks -ServiceNowUrl "https://company.servicenow.com" -SIEMUrl "https://splunk.domain.com"

# Operational Hygiene - Health metrics and queue analysis
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeOperationalChecks

# Attack Path Simulation - Red team validation
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeAttackPathChecks -IncludeADChecks

# Supply Chain Integrity - Component validation
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeSupplyChainChecks

# Network Segmentation - Micro-segmentation analysis
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP `
    -IncludeNetworkSegmentationChecks

# Comprehensive audit with all security posture checks
.\CyberArk-Security-Audit.ps1 `
    -PVWA "https://pvwa.domain.com" `
    -AuthType LDAP `
    -IncludeSecretsHubChecks `
    -IncludeRemoteAccessChecks `
    -IncludeK8sChecks `
    -IncludeDevSecOpsChecks `
    -IncludeIdentityChecks `
    -IncludePluginChecks `
    -IncludeBackupSecurityChecks `
    -IncludeHSMChecks `
    -IncludePTADeepDive `
    -IncludeThirdPartyChecks `
    -IncludeOperationalChecks `
    -IncludeAttackPathChecks `
    -IncludeSupplyChainChecks `
    -IncludeNetworkSegmentationChecks `
    -ComplianceMapping
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| PVWA | Yes | - | PVWA server URL (e.g., https://pvwa.domain.com) |
| AuthType | No | CyberArk | Authentication method: CyberArk, LDAP, RADIUS, SAML |
| OutputPath | No | Current directory | Report output directory |
| Credential | No | Prompt | PSCredential for authentication |
| **Skip Parameters** | | | |
| SkipPortScan | No | False | Skip network port scanning |
| SkipHostChecks | No | (deprecated) | Deprecated - host checks are skipped by default for remote audits |
| SkipCVEChecks | No | False | Skip CVE-specific vulnerability testing |
| SkipAPITests | No | False | Skip API security testing |
| SkipAuthenticatedChecks | No | False | Skip all Phase 2 authenticated checks |
| SkipSecretsChecks | No | False | Skip Secrets Management checks (SEC1-SEC14) |
| SkipMachineIdentity | No | False | Skip Machine Identity checks (MID1-MID9) |
| SkipIGAChecks | No | False | Skip Identity Governance checks (IGA1-IGA8) |
| SkipCloudChecks | No | False | Skip Cloud Security checks (CLD1-CLD6) |
| SkipDRChecks | No | False | Skip Disaster Recovery checks (DR1-DR5) |
| SkipHardeningChecks | No | False | Skip component hardening checks (HARD, VAULT, PSM, PVWA, CPM) |
| SkipSecretsHubChecks | No | False | Skip Secrets Hub checks (SH1-SH6) |
| SkipRemoteAccessChecks | No | False | Skip Remote Access/Alero checks (RA1-RA6) |
| SkipK8sChecks | No | False | Skip Kubernetes checks (K8S1-K8S8) |
| SkipDevSecOpsChecks | No | False | Skip DevSecOps checks (DSO1-DSO6) |
| SkipPrivilegeCloudChecks | No | False | Skip Privilege Cloud checks (PC1-PC5) |
| SkipIdentityChecks | No | False | Skip CyberArk Identity checks (IDN1-IDN6) |
| SkipPluginChecks | No | False | Skip Custom Plugins checks (PLG1-PLG5) |
| SkipBackupSecurityChecks | No | False | Skip Backup Security checks (BKP1-BKP5) |
| SkipHSMChecks | No | False | Skip HSM Integration checks (HSM1-HSM4) |
| SkipPTADeepDive | No | False | Skip PTA Deep Dive checks (PTAD1-PTAD6) |
| SkipThirdPartyChecks | No | False | Skip Third-Party Integration checks (TPI1-TPI5) |
| SkipOperationalChecks | No | False | Skip Operational Hygiene checks (OPS1-OPS8) |
| SkipAttackPathChecks | No | False | Skip Attack Path Simulation checks (APS1-APS6) |
| SkipSupplyChainChecks | No | False | Skip Supply Chain Integrity checks (SCI1-SCI5) |
| SkipNetworkSegmentationChecks | No | False | Skip Network Segmentation checks (NSG1-NSG5) |
| **Mode Parameters** | | | |
| UnauthenticatedOnly | No | False | Run only Phase 1 (no credentials needed) |
| IncludeLocalHostChecks | No | False | Include local host security checks (only use when on CyberArk server) |
| IncludeEPMChecks | No | False | Include EPM integration checks |
| ComplianceMapping | No | False | Generate compliance framework mapping |
| **CyberArk Tools Parameters** | | | |
| IncludeADChecks | No | False | Enable Active Directory security checks (zBang-inspired) |
| IncludeAppControlChecks | No | False | Enable application control bypass detection (Evasor-inspired) |
| IncludeConjurChecks | No | False | Enable Conjur/Secrets Manager integration checks |
| ConjurUrl | No | - | Conjur server URL for integration checks |
| DomainController | No | - | Domain controller for AD security queries |
| **Red Team Parameters** | | | |
| OPSECMode / Stealth | No | False | Enable OPSEC/stealth mode with delays and reduced noise |
| Proxy | No | - | Proxy URL for traffic routing (e.g., http://127.0.0.1:8080) |
| ProxyCredential | No | - | Credentials for authenticated proxy |
| IgnoreCertificateErrors | No | False | Skip SSL/TLS certificate validation |
| RequestDelay | No | 0 | Delay between requests in seconds (0-60) |
| Jitter | No | 0 | Random jitter percentage (0-100) for timing variance |
| UserAgent | No | - | Custom User-Agent string |
| RandomizeUserAgent | No | False | Rotate through common User-Agent strings |
| IncludeTimingAttacks | No | False | Enable timing-based vulnerability detection |
| IncludeJWTTests | No | False | Enable JWT/OAuth2 security testing |
| IncludeWebSocketTests | No | False | Enable WebSocket endpoint discovery |
| IncludeWAFEvasion | No | False | Enable WAF/IDS bypass testing |
| NoLogo | No | False | Suppress banner display |
| QuietMode | No | False | Reduce console output (info messages suppressed) |
| EnablePasswordSpraying | No | False | Enable password spraying (requires explicit confirmation) |
| **Performance Parameters** | | | |
| ParallelExecution | No | False | Enable parallel execution for faster scans |
| MaxThreads | No | 5 | Maximum concurrent threads (1-20) |
| **EPM Parameters** | | | |
| EPMUrl | No | - | EPM server URL for EPM integration checks |
| **Security Posture Parameters** | | | |
| IncludeSecretsHubChecks | No | False | Enable Secrets Hub cloud sync checks |
| SecretsHubUrl | No | - | Secrets Hub URL for integration checks |
| IncludeRemoteAccessChecks | No | False | Enable Remote Access/Alero checks |
| AleroUrl | No | - | Alero URL for vendor access checks |
| IncludeK8sChecks | No | False | Enable Kubernetes/Container secrets checks |
| K8sNamespace | No | default | Kubernetes namespace for secrets checks |
| ConjurApplianceUrl | No | - | Conjur appliance URL for K8s integration |
| IncludeDevSecOpsChecks | No | False | Enable DevSecOps pipeline security checks |
| IsPrivilegeCloud | No | False | Indicate target is Privilege Cloud SaaS |
| PrivilegeCloudTenant | No | - | Privilege Cloud tenant identifier |
| IncludeIdentityChecks | No | False | Enable CyberArk Identity/Idaptive checks |
| IdentityTenantUrl | No | - | CyberArk Identity tenant URL |
| IncludePluginChecks | No | False | Enable custom plugin security checks |
| IncludeBackupSecurityChecks | No | False | Enable backup security checks |
| BackupPath | No | - | Path to Vault backup files for analysis |
| IncludeHSMChecks | No | False | Enable HSM integration checks |
| HSMProvider | No | - | HSM provider type (Thales, nCipher, SafeNet, AWSCloudHSM, AzureHSM, Other) |
| IncludePTADeepDive | No | False | Enable advanced PTA detection checks |
| IncludeThirdPartyChecks | No | False | Enable SIEM/ITSM/SOAR integration checks |
| ServiceNowUrl | No | - | ServiceNow URL for ITSM checks |
| SIEMUrl | No | - | SIEM URL for event correlation checks |
| IncludeOperationalChecks | No | False | Enable operational hygiene metrics |
| IncludeAttackPathChecks | No | False | Enable attack path simulation checks |
| IncludeSupplyChainChecks | No | False | Enable supply chain integrity checks |
| IncludeNetworkSegmentationChecks | No | False | Enable network segmentation checks |
| **Other Parameters** | | | |
| PortScanTimeout | No | 1000 | Port scan connection timeout (ms) |
| VerboseOutput | No | False | Enable verbose logging |

## Output

The script generates comprehensive reports in three formats, designed to support writing detailed security assessment reports:

### Report Formats

#### 1. HTML Report (Interactive Dashboard)

A modern, interactive HTML report with:

- **Table of Contents**: Quick navigation to all report sections
- **Executive Summary**: Overall risk rating, compliance percentage, key metrics
- **Key Risks Section**: Top 10 critical/high findings with business impact
- **CIS Benchmark Compliance Matrix**: Control-by-control compliance status
- **Detailed Findings Table**: Expandable rows with full evidence and remediation steps
  - Click any finding to reveal: evidence, technical details, risk description, business impact, CVSS score, remediation steps, and references
- **Remediation Roadmap**: Prioritized timeline (24h/1wk/30d/90d)
- **Component Analysis**: Findings grouped by CyberArk component (Vault, CPM, PSM, PVWA, PTA)
- **Skipped Checks**: Manual verification requirements with follow-up guidance
- **Print-friendly**: Auto-expands all findings when printing

#### 2. CSV Reports (7 Separate Files)

Generates multiple CSV files for different audiences:

| File | Purpose | Audience |
|------|---------|----------|
| `Executive_Summary.csv` | High-level metrics and risk overview | Leadership, Management |
| `Full_Findings.csv` | Complete findings with all 20+ fields | Security Analysts |
| `Failed_Findings.csv` | Failed checks only, sorted by severity | Remediation Teams |
| `Remediation_Tracker.csv` | Actionable tracker with AssignedTo, Status, DueDate | IT Operations |
| `Skipped_Checks.csv` | Checks requiring manual verification | Auditors |
| `CIS_Compliance_Matrix.csv` | Control-by-control compliance status | Compliance Officers |
| `Component_Summary.csv` | Findings grouped by component | Component Owners |

#### 3. JSON Report (Structured Data)

Comprehensive structured data for programmatic analysis:

```json
{
  "reportInfo": { "title", "generatedAt", "version" },
  "auditMetadata": { "target", "auditDate", "auditorInfo" },
  "executiveSummary": {
    "overallRiskRating": "Fair",
    "riskScore": 45,
    "keyMetrics": { "totalChecks", "passed", "failed", "compliance%" },
    "findingsBySeverity": { "critical", "high", "medium", "low" },
    "keyRisks": [ /* top 10 findings */ ],
    "immediatePriorities": [ /* critical recommendations */ ]
  },
  "complianceAnalysis": {
    "overallCompliance": 78.5,
    "cisControlsCompliance": { /* per-control matrix */ }
  },
  "componentAnalysis": { /* findings by component */ },
  "categoryAnalysis": { /* findings by category */ },
  "remediationRoadmap": {
    "immediate": { "timeframe": "24-48 hours", "findings": [] },
    "urgent": { "timeframe": "1 week", "findings": [] },
    "standard": { "timeframe": "30 days", "findings": [] },
    "routine": { "timeframe": "90 days", "findings": [] }
  },
  "detailedFindings": { "failed", "passed", "all" },
  "skippedChecks": { "summary", "requiresFollowUp", "all" },
  "appendix": { "glossary", "severityDefinitions", "riskScoreExplanation" }
}
```

### Enhanced Finding Details

Each finding now includes comprehensive information for report writing:

| Field | Description |
|-------|-------------|
| `FindingID` | Unique identifier (e.g., CA-20260116-A1B2C3D4) |
| `Category` | Security category (e.g., Safe Configuration, Authentication) |
| `CISControl` | CIS Benchmark control reference |
| `AffectedComponent` | CyberArk component (Vault, CPM, PSM, PVWA, PTA) |
| `Evidence` | Technical evidence supporting the finding |
| `TechnicalDetails` | Detailed technical description |
| `RiskDescription` | Explanation of why this is a security risk |
| `BusinessImpact` | Business-level impact explanation |
| `CVSSScore` | Estimated CVSS score range |
| `RemediationSteps` | Step-by-step remediation guidance |
| `ComplianceRefs` | Compliance framework references |
| `References` | Documentation links |

### Risk Scoring

Findings are scored by severity:
- **Critical**: 40 points (Immediate action required)
- **High**: 20 points (Priority remediation within 1 week)
- **Medium**: 5 points (Address within 30 days)
- **Low**: 1 point (Address within 90 days)

Risk ratings:
- **Excellent**: 0 points (No security issues)
- **Good**: 1-19 points (Minor issues only)
- **Fair**: 20-49 points (Some issues require attention)
- **Poor**: 50-99 points (Significant issues)
- **Critical**: 100+ points (Immediate action required)

### Writing Comprehensive Reports

The output is designed to help you write professional security assessment reports:

1. **Use the Executive Summary** for management briefings
2. **Reference the CIS Compliance Matrix** for compliance sections
3. **Copy Evidence and Technical Details** for technical appendices
4. **Use the Remediation Roadmap** for the recommendations section
5. **Include Component Analysis** for team-specific action items
6. **Track remediation** using the CSV Remediation Tracker

## Security Considerations

⚠️ **WARNING**: This tool performs active security testing that may:
- Generate security alerts in monitoring systems
- Avoid account lockouts by only checking known default passwords
- Password sprays or brute force attacks require explicit user confirmation via `-EnablePasswordSpraying` flag
- Be flagged as malicious activity by security tools
- Impact system performance during port scanning

**Always obtain proper authorization before running this script.**

**Use `-OPSECMode` for reduced detection footprint during red team operations.**

## Known Vulnerable CyberArk Versions

The script checks for the following known vulnerable versions:

| Version | CVEs |
|---------|------|
| 10.9 | CVE-2021-31796 |
| 10.10 | CVE-2021-31796, CVE-2021-44228 |
| 11.0 | CVE-2021-44228 |
| 11.1-11.2 | CVE-2022-22536 |
| 12.0-12.1 | CVE-2023-43903 |
| 12.2 | CVE-2024-42339, CVE-2024-42340 |
| 14.0 | CVE-2025-49827, CVE-2025-49828, CVE-2025-49829, CVE-2025-49830, CVE-2025-49831, CA25-32 |
| 14.2 | CVE-2024-38996, CA25-34, CA25-35 |
| 24.7 (EPM SaaS) | CVE-2025-22270, CVE-2025-22271, CVE-2025-22272, CVE-2025-22273, CVE-2025-22274 |

## Troubleshooting

### Common Issues and Solutions

#### Script Execution Blocked

**Error**: `File cannot be loaded because running scripts is disabled on this system`

**Solution**:
```powershell
# Option 1: Bypass for current session only
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Option 2: Unblock the specific file
Unblock-File -Path .\CyberArk-Security-Audit.ps1
```

#### PowerShell Version Error

**Error**: `This script requires PowerShell 7 or higher.`

**Solution**:
```powershell
# Check current version
$PSVersionTable.PSVersion

# Install PowerShell 7
winget install Microsoft.PowerShell

# Or download from: https://github.com/PowerShell/PowerShell/releases
```

#### TLS/SSL Connection Errors

**Error**: `The request was aborted: Could not create SSL/TLS secure channel`

**Solution**:
```powershell
# Enable TLS 1.2 before running the script
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# For PowerShell 7, TLS 1.3 may also be available
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
```

#### Certificate Validation Errors

**Error**: `The underlying connection was closed: Could not establish trust relationship`

**Solution**: This typically indicates a certificate issue (e.g., self-signed certificate) with the PVWA. The script will automatically capture this as a security finding and continue with the assessment to provide complete coverage. The script includes certificate validation bypass for operational continuity:
```powershell
# The script automatically bypasses certificate validation for assessment continuity
# while capturing certificate issues as findings
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
```

#### Authentication Failures

**Error**: `Authentication failed: The remote server returned an error: (401) Unauthorized`

**Solutions**:
1. Verify credentials are correct
2. Check the authentication type matches your environment (`-AuthType LDAP`, `-AuthType CyberArk`, etc.)
3. Ensure the account is not locked out
4. Verify the account has API access permissions

```powershell
# Test authentication manually
$cred = Get-Credential
$body = @{ username = $cred.UserName; password = $cred.GetNetworkCredential().Password } | ConvertTo-Json
Invoke-RestMethod -Uri "https://pvwa.domain.com/PasswordVault/api/Auth/LDAP/Logon" -Method POST -Body $body -ContentType "application/json"
```

#### Port Scan Timeouts

**Error**: Port scans taking too long or timing out

**Solution**:
```powershell
# Increase timeout (default is 1000ms)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -PortScanTimeout 3000

# Or skip port scanning entirely
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -SkipPortScan
```

#### Host Security Checks Not Running

**Info**: Host security checks are skipped by default for remote audits

**Solution**: Host checks examine the LOCAL machine, not CyberArk servers. Only use `-IncludeLocalHostChecks` when running the script directly on a CyberArk server:
```powershell
# Run on a CyberArk server with local admin rights
.\CyberArk-Security-Audit.ps1 -PVWA "https://localhost" -AuthType CyberArk -IncludeLocalHostChecks
```

#### Report Generation Errors

**Error**: Cannot write report files

**Solution**:
```powershell
# Specify a writable output directory
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -OutputPath "C:\Reports"

# Ensure the directory exists
New-Item -ItemType Directory -Path "C:\Reports" -Force
```

### Getting Help

If you encounter issues not covered above:

1. Run with verbose output: `-VerboseOutput`
2. Check the generated JSON report for detailed error information
3. Review Windows Event Logs for related errors
4. Open an issue on GitHub with the error details and environment information

## References

### CyberArk Documentation
- [CyberArk Security Hardening Guide](https://docs.cyberark.com/)
- [CyberArk REST API Documentation](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Implementing%20Privileged%20Account%20Security%20Web%20Services%20.htm)

### CyberArk Open Source Security Tools
- [zBang](https://github.com/cyberark/zBang) - Risk assessment tool for privileged account threats (Shadow Admins, Kerberos, SPNs)
- [CYBRHardeningCheck](https://github.com/cyberark/CYBRHardeningCheck) - CyberArk component server hardening verification
- [Evasor](https://github.com/cyberark/Evasor) - Application control bypass detection tool
- [Conjur](https://github.com/cyberark/conjur) - Secrets management platform
- [ACLight](https://github.com/cyberark/ACLight) - Shadow Admin discovery (part of zBang)
- [Ansible Security Automation Collection](https://github.com/cyberark/ansible-security-automation-collection) - CyberArk Ansible integration

## License

This tool is provided as-is for security assessment purposes. Use responsibly and ethically.
