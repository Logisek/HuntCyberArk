# CyberArk Security Audit Suite v4.0

A comprehensive PowerShell-based security assessment tool for CyberArk Privileged Access Management (PAM) platforms. This tool performs extensive security checks including CIS Benchmark compliance, vendor best practices, blackbox testing, network security analysis, CVE-specific vulnerability checks (including 2025 CVEs), machine identity security, secrets management, zero standing privileges (ZSP) assessment, identity governance, and host security assessments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Audit Phases & Authentication Requirements](#audit-phases--authentication-requirements)
- [Features](#features)
- [Usage](#usage)
- [Parameters](#parameters)
- [Output](#output)
- [Security Considerations](#security-considerations)
- [Known Vulnerable CyberArk Versions](#known-vulnerable-cyberark-versions)
- [Troubleshooting](#troubleshooting)
- [References](#references)
- [Changelog](#changelog)

## Prerequisites

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| PowerShell | 5.1 | 7.x |
| .NET Framework | 4.5 | 4.8+ |
| Operating System | Windows 10/Server 2016 | Windows 11/Server 2022 |
| Memory | 2 GB available | 4 GB available |

### Required Access

| Audit Phase | Access Required |
|-------------|-----------------|
| Phase 1 (Unauthenticated) | Network access to PVWA (HTTPS/443) |
| Phase 2 (Authenticated) | CyberArk API credentials with Vault Admin or Auditor role |
| Phase 3 (Host Security) | Local administrator on CyberArk server |

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

Ensure the Major version is 5 or higher. If not, [download PowerShell 7.x](https://github.com/PowerShell/PowerShell/releases).

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
- CVE-specific vulnerability testing
- API security testing (unauthenticated endpoints)
- Component version detection

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
- **NEW in v4.0**: Machine Identity Security (service accounts, AppIDs)
- **NEW in v4.0**: Secrets Management (CP/CCP configuration)
- **NEW in v4.0**: Zero Standing Privileges (JIT access assessment)
- **NEW in v4.0**: Identity Governance (orphaned identities, permission drift)
- **NEW in v4.0**: Cloud Security (AWS/Azure/GCP integration)
- **NEW in v4.0**: Disaster Recovery (DR Vault, HA cluster health)
- **NEW in v4.0**: Compliance Mapping (NIST, SOC 2, PCI-DSS)

**Required Permissions**: Vault Admin or Auditor role recommended

### Phase 3: Host Security Checks (Local admin on CyberArk server required)
Windows host hardening checks requiring local execution:
- Windows Firewall configuration
- CyberArk service account settings
- Credential caching (WDigest, LSA Protection)
- Windows Event Log configuration
- Antivirus/EDR status
- CyberArk service health

**Requirement**: Run script directly on CyberArk server with admin rights

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
| **New in v4.0** | | |
| Machine Identity | MID1 - MID6 | Service account and AppID security |
| Secrets Management | SEC1 - SEC8 | Credential Provider/CCP security |
| Zero Standing Privileges | ZSP1 - ZSP5 | JIT access and privilege assessment |
| Identity Governance | IGA1 - IGA8 | Lifecycle and permission management |
| EPM Integration | EPM1 - EPM6 | Endpoint Privilege Manager checks |
| Cloud Security | CLD1 - CLD6 | Secure Cloud Access checks |
| Disaster Recovery | DR1 - DR5 | HA and DR configuration |
| Compliance Mapping | COMP1 - COMP4 | NIST, SOC2, PCI-DSS alignment |
| Audit Logging | AUD1 - AUD4 | SIEM and logging validation |

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
*Requires local execution on CyberArk server*
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

#### Machine Identity Security (MID1 - MID6) - NEW in v4.0
- Service account enumeration and privilege analysis
- Machine identity password rotation validation
- Over-privileged service account detection
- Certificate-based authentication configuration
- AppID security validation (allowed machines, OS user restrictions)
- Stale machine identity detection

#### Secrets Management (SEC1 - SEC8) - NEW in v4.0
- Credential Provider (CP/CCP) deployment verification
- AppID authentication method strength analysis
- Allowed machines configuration validation
- Cache TTL and refresh interval settings
- CCP TLS/mTLS configuration
- Secret rotation policy enforcement
- Orphan/unmanaged secrets detection
- Credential sprawl analysis

#### Zero Standing Privileges (ZSP1 - ZSP5) - NEW in v4.0
- Permanent privileged access detection
- Dual control workflow validation
- Concurrent session limit checks
- Check-in/check-out enforcement
- Standing privilege reduction recommendations
- JIT readiness scoring

#### Identity Governance (IGA1 - IGA8) - NEW in v4.0
- Orphaned identity detection
- Permission drift analysis
- Inactive user account detection
- Excessive safe membership analysis
- Access certification status
- Role/group membership sprawl
- Pending account queue age
- Account ownership gap detection

#### EPM Integration (EPM1 - EPM6) - NEW in v4.0
*Requires EPM URL and optional authentication*
- EPM integration status verification
- Default policy security assessment
- Application control mode validation
- Credential theft protection status
- Elevation request justification requirements
- EPM audit logging configuration

#### Cloud Security (CLD1 - CLD6) - NEW in v4.0
- Cloud provider integration status (AWS, Azure, GCP)
- Federated identity configuration
- Cloud secret sync policy validation
- CIEM integration assessment
- Cloud IAM role binding analysis
- Multi-cloud policy consistency

#### Disaster Recovery (DR1 - DR5) - NEW in v4.0
- DR Vault replication status
- HA cluster health verification
- Component redundancy assessment
- Backup configuration validation
- Break-glass account availability

#### Compliance Mapping (COMP1 - COMP4) - NEW in v4.0
- NIST Cybersecurity Framework mapping
- SOC 2 Type II alignment indicators
- PCI-DSS relevant controls
- CyberArk Blueprint maturity scoring

#### Audit Logging (AUD1 - AUD4) - NEW in v4.0
- SIEM integration health
- Audit log retention configuration
- Critical event alerting validation
- Audit data integrity verification

## Requirements

### Software Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| PowerShell | 5.1+ | PowerShell 7.x recommended for best performance |
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
# 1. Verify PowerShell version (need 5.1+)
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

# Skip host checks (when not running on CyberArk server)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -SkipHostChecks

# Skip authenticated checks (only blackbox + host)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -SkipAuthenticatedChecks
```

### Full Options Example

```powershell
.\CyberArk-Security-Audit.ps1 `
    -PVWA "https://pvwa.domain.com" `
    -AuthType LDAP `
    -OutputPath "C:\Reports" `
    -Credential $cred `
    -SkipPortScan `
    -SkipHostChecks `
    -SkipCVEChecks `
    -SkipAPITests `
    -PortScanTimeout 2000 `
    -VerboseOutput

# Full audit with v4.0 features including compliance mapping
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
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP -SkipHostChecks

# Full audit on CyberArk server (run locally with admin)
.\CyberArk-Security-Audit.ps1 -PVWA "https://localhost" -AuthType CyberArk

# Quick check (skip intensive scans)
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -SkipPortScan -SkipCVEChecks
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
| SkipHostChecks | No | False | Skip local host security checks |
| SkipCVEChecks | No | False | Skip CVE-specific vulnerability testing |
| SkipAPITests | No | False | Skip API security testing |
| SkipAuthenticatedChecks | No | False | Skip all Phase 2 authenticated checks |
| SkipSecretsChecks | No | False | Skip Secrets Management checks (SEC1-SEC8) |
| SkipMachineIdentity | No | False | Skip Machine Identity checks (MID1-MID6) |
| SkipIGAChecks | No | False | Skip Identity Governance checks (IGA1-IGA8) |
| SkipCloudChecks | No | False | Skip Cloud Security checks (CLD1-CLD6) |
| SkipDRChecks | No | False | Skip Disaster Recovery checks (DR1-DR5) |
| **Mode Parameters** | | | |
| UnauthenticatedOnly | No | False | Run only Phase 1 (no credentials needed) |
| IncludeEPMChecks | No | False | Include EPM integration checks |
| ComplianceMapping | No | False | Generate compliance framework mapping |
| **EPM Parameters** | | | |
| EPMUrl | No | - | EPM server URL for EPM integration checks |
| **Other Parameters** | | | |
| PortScanTimeout | No | 1000 | Port scan connection timeout (ms) |
| VerboseOutput | No | False | Enable verbose logging |

## Output

The script generates three report formats:

1. **HTML Report**: Interactive dashboard with filtering, risk scoring, and remediation priorities
2. **CSV Report**: Tabular data for spreadsheet analysis
3. **JSON Report**: Structured data for integration with other tools

### Risk Scoring

Findings are scored by severity:
- **Critical**: 40 points
- **High**: 20 points
- **Medium**: 5 points
- **Low**: 1 point

Risk ratings:
- **Excellent**: 0 points
- **Good**: 1-19 points
- **Fair**: 20-49 points
- **Poor**: 50-99 points
- **Critical**: 100+ points

## Security Considerations

⚠️ **WARNING**: This tool performs active security testing that may:
- Generate security alerts in monitoring systems
- Trigger account lockouts (default credential testing)
- Be flagged as malicious activity by security tools
- Impact system performance during port scanning

**Always obtain proper authorization before running this script.**

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

**Solution**: This typically indicates a certificate issue with the PVWA. The script will capture this as a finding. If you need to proceed anyway:
```powershell
# NOT RECOMMENDED for production - bypasses certificate validation
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

#### Host Security Checks Failing

**Error**: `Access is denied` on host security checks

**Solution**: Host security checks require local administrator privileges on the CyberArk server:
```powershell
# Run PowerShell as Administrator
Start-Process powershell -Verb RunAs

# Or skip host checks if running remotely
.\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -SkipHostChecks
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

### Verifying Script Requirements

Run this diagnostic script to verify your environment:

```powershell
# Check PowerShell version
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan

# Check .NET version
Write-Host ".NET Version: $([System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)" -ForegroundColor Cyan

# Check TLS settings
Write-Host "TLS Protocols: $([Net.ServicePointManager]::SecurityProtocol)" -ForegroundColor Cyan

# Check execution policy
Write-Host "Execution Policy: $(Get-ExecutionPolicy)" -ForegroundColor Cyan

# Test network stack
try {
    $tcpTest = New-Object System.Net.Sockets.TcpClient
    Write-Host "TCP Client: Available" -ForegroundColor Green
} catch {
    Write-Host "TCP Client: Error - $($_.Exception.Message)" -ForegroundColor Red
}

# Test SSL stream
try {
    $sslTest = [System.Net.Security.SslStream]
    Write-Host "SSL Stream: Available" -ForegroundColor Green
} catch {
    Write-Host "SSL Stream: Error - $($_.Exception.Message)" -ForegroundColor Red
}
```

### Getting Help

If you encounter issues not covered above:

1. Run with verbose output: `-VerboseOutput`
2. Check the generated JSON report for detailed error information
3. Review Windows Event Logs for related errors
4. Open an issue on GitHub with the error details and environment information

## References

- [CIS CyberArk PAM Benchmark](https://www.cisecurity.org/benchmark/cyberark)
- [CyberArk Security Hardening Guide](https://docs.cyberark.com/)
- [CyberArk Security Bulletins](https://www.cyberark.com/resources/security-bulletins)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/)
- [CyberArk REST API Documentation](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Implementing%20Privileged%20Account%20Security%20Web%20Services%20.htm)

## License

This tool is provided as-is for security assessment purposes. Use responsibly and ethically.

## Changelog

### Version 4.0
Major update with comprehensive identity security and 2025 vulnerability coverage:

**New Check Categories:**
- Machine Identity Security (MID1-MID6): Service account enumeration, rotation validation, over-privileged detection, AppID security
- Secrets Management (SEC1-SEC8): Credential Provider security, cache settings, secret rotation, orphan detection
- Zero Standing Privileges (ZSP1-ZSP5): JIT readiness assessment, dual control, check-in/check-out enforcement
- Identity Governance (IGA1-IGA8): Orphaned identities, permission drift, inactive users, access certification
- EPM Integration (EPM1-EPM6): Endpoint Privilege Manager policy assessment
- Cloud Security (CLD1-CLD6): AWS/Azure/GCP integration, federated identity, CIEM integration
- Disaster Recovery (DR1-DR5): DR Vault replication, HA cluster health, break-glass accounts
- Compliance Mapping (COMP1-COMP4): NIST CSF, SOC 2, PCI-DSS, Blueprint maturity scoring
- Audit Logging (AUD1-AUD4): SIEM integration, log retention, critical event alerting

**2025 CVE Updates:**
- CVE-2025-22270 through CVE-2025-22274: EPM SaaS vulnerabilities
- CVE-2025-49827 through CVE-2025-49831: Secrets Manager/Conjur critical vulnerabilities
- CVE-2024-38996: PVWA prototype pollution
- Security Bulletins: CA25-25, CA25-29, CA25-32, CA25-34, CA25-35

**New Parameters:**
- `-SkipSecretsChecks`: Skip Secrets Management checks
- `-SkipMachineIdentity`: Skip Machine Identity checks
- `-SkipIGAChecks`: Skip Identity Governance checks
- `-SkipCloudChecks`: Skip Cloud Security checks
- `-SkipDRChecks`: Skip Disaster Recovery checks
- `-IncludeEPMChecks`: Include EPM integration checks
- `-EPMUrl`: EPM server URL for integration
- `-ComplianceMapping`: Generate compliance framework mapping

**Enhanced Configuration:**
- New configuration thresholds for machine identity, IGA, ZSP, secrets management
- Expanded vulnerable version database including 2025 CVEs
- Blueprint maturity scoring based on findings

### Version 3.0.1
- Enhanced README with comprehensive installation guide
- Added Prerequisites section with system requirements
- Added detailed Installation instructions (no external tools required)
- Added Troubleshooting section with common issues and solutions
- Added Quick Start guide for rapid deployment
- Added diagnostic script for environment verification
- Updated Requirements section with detailed access matrix
- Added Table of Contents for easier navigation

### Version 3.0
- Added comprehensive port scanning (28+ ports)
- Added Vault port (1858) security analysis
- Added TLS/SSL cipher suite enumeration
- Added weak protocol detection
- Added CVE-specific vulnerability checks:
  - CVE-2021-31796 (SSRF)
  - CVE-2022-22536 (Auth Bypass)
  - CVE-2023-43903 (XSS)
  - CVE-2024-42340 (DOM XSS)
  - CVE-2024-42339 (HTML Injection)
- Added API security testing (BOLA, injection, mass assignment)
- Added Windows host security checks
- Added component version detection
- Added session security testing
- Added header injection testing
- Added XXE vulnerability testing
- Added configurable scan options (skip parameters)
- Enhanced reporting with new control categories

### Version 2.0
- Initial CIS Benchmark compliance checks
- Vendor Best Practice assessments
- Basic blackbox security testing
- HTML/CSV/JSON reporting
