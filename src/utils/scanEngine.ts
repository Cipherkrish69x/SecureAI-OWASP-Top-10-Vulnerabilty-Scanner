import { ScanResult, ScanTarget, Vulnerability, AIAnalysis } from '../types/vulnerability';

// Simulated vulnerability database with OWASP Top 10 coverage
const vulnerabilityDatabase: Vulnerability[] = [
  // A01: Broken Access Control
  {
    id: 'BAC-001',
    name: 'Vertical Privilege Escalation',
    category: 'Access Control',
    severity: 'Critical',
    description: 'Application allows users to access functionality or data that should be restricted to higher privilege levels.',
    impact: 'Attackers can gain administrative access and compromise the entire application.',
    remediation: 'Implement proper role-based access control (RBAC) and validate user permissions on every request.',
    owaspCategory: 'A01:2021 – Broken Access Control',
    cweId: 'CWE-269'
  },
  {
    id: 'BAC-002',
    name: 'Horizontal Privilege Escalation',
    category: 'Access Control',
    severity: 'High',
    description: 'Users can access resources belonging to other users at the same privilege level.',
    impact: 'Unauthorized access to sensitive user data and potential data breaches.',
    remediation: 'Implement proper authorization checks and object-level permissions.',
    owaspCategory: 'A01:2021 – Broken Access Control',
    cweId: 'CWE-862'
  },
  
  // A02: Cryptographic Failures
  {
    id: 'CF-001',
    name: 'Weak SSL/TLS Configuration',
    category: 'Cryptography',
    severity: 'High',
    description: 'Application uses outdated or weak SSL/TLS protocols and cipher suites.',
    impact: 'Man-in-the-middle attacks and data interception during transmission.',
    remediation: 'Configure TLS 1.2+ with strong cipher suites and implement HTTP Strict Transport Security (HSTS).',
    owaspCategory: 'A02:2021 – Cryptographic Failures',
    cweId: 'CWE-326'
  },
  {
    id: 'CF-002',
    name: 'Sensitive Data in Transit',
    category: 'Cryptography',
    severity: 'Medium',
    description: 'Sensitive information transmitted without proper encryption.',
    impact: 'Exposure of sensitive data during network transmission.',
    remediation: 'Encrypt all sensitive data in transit using strong encryption protocols.',
    owaspCategory: 'A02:2021 – Cryptographic Failures',
    cweId: 'CWE-319'
  },

  // A03: Injection
  {
    id: 'INJ-001',
    name: 'SQL Injection',
    category: 'Injection',
    severity: 'Critical',
    description: 'Application vulnerable to SQL injection attacks through unsanitized user input.',
    impact: 'Complete database compromise, data theft, and potential system takeover.',
    remediation: 'Use parameterized queries, input validation, and least-privilege database access.',
    owaspCategory: 'A03:2021 – Injection',
    cweId: 'CWE-89'
  },
  {
    id: 'INJ-002',
    name: 'Cross-Site Scripting (XSS)',
    category: 'Injection',
    severity: 'High',
    description: 'Application allows injection of malicious scripts into web pages viewed by other users.',
    impact: 'Session hijacking, defacement, and malicious script execution.',
    remediation: 'Implement proper output encoding, input validation, and Content Security Policy (CSP).',
    owaspCategory: 'A03:2021 – Injection',
    cweId: 'CWE-79'
  },

  // A04: Insecure Design
  {
    id: 'ID-001',
    name: 'Missing Rate Limiting',
    category: 'Design',
    severity: 'Medium',
    description: 'Application lacks proper rate limiting mechanisms for sensitive operations.',
    impact: 'Brute force attacks and denial of service vulnerabilities.',
    remediation: 'Implement rate limiting, account lockout policies, and CAPTCHA for sensitive operations.',
    owaspCategory: 'A04:2021 – Insecure Design',
    cweId: 'CWE-307'
  },

  // A05: Security Misconfiguration
  {
    id: 'SM-001',
    name: 'Default Credentials',
    category: 'Configuration',
    severity: 'Critical',
    description: 'Application uses default or weak administrative credentials.',
    impact: 'Unauthorized administrative access and complete system compromise.',
    remediation: 'Change all default passwords, implement strong password policies, and enforce regular password updates.',
    owaspCategory: 'A05:2021 – Security Misconfiguration',
    cweId: 'CWE-521'
  },
  {
    id: 'SM-002',
    name: 'Directory Listing Enabled',
    category: 'Configuration',
    severity: 'Low',
    description: 'Web server configured to show directory listings for certain paths.',
    impact: 'Information disclosure and potential exposure of sensitive files.',
    remediation: 'Disable directory listing and implement proper access controls.',
    owaspCategory: 'A05:2021 – Security Misconfiguration',
    cweId: 'CWE-548'
  },

  // A06: Vulnerable and Outdated Components
  {
    id: 'VOC-001',
    name: 'Outdated JavaScript Libraries',
    category: 'Components',
    severity: 'High',
    description: 'Application uses outdated JavaScript libraries with known security vulnerabilities.',
    impact: 'Exploitation of known vulnerabilities in third-party components.',
    remediation: 'Update all dependencies to latest secure versions and implement automated vulnerability scanning.',
    owaspCategory: 'A06:2021 – Vulnerable and Outdated Components',
    cweId: 'CWE-1104'
  },

  // A07: Identification and Authentication Failures
  {
    id: 'IAF-001',
    name: 'Weak Password Policy',
    category: 'Authentication',
    severity: 'Medium',
    description: 'Application enforces weak password requirements.',
    impact: 'Increased risk of password-based attacks and unauthorized access.',
    remediation: 'Implement strong password policies including complexity, length, and rotation requirements.',
    owaspCategory: 'A07:2021 – Identification and Authentication Failures',
    cweId: 'CWE-521'
  },
  {
    id: 'IAF-002',
    name: 'Missing Multi-Factor Authentication',
    category: 'Authentication',
    severity: 'High',
    description: 'Critical functions lack multi-factor authentication protection.',
    impact: 'Increased risk of account compromise through single-factor attacks.',
    remediation: 'Implement multi-factor authentication for all sensitive operations.',
    owaspCategory: 'A07:2021 – Identification and Authentication Failures',
    cweId: 'CWE-308'
  },

  // A08: Software and Data Integrity Failures
  {
    id: 'SDIF-001',
    name: 'Insecure Deserialization',
    category: 'Integrity',
    severity: 'Critical',
    description: 'Application deserializes untrusted data without proper validation.',
    impact: 'Remote code execution and complete system compromise.',
    remediation: 'Avoid deserializing untrusted data or implement strict validation and integrity checks.',
    owaspCategory: 'A08:2021 – Software and Data Integrity Failures',
    cweId: 'CWE-502'
  },

  // A09: Security Logging and Monitoring Failures
  {
    id: 'SLMF-001',
    name: 'Insufficient Logging',
    category: 'Monitoring',
    severity: 'Medium',
    description: 'Application lacks comprehensive security event logging.',
    impact: 'Inability to detect and respond to security incidents effectively.',
    remediation: 'Implement comprehensive logging for all security-relevant events and regular log monitoring.',
    owaspCategory: 'A09:2021 – Security Logging and Monitoring Failures',
    cweId: 'CWE-778'
  },

  // A10: Server-Side Request Forgery
  {
    id: 'SSRF-001',
    name: 'Server-Side Request Forgery',
    category: 'SSRF',
    severity: 'High',
    description: 'Application can be tricked into making requests to unintended locations.',
    impact: 'Access to internal systems and potential data exfiltration.',
    remediation: 'Validate and sanitize all URLs, implement allow-lists, and use network segmentation.',
    owaspCategory: 'A10:2021 – Server-Side Request Forgery (SSRF)',
    cweId: 'CWE-918'
  }
];

// AI-powered analysis engine
class AIVulnerabilityAnalyzer {
  private generateRecommendation(vulnerability: Vulnerability, evidence: string): string {
    const recommendations = {
      'Access Control': [
        'Implement role-based access control (RBAC) with principle of least privilege',
        'Add session management with proper timeout and invalidation',
        'Use secure authorization frameworks like OAuth 2.0 or JWT with proper validation',
        'Implement proper user context validation for every request'
      ],
      'Cryptography': [
        'Upgrade to TLS 1.3 with strong cipher suites (ECDHE-RSA-AES256-GCM-SHA384)',
        'Implement Certificate Transparency monitoring and HSTS',
        'Use authenticated encryption modes (AES-GCM) for data at rest',
        'Implement proper key rotation and certificate lifecycle management'
      ],
      'Injection': [
        'Use parameterized queries with prepared statements for all database interactions',
        'Implement comprehensive input validation using whitelist approach',
        'Add Content Security Policy (CSP) headers to prevent XSS',
        'Use ORM frameworks with built-in injection protection'
      ],
      'Design': [
        'Implement rate limiting using sliding window algorithms',
        'Add comprehensive threat modeling to identify design flaws',
        'Use secure design patterns like defense in depth',
        'Implement proper error handling without information leakage'
      ],
      'Configuration': [
        'Harden server configurations using security benchmarks (CIS)',
        'Implement infrastructure as code with security scanning',
        'Use configuration management tools with security validation',
        'Regular security configuration audits and compliance checks'
      ],
      'Components': [
        'Implement automated dependency scanning in CI/CD pipeline',
        'Use software composition analysis (SCA) tools',
        'Maintain an inventory of all third-party components',
        'Establish vulnerability disclosure and patching processes'
      ],
      'Authentication': [
        'Implement adaptive authentication based on risk factors',
        'Use modern authentication protocols like FIDO2/WebAuthn',
        'Add behavioral analysis for anomaly detection',
        'Implement proper session management with secure flags'
      ],
      'Integrity': [
        'Implement code signing and verification for all deployments',
        'Use immutable infrastructure and integrity monitoring',
        'Add runtime application self-protection (RASP)',
        'Implement proper serialization security controls'
      ],
      'Monitoring': [
        'Implement SIEM integration with real-time alerting',
        'Add user and entity behavior analytics (UEBA)',
        'Use threat intelligence feeds for proactive monitoring',
        'Implement automated incident response workflows'
      ],
      'SSRF': [
        'Implement URL validation with strict allow-lists',
        'Use network segmentation and micro-segmentation',
        'Add egress filtering and monitoring',
        'Implement proper input sanitization for URL parameters'
      ]
    };

    const categoryRecommendations = recommendations[vulnerability.category] || [];
    const baseRecommendation = categoryRecommendations[Math.floor(Math.random() * categoryRecommendations.length)];
    
    return `AI Analysis: ${baseRecommendation}. Context: ${evidence.substring(0, 100)}... This recommendation is generated based on current threat landscape and best practices.`;
  }

  private generateFixCode(vulnerability: Vulnerability): string | undefined {
    const fixes = {
      'SQL Injection': `// Secure parameterized query example
const query = 'SELECT * FROM users WHERE id = ? AND status = ?';
const values = [userId, 'active'];
const result = await db.execute(query, values);`,
      
      'Cross-Site Scripting (XSS)': `// Input sanitization and output encoding
import DOMPurify from 'dompurify';

// Sanitize user input
const sanitizedInput = DOMPurify.sanitize(userInput);

// Use template literals with encoding
const safeHTML = \`<div>\${escapeHtml(userContent)}</div>\`;`,

      'Weak SSL/TLS Configuration': `// Secure TLS configuration
const tlsOptions = {
  minVersion: 'TLSv1.2',
  ciphers: 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256',
  honorCipherOrder: true,
  secureProtocol: 'TLSv1_2_method'
};`,

      'Default Credentials': `// Secure password generation and validation
const bcrypt = require('bcrypt');
const saltRounds = 12;

// Generate secure password
const securePassword = generateSecurePassword(16);
const hashedPassword = await bcrypt.hash(securePassword, saltRounds);`,

      'Missing Multi-Factor Authentication': `// Implement TOTP-based MFA
const speakeasy = require('speakeasy');

// Generate secret for user
const secret = speakeasy.generateSecret({
  name: 'Your App',
  account: user.email
});

// Verify TOTP token
const verified = speakeasy.totp.verify({
  secret: user.mfaSecret,
  encoding: 'base32',
  token: userToken,
  window: 2
});`
    };

    return fixes[vulnerability.name];
  }

  private calculateConfidence(vulnerability: Vulnerability, scanType: string): number {
    let baseConfidence = 85;

    // Adjust based on vulnerability type
    if (vulnerability.severity === 'Critical') baseConfidence += 10;
    if (vulnerability.severity === 'Low') baseConfidence -= 15;

    // Adjust based on scan type
    if (scanType === 'comprehensive') baseConfidence += 10;
    if (scanType === 'quick') baseConfidence -= 10;

    // Add some randomness for realism
    const variance = Math.random() * 20 - 10;
    
    return Math.min(99, Math.max(60, Math.round(baseConfidence + variance)));
  }

  analyze(vulnerability: Vulnerability, evidence: string, scanType: string): AIAnalysis {
    return {
      recommendation: this.generateRecommendation(vulnerability, evidence),
      fixCode: this.generateFixCode(vulnerability),
      confidence: this.calculateConfidence(vulnerability, scanType),
      reasoning: `AI assessment based on pattern analysis, threat intelligence, and security best practices. High confidence due to clear evidence patterns and known attack vectors.`
    };
  }
}

// Main scan engine
export async function simulateVulnerabilityScan(scanTarget: ScanTarget): Promise<ScanResult[]> {
  const analyzer = new AIVulnerabilityAnalyzer();
  const results: ScanResult[] = [];
  
  // Determine number of vulnerabilities based on scan type
  const vulnCounts = {
    quick: { min: 3, max: 6 },
    deep: { min: 5, max: 10 },
    comprehensive: { min: 8, max: 15 }
  };

  const { min, max } = vulnCounts[scanTarget.scanType];
  const numVulnerabilities = Math.floor(Math.random() * (max - min + 1)) + min;

  // Filter vulnerabilities based on selected categories
  let availableVulns = vulnerabilityDatabase;
  if (scanTarget.selectedCategories.length > 0) {
    availableVulns = vulnerabilityDatabase.filter(vuln => 
      scanTarget.selectedCategories.some(cat => vuln.owaspCategory.includes(cat))
    );
  }

  // Randomly select vulnerabilities
  const selectedVulns = [];
  for (let i = 0; i < numVulnerabilities && i < availableVulns.length; i++) {
    const randomIndex = Math.floor(Math.random() * availableVulns.length);
    const vuln = availableVulns.splice(randomIndex, 1)[0];
    selectedVulns.push(vuln);
  }

  // Generate scan results with AI analysis
  for (const vulnerability of selectedVulns) {
    const evidence = generateEvidence(vulnerability, scanTarget.url);
    const aiAnalysis = analyzer.analyze(vulnerability, evidence, scanTarget.scanType);
    
    const result: ScanResult = {
      id: `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      url: scanTarget.url,
      timestamp: new Date(),
      vulnerability,
      evidence,
      aiRecommendation: aiAnalysis.recommendation,
      fixCode: aiAnalysis.fixCode,
      confidence: aiAnalysis.confidence,
      status: Math.random() > 0.7 ? 'Fixed' : 'Open'
    };

    results.push(result);
  }

  // Sort by severity (Critical first)
  const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
  results.sort((a, b) => severityOrder[a.vulnerability.severity] - severityOrder[b.vulnerability.severity]);

  return results;
}

function generateEvidence(vulnerability: Vulnerability, url: string): string {
  const evidenceTemplates = {
    'SQL Injection': `SQL injection detected in parameter 'id' at ${url}/api/users. Payload: ' OR '1'='1 returned different response indicating vulnerability.`,
    'Cross-Site Scripting (XSS)': `XSS vulnerability found in search parameter at ${url}/search. Payload: <script>alert('XSS')</script> was reflected in response without proper encoding.`,
    'Weak SSL/TLS Configuration': `SSL Labs analysis of ${url} shows TLS 1.0/1.1 support and weak cipher suites. Grade: B (should be A+).`,
    'Default Credentials': `Default administrative credentials detected at ${url}/admin. Username: admin, Password: admin123 allows successful authentication.`,
    'Directory Listing Enabled': `Directory listing enabled at ${url}/uploads/ exposing sensitive files and directory structure.`,
    'Missing Multi-Factor Authentication': `Administrative panel at ${url}/admin lacks multi-factor authentication. Single-factor authentication presents security risk.`,
    'Vertical Privilege Escalation': `User role manipulation possible at ${url}/api/user/profile. Parameter 'role' can be modified to gain administrative privileges.`,
    'Server-Side Request Forgery': `SSRF vulnerability detected at ${url}/api/fetch. Parameter 'url' allows requests to internal network ranges.`
  };

  return evidenceTemplates[vulnerability.name] || 
    `Security vulnerability detected at ${url}. Manual verification recommended for ${vulnerability.name}.`;
}

// Additional utility functions for enhanced scanning
export function generateScanReport(results: ScanResult[]): string {
  const criticalCount = results.filter(r => r.vulnerability.severity === 'Critical').length;
  const highCount = results.filter(r => r.vulnerability.severity === 'High').length;
  const totalScore = calculateSecurityScore(results);

  return `
Security Assessment Report
========================

Total Vulnerabilities: ${results.length}
Critical: ${criticalCount}
High: ${highCount}
Security Score: ${totalScore}/100

Top Recommendations:
${results.slice(0, 3).map(r => `- ${r.aiRecommendation.substring(0, 100)}...`).join('\n')}
  `;
}

export function calculateSecurityScore(results: ScanResult[]): number {
  if (results.length === 0) return 100;

  const weights = { 'Critical': 25, 'High': 15, 'Medium': 8, 'Low': 3 };
  const totalDeductions = results.reduce((sum, result) => {
    return sum + (weights[result.vulnerability.severity] || 0);
  }, 0);

  return Math.max(0, 100 - totalDeductions);
}