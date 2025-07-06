import React, { useState } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Lock, 
  Database, 
  Settings, 
  Package,
  User,
  FileText,
  Eye,
  Globe
} from 'lucide-react';

const OWASP10Coverage: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState('A01');

  const owaspCategories = [
    {
      id: 'A01',
      title: 'Broken Access Control',
      icon: Shield,
      color: 'bg-red-500',
      description: 'Failures related to restrictions on what authenticated users are allowed to do.',
      examples: [
        'Violation of the principle of least privilege',
        'Bypassing access control checks',
        'Elevation of privilege',
        'Metadata manipulation'
      ],
      detectionMethods: [
        'Automated testing for privilege escalation',
        'Manual review of access control implementation',
        'Session management analysis',
        'URL manipulation testing'
      ],
      aiAnalysis: 'AI analyzes access patterns, identifies unusual privilege escalations, and suggests role-based access control improvements.',
      remediation: [
        'Implement proper authorization checks',
        'Use principle of least privilege',
        'Regular access reviews',
        'Implement proper session management'
      ]
    },
    {
      id: 'A02',
      title: 'Cryptographic Failures',
      icon: Lock,
      color: 'bg-orange-500',
      description: 'Failures related to cryptography which often leads to sensitive data exposure.',
      examples: [
        'Transmitting sensitive data in clear text',
        'Using old or weak cryptographic algorithms',
        'Default crypto keys in use',
        'Weak random number generation'
      ],
      detectionMethods: [
        'SSL/TLS configuration analysis',
        'Certificate validation testing',
        'Encryption algorithm assessment',
        'Key management evaluation'
      ],
      aiAnalysis: 'AI identifies weak encryption patterns, analyzes certificate chains, and recommends modern cryptographic standards.',
      remediation: [
        'Use strong encryption algorithms',
        'Implement proper key management',
        'Regular certificate rotation',
        'Enforce HTTPS everywhere'
      ]
    },
    {
      id: 'A03',
      title: 'Injection',
      icon: Database,
      color: 'bg-yellow-500',
      description: 'Occurs when untrusted data is sent to an interpreter as part of a command or query.',
      examples: [
        'SQL injection',
        'NoSQL injection',
        'Command injection',
        'LDAP injection'
      ],
      detectionMethods: [
        'Input validation testing',
        'Dynamic analysis with payloads',
        'Static code analysis',
        'Parameterized query verification'
      ],
      aiAnalysis: 'AI detects injection patterns, analyzes input validation, and suggests secure coding practices.',
      remediation: [
        'Use parameterized queries',
        'Input validation and sanitization',
        'Principle of least privilege for DB access',
        'Regular security testing'
      ]
    },
    {
      id: 'A04',
      title: 'Insecure Design',
      icon: Settings,
      color: 'bg-green-500',
      description: 'Risks related to design flaws and missing or ineffective control design.',
      examples: [
        'Missing or ineffective control design',
        'Insecure design patterns',
        'Lack of security requirements',
        'Insufficient threat modeling'
      ],
      detectionMethods: [
        'Architecture review',
        'Threat modeling assessment',
        'Security requirements analysis',
        'Design pattern evaluation'
      ],
      aiAnalysis: 'AI analyzes architectural patterns, identifies design weaknesses, and suggests secure design principles.',
      remediation: [
        'Implement secure development lifecycle',
        'Regular threat modeling',
        'Security requirements definition',
        'Secure design patterns'
      ]
    },
    {
      id: 'A05',
      title: 'Security Misconfiguration',
      icon: Package,
      color: 'bg-blue-500',
      description: 'Security misconfigurations are commonly a result of insecure default configurations.',
      examples: [
        'Missing security hardening',
        'Improperly configured permissions',
        'Default passwords',
        'Verbose error messages'
      ],
      detectionMethods: [
        'Configuration baseline assessment',
        'Default credential testing',
        'Security header analysis',
        'Error message evaluation'
      ],
      aiAnalysis: 'AI compares configurations against security baselines and identifies misconfigurations automatically.',
      remediation: [
        'Implement security hardening',
        'Regular configuration reviews',
        'Automated configuration management',
        'Disable unnecessary features'
      ]
    },
    {
      id: 'A06',
      title: 'Vulnerable and Outdated Components',
      icon: Package,
      color: 'bg-indigo-500',
      description: 'Components run with the same privileges as the application.',
      examples: [
        'Outdated libraries and frameworks',
        'Vulnerable third-party components',
        'Unsupported software versions',
        'Missing security patches'
      ],
      detectionMethods: [
        'Dependency scanning',
        'Version analysis',
        'CVE database checking',
        'License compliance review'
      ],
      aiAnalysis: 'AI monitors vulnerability databases, tracks component versions, and prioritizes updates based on risk.',
      remediation: [
        'Regular dependency updates',
        'Vulnerability scanning',
        'Component inventory management',
        'Automated patching processes'
      ]
    },
    {
      id: 'A07',
      title: 'Identification and Authentication Failures',
      icon: User,
      color: 'bg-purple-500',
      description: 'Confirmation of the user\'s identity, authentication, and session management.',
      examples: [
        'Weak password policies',
        'Credential stuffing attacks',
        'Session hijacking',
        'Missing multi-factor authentication'
      ],
      detectionMethods: [
        'Authentication mechanism testing',
        'Session management analysis',
        'Password policy evaluation',
        'Multi-factor authentication assessment'
      ],
      aiAnalysis: 'AI analyzes authentication patterns, detects anomalous login attempts, and suggests improvements.',
      remediation: [
        'Implement strong password policies',
        'Multi-factor authentication',
        'Secure session management',
        'Account lockout mechanisms'
      ]
    },
    {
      id: 'A08',
      title: 'Software and Data Integrity Failures',
      icon: FileText,
      color: 'bg-pink-500',
      description: 'Relates to code and infrastructure that does not protect against integrity violations.',
      examples: [
        'Unsigned software updates',
        'Insecure CI/CD pipelines',
        'Tampered serialized objects',
        'Missing integrity checks'
      ],
      detectionMethods: [
        'Code signing verification',
        'Pipeline security assessment',
        'Integrity check implementation',
        'Serialization security testing'
      ],
      aiAnalysis: 'AI monitors code integrity, analyzes CI/CD pipelines, and detects tampering attempts.',
      remediation: [
        'Implement code signing',
        'Secure CI/CD pipelines',
        'Regular integrity checks',
        'Secure serialization practices'
      ]
    },
    {
      id: 'A09',
      title: 'Security Logging and Monitoring Failures',
      icon: Eye,
      color: 'bg-teal-500',
      description: 'Insufficient logging and monitoring, coupled with missing or ineffective integration.',
      examples: [
        'Missing security event logging',
        'Inadequate log monitoring',
        'Lack of alerting mechanisms',
        'Insufficient audit trails'
      ],
      detectionMethods: [
        'Log analysis and review',
        'Monitoring system assessment',
        'Alert mechanism testing',
        'Audit trail verification'
      ],
      aiAnalysis: 'AI analyzes log patterns, detects security events, and provides intelligent alerting.',
      remediation: [
        'Comprehensive logging implementation',
        'Real-time monitoring',
        'Automated alerting',
        'Regular log analysis'
      ]
    },
    {
      id: 'A10',
      title: 'Server-Side Request Forgery (SSRF)',
      icon: Globe,
      color: 'bg-cyan-500',
      description: 'SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.',
      examples: [
        'Internal service enumeration',
        'Port scanning via SSRF',
        'Accessing internal APIs',
        'Cloud metadata access'
      ],
      detectionMethods: [
        'URL validation testing',
        'Internal network scanning',
        'Response analysis',
        'Metadata endpoint testing'
      ],
      aiAnalysis: 'AI identifies SSRF patterns, analyzes URL validation, and suggests secure URL handling practices.',
      remediation: [
        'URL validation and sanitization',
        'Network segmentation',
        'Whitelist allowed URLs',
        'Regular security testing'
      ]
    }
  ];

  const selectedCategoryData = owaspCategories.find(cat => cat.id === selectedCategory);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-purple-700 rounded-2xl p-8 text-white">
        <h2 className="text-3xl font-bold mb-2">OWASP Top 10 Coverage</h2>
        <p className="text-blue-100 text-lg">
          Comprehensive security assessment based on the most critical web application security risks
        </p>
      </div>

      {/* Categories Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {owaspCategories.map((category) => {
          const Icon = category.icon;
          return (
            <button
              key={category.id}
              onClick={() => setSelectedCategory(category.id)}
              className={`p-4 rounded-xl border-2 transition-all text-left ${
                selectedCategory === category.id
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-slate-200 hover:border-slate-300 bg-white'
              }`}
            >
              <div className={`p-3 rounded-lg ${category.color} mb-3 inline-block`}>
                <Icon className="h-6 w-6 text-white" />
              </div>
              <div className="text-sm font-bold text-slate-900">{category.id}</div>
              <div className="text-xs text-slate-600 mt-1">{category.title}</div>
            </button>
          );
        })}
      </div>

      {/* Selected Category Details */}
      {selectedCategoryData && (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <div className="p-6 border-b border-slate-200">
            <div className="flex items-center space-x-4">
              <div className={`p-4 rounded-xl ${selectedCategoryData.color}`}>
                <selectedCategoryData.icon className="h-8 w-8 text-white" />
              </div>
              <div>
                <h3 className="text-2xl font-bold text-slate-900">
                  {selectedCategoryData.id}: {selectedCategoryData.title}
                </h3>
                <p className="text-slate-600 mt-1">{selectedCategoryData.description}</p>
              </div>
            </div>
          </div>

          <div className="p-6 grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Examples */}
            <div>
              <h4 className="text-lg font-semibold text-slate-900 mb-4">Common Examples</h4>
              <ul className="space-y-2">
                {selectedCategoryData.examples.map((example, index) => (
                  <li key={index} className="flex items-start space-x-2">
                    <AlertTriangle className="h-4 w-4 text-amber-500 mt-1 flex-shrink-0" />
                    <span className="text-sm text-slate-700">{example}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Detection Methods */}
            <div>
              <h4 className="text-lg font-semibold text-slate-900 mb-4">Detection Methods</h4>
              <ul className="space-y-2">
                {selectedCategoryData.detectionMethods.map((method, index) => (
                  <li key={index} className="flex items-start space-x-2">
                    <Eye className="h-4 w-4 text-blue-500 mt-1 flex-shrink-0" />
                    <span className="text-sm text-slate-700">{method}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* AI Analysis */}
            <div className="lg:col-span-2">
              <h4 className="text-lg font-semibold text-slate-900 mb-4 flex items-center space-x-2">
                <div className="p-2 bg-purple-100 rounded-lg">
                  <Database className="h-5 w-5 text-purple-600" />
                </div>
                <span>AI-Powered Analysis</span>
              </h4>
              <p className="text-sm text-slate-700 bg-purple-50 p-4 rounded-lg">
                {selectedCategoryData.aiAnalysis}
              </p>
            </div>

            {/* Remediation */}
            <div className="lg:col-span-2">
              <h4 className="text-lg font-semibold text-slate-900 mb-4">Remediation Strategies</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {selectedCategoryData.remediation.map((remedy, index) => (
                  <div key={index} className="flex items-start space-x-2 p-3 bg-green-50 rounded-lg">
                    <Shield className="h-4 w-4 text-green-600 mt-1 flex-shrink-0" />
                    <span className="text-sm text-slate-700">{remedy}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default OWASP10Coverage;