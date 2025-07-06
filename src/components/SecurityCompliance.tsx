import React from 'react';
import { 
  Shield, 
  CheckCircle, 
  AlertTriangle, 
  FileText, 
  Award,
  Target,
  Globe,
  Lock
} from 'lucide-react';

const SecurityCompliance: React.FC = () => {
  const complianceFrameworks = [
    {
      name: 'OWASP Top 10 2021',
      status: 'Compliant',
      coverage: 100,
      description: 'Complete coverage of all OWASP Top 10 vulnerability categories'
    },
    {
      name: 'NIST Cybersecurity Framework',
      status: 'Compliant',
      coverage: 95,
      description: 'Aligned with NIST CSF for comprehensive security management'
    },
    {
      name: 'ISO 27001',
      status: 'Partial',
      coverage: 85,
      description: 'Information security management system standards'
    },
    {
      name: 'GDPR Privacy',
      status: 'Compliant',
      coverage: 98,
      description: 'General Data Protection Regulation compliance measures'
    }
  ];

  const ethicalGuidelines = [
    {
      title: 'Authorized Testing Only',
      description: 'Scan only applications you own or have explicit written permission to test',
      icon: Shield,
      status: 'enforced'
    },
    {
      title: 'Responsible Disclosure',
      description: 'Follow coordinated vulnerability disclosure practices',
      icon: FileText,
      status: 'enforced'
    },
    {
      title: 'Data Protection',
      description: 'No sensitive data collection or storage during scanning',
      icon: Lock,
      status: 'enforced'
    },
    {
      title: 'Rate Limiting',
      description: 'Respectful scanning to avoid service disruption',
      icon: Target,
      status: 'enforced'
    }
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Compliant': return 'text-green-600 bg-green-100';
      case 'Partial': return 'text-yellow-600 bg-yellow-100';
      case 'Non-Compliant': return 'text-red-600 bg-red-100';
      default: return 'text-slate-600 bg-slate-100';
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="bg-gradient-to-r from-green-600 to-blue-600 rounded-2xl p-8 text-white">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-3xl font-bold mb-2">Security & Compliance</h2>
            <p className="text-green-100 text-lg">
              Ethical security testing with comprehensive compliance coverage
            </p>
          </div>
          <div className="flex items-center space-x-2 bg-white/10 backdrop-blur-sm rounded-xl p-4">
            <Award className="h-8 w-8" />
            <div className="text-center">
              <div className="text-xl font-bold">A+</div>
              <div className="text-sm text-green-100">Security Grade</div>
            </div>
          </div>
        </div>
      </div>

      {/* Compliance Frameworks */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200">
        <div className="p-6 border-b border-slate-200">
          <h3 className="text-xl font-semibold text-slate-900 mb-2">Compliance Frameworks</h3>
          <p className="text-slate-600">Our security scanner aligns with industry standards and regulations</p>
        </div>
        
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {complianceFrameworks.map((framework, index) => (
              <div key={index} className="border border-slate-200 rounded-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-semibold text-slate-900">{framework.name}</h4>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(framework.status)}`}>
                    {framework.status}
                  </span>
                </div>
                
                <p className="text-sm text-slate-600 mb-4">{framework.description}</p>
                
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-slate-600">Coverage</span>
                  <span className="text-sm font-semibold text-slate-900">{framework.coverage}%</span>
                </div>
                
                <div className="w-full bg-slate-200 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      framework.coverage >= 95 ? 'bg-green-500' :
                      framework.coverage >= 80 ? 'bg-yellow-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${framework.coverage}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Ethical Guidelines */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200">
        <div className="p-6 border-b border-slate-200">
          <h3 className="text-xl font-semibold text-slate-900 mb-2">Ethical Security Testing</h3>
          <p className="text-slate-600">Built-in safeguards ensure responsible and ethical vulnerability assessment</p>
        </div>
        
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {ethicalGuidelines.map((guideline, index) => {
              const Icon = guideline.icon;
              return (
                <div key={index} className="flex items-start space-x-4 p-4 bg-green-50 rounded-lg border border-green-200">
                  <div className="p-2 bg-green-600 rounded-lg">
                    <Icon className="h-5 w-5 text-white" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-semibold text-slate-900">{guideline.title}</h4>
                      <CheckCircle className="h-5 w-5 text-green-600" />
                    </div>
                    <p className="text-sm text-slate-700">{guideline.description}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Legal Notice */}
      <div className="bg-amber-50 border border-amber-200 rounded-xl p-6">
        <div className="flex items-start space-x-3">
          <AlertTriangle className="h-6 w-6 text-amber-600 mt-1" />
          <div>
            <h4 className="font-semibold text-amber-900 mb-2">Legal & Ethical Use Notice</h4>
            <div className="space-y-2 text-sm text-amber-800">
              <p>
                <strong>Authorized Use Only:</strong> This security scanner must only be used on applications you own or have explicit written permission to test. Unauthorized testing is illegal and unethical.
              </p>
              <p>
                <strong>Responsible Disclosure:</strong> Any vulnerabilities discovered must be reported following responsible disclosure practices. Do not exploit or share vulnerabilities publicly without proper coordination.
              </p>
              <p>
                <strong>Compliance Requirements:</strong> Users must comply with all applicable laws, regulations, and organizational policies. This tool does not authorize testing without proper permissions.
              </p>
              <p>
                <strong>Educational Purpose:</strong> This demonstration tool is designed for educational purposes and authorized security testing environments only.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* AI Ethics */}
      <div className="bg-purple-50 border border-purple-200 rounded-xl p-6">
        <div className="flex items-center space-x-3 mb-4">
          <div className="p-3 bg-purple-600 rounded-lg">
            <Globe className="h-6 w-6 text-white" />
          </div>
          <div>
            <h4 className="font-semibold text-slate-900">AI Ethics & Transparency</h4>
            <p className="text-slate-600">Our AI implementation follows responsible AI principles</p>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white p-4 rounded-lg">
            <h5 className="font-medium text-slate-900 mb-2">Transparency</h5>
            <p className="text-sm text-slate-700">All AI recommendations include confidence scores and reasoning</p>
          </div>
          
          <div className="bg-white p-4 rounded-lg">
            <h5 className="font-medium text-slate-900 mb-2">Bias Mitigation</h5>
            <p className="text-sm text-slate-700">Regular testing for algorithmic bias and fairness</p>
          </div>
          
          <div className="bg-white p-4 rounded-lg">
            <h5 className="font-medium text-slate-900 mb-2">Human Oversight</h5>
            <p className="text-sm text-slate-700">AI suggestions require human validation and approval</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecurityCompliance;