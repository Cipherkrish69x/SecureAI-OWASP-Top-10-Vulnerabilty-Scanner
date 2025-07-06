import React, { useState } from 'react';
import { 
  BookOpen, 
  Shield, 
  Brain, 
  Code, 
  Globe, 
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Download
} from 'lucide-react';

const Documentation: React.FC = () => {
  const [activeSection, setActiveSection] = useState('overview');

  const sections = [
    { id: 'overview', title: 'Overview', icon: BookOpen },
    { id: 'architecture', title: 'Architecture', icon: Code },
    { id: 'ai-integration', title: 'AI Integration', icon: Brain },
    { id: 'owasp-mapping', title: 'OWASP Mapping', icon: Shield },
    { id: 'usage', title: 'Usage Guide', icon: Globe },
    { id: 'limitations', title: 'Limitations', icon: AlertTriangle },
  ];

  const renderContent = () => {
    switch (activeSection) {
      case 'overview':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-2xl font-bold text-slate-900 mb-4">SecureAI Scanner Overview</h3>
              <p className="text-slate-700 mb-4">
                SecureAI Scanner is an AI-powered web application vulnerability assessment tool designed to identify and analyze security vulnerabilities based on the OWASP Top 10 framework. The tool combines automated vulnerability scanning with intelligent AI analysis to provide comprehensive security insights and actionable recommendations.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                <div className="bg-blue-50 p-4 rounded-lg">
                  <Shield className="h-8 w-8 text-blue-600 mb-2" />
                  <h4 className="font-semibold text-blue-900">OWASP Top 10 Coverage</h4>
                  <p className="text-sm text-blue-700">Complete coverage of all OWASP Top 10 vulnerability categories</p>
                </div>
                <div className="bg-purple-50 p-4 rounded-lg">
                  <Brain className="h-8 w-8 text-purple-600 mb-2" />
                  <h4 className="font-semibold text-purple-900">AI-Enhanced Analysis</h4>
                  <p className="text-sm text-purple-700">Intelligent vulnerability analysis and remediation suggestions</p>
                </div>
                <div className="bg-green-50 p-4 rounded-lg">
                  <CheckCircle className="h-8 w-8 text-green-600 mb-2" />
                  <h4 className="font-semibold text-green-900">Ethical Guidelines</h4>
                  <p className="text-sm text-green-700">Built with responsible disclosure and ethical testing in mind</p>
                </div>
              </div>
            </div>
            
            <div>
              <h4 className="text-lg font-semibold text-slate-900 mb-3">Key Features</h4>
              <ul className="space-y-2 text-slate-700">
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
                  <span>Automated vulnerability scanning with multiple scan types (Quick, Deep, Comprehensive)</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
                  <span>AI-powered vulnerability analysis and remediation recommendations</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
                  <span>Real-time scanning progress with detailed status updates</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
                  <span>Comprehensive reporting with severity classification and confidence scores</span>
                </li>
                <li className="flex items-start space-x-2">
                  <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
                  <span>Interactive dashboard with vulnerability trends and statistics</span>
                </li>
              </ul>
            </div>
          </div>
        );

      case 'architecture':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-2xl font-bold text-slate-900 mb-4">System Architecture</h3>
              <p className="text-slate-700 mb-6">
                SecureAI Scanner is built using a modern, modular architecture that ensures scalability, maintainability, and extensibility.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-white p-6 rounded-lg border border-slate-200">
                <h4 className="text-lg font-semibold text-slate-900 mb-3">Frontend Components</h4>
                <ul className="space-y-2 text-sm text-slate-700">
                  <li>• <strong>React 18:</strong> Modern UI framework with hooks</li>
                  <li>• <strong>TypeScript:</strong> Type-safe development</li>
                  <li>• <strong>Tailwind CSS:</strong> Utility-first styling</li>
                  <li>• <strong>Lucide React:</strong> Consistent iconography</li>
                  <li>• <strong>Vite:</strong> Fast development and build tooling</li>
                </ul>
              </div>

              <div className="bg-white p-6 rounded-lg border border-slate-200">
                <h4 className="text-lg font-semibold text-slate-900 mb-3">Core Modules</h4>
                <ul className="space-y-2 text-sm text-slate-700">
                  <li>• <strong>Scan Engine:</strong> Vulnerability detection algorithms</li>
                  <li>• <strong>AI Integration:</strong> Machine learning analysis</li>
                  <li>• <strong>Result Processing:</strong> Data normalization and scoring</li>
                  <li>• <strong>Reporting Engine:</strong> Report generation and export</li>
                  <li>• <strong>Dashboard:</strong> Real-time visualization</li>
                </ul>
              </div>
            </div>

            <div className="bg-slate-50 p-6 rounded-lg">
              <h4 className="text-lg font-semibold text-slate-900 mb-3">Data Flow</h4>
              <div className="space-y-3">
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-semibold">1</div>
                  <span className="text-slate-700">User configures scan target and parameters</span>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-semibold">2</div>
                  <span className="text-slate-700">Scan engine performs vulnerability detection</span>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-semibold">3</div>
                  <span className="text-slate-700">AI analyzes findings and generates recommendations</span>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-semibold">4</div>
                  <span className="text-slate-700">Results are processed, scored, and presented</span>
                </div>
              </div>
            </div>
          </div>
        );

      case 'ai-integration':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-2xl font-bold text-slate-900 mb-4">AI Integration</h3>
              <p className="text-slate-700 mb-6">
                SecureAI Scanner leverages artificial intelligence to enhance vulnerability detection, analysis, and remediation guidance.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-purple-50 p-6 rounded-lg">
                <Brain className="h-8 w-8 text-purple-600 mb-3" />
                <h4 className="font-semibold text-purple-900 mb-2">Pattern Recognition</h4>
                <p className="text-sm text-purple-700">AI identifies complex vulnerability patterns that traditional scanners might miss</p>
              </div>
              <div className="bg-purple-50 p-6 rounded-lg">
                <Code className="h-8 w-8 text-purple-600 mb-3" />
                <h4 className="font-semibold text-purple-900 mb-2">Code Analysis</h4>
                <p className="text-sm text-purple-700">Intelligent static and dynamic code analysis for comprehensive security review</p>
              </div>
              <div className="bg-purple-50 p-6 rounded-lg">
                <CheckCircle className="h-8 w-8 text-purple-600 mb-3" />
                <h4 className="font-semibold text-purple-900 mb-2">Smart Recommendations</h4>
                <p className="text-sm text-purple-700">Context-aware remediation suggestions tailored to specific vulnerabilities</p>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg border border-slate-200">
              <h4 className="text-lg font-semibold text-slate-900 mb-4">AI Capabilities</h4>
              <div className="space-y-4">
                <div>
                  <h5 className="font-medium text-slate-900 mb-2">Vulnerability Classification</h5>
                  <p className="text-sm text-slate-700">
                    AI models classify vulnerabilities with high accuracy, reducing false positives and providing confidence scores for each finding.
                  </p>
                </div>
                <div>
                  <h5 className="font-medium text-slate-900 mb-2">Risk Assessment</h5>
                  <p className="text-sm text-slate-700">
                    Intelligent risk scoring based on vulnerability type, exploitability, and potential impact on the target application.
                  </p>
                </div>
                <div>
                  <h5 className="font-medium text-slate-900 mb-2">Remediation Guidance</h5>
                  <p className="text-sm text-slate-700">
                    AI generates specific, actionable remediation steps and even suggests code fixes for common vulnerability patterns.
                  </p>
                </div>
                <div>
                  <h5 className="font-medium text-slate-900 mb-2">Continuous Learning</h5>
                  <p className="text-sm text-slate-700">
                    The AI system continuously learns from new vulnerability data and attack patterns to improve detection accuracy.
                  </p>
                </div>
              </div>
            </div>
          </div>
        );

      case 'owasp-mapping':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-2xl font-bold text-slate-900 mb-4">OWASP Top 10 Mapping</h3>
              <p className="text-slate-700 mb-6">
                SecureAI Scanner provides comprehensive coverage of the OWASP Top 10 2021, the most critical security risks to web applications.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {[
                { id: 'A01', title: 'Broken Access Control', coverage: '95%' },
                { id: 'A02', title: 'Cryptographic Failures', coverage: '90%' },
                { id: 'A03', title: 'Injection', coverage: '98%' },
                { id: 'A04', title: 'Insecure Design', coverage: '85%' },
                { id: 'A05', title: 'Security Misconfiguration', coverage: '92%' },
                { id: 'A06', title: 'Vulnerable Components', coverage: '88%' },
                { id: 'A07', title: 'Authentication Failures', coverage: '94%' },
                { id: 'A08', title: 'Software and Data Integrity', coverage: '87%' },
                { id: 'A09', title: 'Logging and Monitoring Failures', coverage: '91%' },
                { id: 'A10', title: 'Server-Side Request Forgery', coverage: '93%' },
              ].map((item) => (
                <div key={item.id} className="bg-white p-4 rounded-lg border border-slate-200">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-semibold text-slate-900">{item.id}: {item.title}</h4>
                    <span className="text-sm font-medium text-green-600">{item.coverage}</span>
                  </div>
                  <div className="w-full bg-slate-200 rounded-full h-2">
                    <div
                      className="bg-green-500 h-2 rounded-full"
                      style={{ width: item.coverage }}
                    ></div>
                  </div>
                </div>
              ))}
            </div>

            <div className="bg-blue-50 p-6 rounded-lg">
              <h4 className="text-lg font-semibold text-blue-900 mb-3">Detection Techniques</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h5 className="font-medium text-blue-900 mb-2">Static Analysis</h5>
                  <ul className="text-sm text-blue-700 space-y-1">
                    <li>• Code structure analysis</li>
                    <li>• Configuration review</li>
                    <li>• Dependency scanning</li>
                  </ul>
                </div>
                <div>
                  <h5 className="font-medium text-blue-900 mb-2">Dynamic Analysis</h5>
                  <ul className="text-sm text-blue-700 space-y-1">
                    <li>• Runtime behavior monitoring</li>
                    <li>• Traffic pattern analysis</li>
                    <li>• Response inspection</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        );

      case 'usage':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-2xl font-bold text-slate-900 mb-4">Usage Guide</h3>
              <p className="text-slate-700 mb-6">
                Follow these steps to effectively use SecureAI Scanner for vulnerability assessment.
              </p>
            </div>

            <div className="space-y-6">
              <div className="bg-white p-6 rounded-lg border border-slate-200">
                <h4 className="text-lg font-semibold text-slate-900 mb-4">Step 1: Configure Scan Target</h4>
                <ol className="space-y-2 text-slate-700">
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">1.</span>
                    <span>Navigate to the Vulnerability Scanner tab</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">2.</span>
                    <span>Enter the target URL (ensure you have permission to scan)</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">3.</span>
                    <span>Select scan type: Quick (2-5 min), Deep (10-20 min), or Comprehensive (30-60 min)</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">4.</span>
                    <span>Choose OWASP Top 10 categories to include in the scan</span>
                  </li>
                </ol>
              </div>

              <div className="bg-white p-6 rounded-lg border border-slate-200">
                <h4 className="text-lg font-semibold text-slate-900 mb-4">Step 2: Execute Scan</h4>
                <ol className="space-y-2 text-slate-700">
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">1.</span>
                    <span>Click "Start Scan" to begin the vulnerability assessment</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">2.</span>
                    <span>Monitor real-time progress and scan steps</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">3.</span>
                    <span>Wait for AI analysis to complete</span>
                  </li>
                </ol>
              </div>

              <div className="bg-white p-6 rounded-lg border border-slate-200">
                <h4 className="text-lg font-semibold text-slate-900 mb-4">Step 3: Review Results</h4>
                <ol className="space-y-2 text-slate-700">
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">1.</span>
                    <span>Navigate to Scan Results tab to view findings</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">2.</span>
                    <span>Filter results by severity and status</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">3.</span>
                    <span>Click on individual results to view detailed information</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">4.</span>
                    <span>Review AI recommendations and suggested fixes</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="font-medium text-blue-600">5.</span>
                    <span>Export results to CSV for further analysis</span>
                  </li>
                </ol>
              </div>
            </div>

            <div className="bg-amber-50 p-6 rounded-lg border border-amber-200">
              <div className="flex items-start space-x-3">
                <AlertTriangle className="h-6 w-6 text-amber-600 mt-1" />
                <div>
                  <h4 className="font-semibold text-amber-900 mb-2">Important Guidelines</h4>
                  <ul className="text-sm text-amber-800 space-y-1">
                    <li>• Only scan applications you own or have explicit permission to test</li>
                    <li>• Use sandbox environments for testing whenever possible</li>
                    <li>• Follow responsible disclosure practices for any vulnerabilities found</li>
                    <li>• Respect rate limits and avoid causing service disruption</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        );

      case 'limitations':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-2xl font-bold text-slate-900 mb-4">Known Limitations</h3>
              <p className="text-slate-700 mb-6">
                While SecureAI Scanner provides comprehensive vulnerability assessment, it's important to understand its limitations and areas for improvement.
              </p>
            </div>

            <div className="space-y-6">
              <div className="bg-white p-6 rounded-lg border border-slate-200">
                <h4 className="text-lg font-semibold text-slate-900 mb-4">Technical Limitations</h4>
                <ul className="space-y-3 text-slate-700">
                  <li className="flex items-start space-x-2">
                    <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
                    <span><strong>False Positives:</strong> AI analysis may occasionally flag legitimate code as vulnerable</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
                    <span><strong>Complex Logic:</strong> May not detect vulnerabilities in highly complex business logic</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
                    <span><strong>Authentication:</strong> Limited ability to test authenticated sections without credentials</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
                    <span><strong>Client-Side:</strong> JavaScript-heavy applications may require additional analysis</span>
                  </li>
                </ul>
              </div>

              <div className="bg-white p-6 rounded-lg border border-slate-200">
                <h4 className="text-lg font-semibold text-slate-900 mb-4">Scope Limitations</h4>
                <ul className="space-y-3 text-slate-700">
                  <li className="flex items-start space-x-2">
                    <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
                    <span><strong>Infrastructure:</strong> Does not assess underlying server or network infrastructure</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
                    <span><strong>Mobile Apps:</strong> Limited support for mobile application security testing</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
                    <span><strong>APIs:</strong> GraphQL and some REST API patterns may need manual review</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
                    <span><strong>Zero-Day:</strong> Cannot detect previously unknown vulnerabilities</span>
                  </li>
                </ul>
              </div>

              <div className="bg-green-50 p-6 rounded-lg border border-green-200">
                <h4 className="text-lg font-semibold text-green-900 mb-4">Future Improvements</h4>
                <ul className="space-y-3 text-green-700">
                  <li className="flex items-start space-x-2">
                    <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
                    <span><strong>Enhanced AI Models:</strong> Continuous improvement of detection algorithms</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
                    <span><strong>API Integration:</strong> Better support for modern API architectures</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
                    <span><strong>Real-time Monitoring:</strong> Continuous security monitoring capabilities</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
                    <span><strong>Integration Platform:</strong> Integration with CI/CD pipelines and security tools</span>
                  </li>
                </ul>
              </div>
            </div>

            <div className="bg-slate-50 p-6 rounded-lg">
              <h4 className="text-lg font-semibold text-slate-900 mb-3">Best Practices</h4>
              <p className="text-slate-700 mb-4">
                To maximize the effectiveness of SecureAI Scanner, consider these best practices:
              </p>
              <ul className="space-y-2 text-slate-700">
                <li>• Combine automated scanning with manual security testing</li>
                <li>• Regularly update scan configurations based on your application changes</li>
                <li>• Validate findings in a controlled environment before applying fixes</li>
                <li>• Use multiple scanning tools for comprehensive coverage</li>
                <li>• Implement security testing as part of your development workflow</li>
              </ul>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="bg-gradient-to-r from-slate-700 to-slate-800 rounded-2xl p-8 text-white">
        <h2 className="text-3xl font-bold mb-2">Technical Documentation</h2>
        <p className="text-slate-300 text-lg">
          Comprehensive guide to SecureAI Scanner architecture, features, and usage
        </p>
      </div>

      {/* Navigation */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
        <div className="flex flex-wrap border-b border-slate-200">
          {sections.map((section) => {
            const Icon = section.icon;
            return (
              <button
                key={section.id}
                onClick={() => setActiveSection(section.id)}
                className={`flex items-center space-x-2 px-6 py-4 text-sm font-medium transition-colors ${
                  activeSection === section.id
                    ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{section.title}</span>
              </button>
            );
          })}
        </div>

        {/* Content */}
        <div className="p-8">
          {renderContent()}
        </div>
      </div>
    </div>
  );
};

export default Documentation;