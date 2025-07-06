import React, { useState } from 'react';
import { Shield, Search, AlertTriangle, CheckCircle, Brain, Target, Code, Globe, Activity } from 'lucide-react';
import Dashboard from './components/Dashboard';
import VulnerabilityScanner from './components/VulnerabilityScanner';
import OWASP10Coverage from './components/OWASP10Coverage';
import ScanResults from './components/ScanResults';
import Documentation from './components/Documentation';
import ThreatIntelligence from './components/ThreatIntelligence';
import SecurityCompliance from './components/SecurityCompliance';
import EnhancedScanner from './components/EnhancedScanner';
import { ScanResult } from './types/vulnerability';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Shield },
    { id: 'scanner', label: 'AI Scanner', icon: Search },
    { id: 'owasp10', label: 'OWASP Top 10', icon: Target },
    { id: 'results', label: 'Scan Results', icon: AlertTriangle },
    { id: 'intelligence', label: 'Threat Intel', icon: Activity },
    { id: 'compliance', label: 'Compliance', icon: CheckCircle },
    { id: 'docs', label: 'Documentation', icon: Code },
  ];

  const handleScanComplete = (results: ScanResult[]) => {
    setScanResults(results);
    setIsScanning(false);
    setScanProgress(0);
    setActiveTab('results');
  };

  const handleScanStart = () => {
    setIsScanning(true);
    setScanProgress(0);
    
    // Simulate scanning progress
    const interval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          return 100;
        }
        return prev + Math.random() * 15;
      });
    }, 800);
  };

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard scanResults={scanResults} onStartScan={() => setActiveTab('scanner')} />;
      case 'scanner':
        return (
          <div className="space-y-8">
            <EnhancedScanner 
              onStartScan={handleScanStart}
              isScanning={isScanning}
              scanProgress={scanProgress}
            />
            <VulnerabilityScanner
              onScanComplete={handleScanComplete}
              onScanStart={handleScanStart}
              isScanning={isScanning}
            />
          </div>
        );
      case 'owasp10':
        return <OWASP10Coverage />;
      case 'results':
        return <ScanResults results={scanResults} />;
      case 'intelligence':
        return <ThreatIntelligence />;
      case 'compliance':
        return <SecurityCompliance />;
      case 'docs':
        return <Documentation />;
      default:
        return <Dashboard scanResults={scanResults} onStartScan={() => setActiveTab('scanner')} />;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-purple-50">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm shadow-sm border-b border-slate-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-gradient-to-r from-blue-500 via-purple-600 to-pink-500 rounded-xl">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                  SecureAI Scanner
                </h1>
                <p className="text-sm text-slate-600">AI-Powered OWASP Top 10 Assessment</p>
              </div>
            </div>
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-2 bg-purple-100 px-3 py-1.5 rounded-lg">
                <Brain className="h-4 w-4 text-purple-600" />
                <span className="text-sm font-medium text-purple-700">Neural Network</span>
              </div>
              <div className="flex items-center space-x-2 bg-green-100 px-3 py-1.5 rounded-lg">
                <Activity className="h-4 w-4 text-green-600" />
                <span className="text-sm font-medium text-green-700">Live Intel</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white/60 backdrop-blur-sm shadow-sm border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8 overflow-x-auto">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-2 px-1 py-4 text-sm font-medium border-b-2 transition-all whitespace-nowrap ${
                    activeTab === tab.id
                      ? 'text-blue-600 border-blue-600 bg-blue-50/50'
                      : 'text-slate-600 border-transparent hover:text-slate-900 hover:border-slate-300'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {renderContent()}
      </main>

      {/* Footer */}
      <footer className="bg-white/80 backdrop-blur-sm border-t border-slate-200 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Globe className="h-5 w-5 text-slate-400" />
                <span className="text-sm text-slate-600">
                  Ethical testing on authorized environments only
                </span>
              </div>
              <div className="hidden md:flex items-center space-x-2">
                <Shield className="h-5 w-5 text-green-500" />
                <span className="text-sm text-slate-600">OWASP Top 10 Compliant</span>
              </div>
            </div>
            <div className="text-sm text-slate-500">
              Built with AI • Neural Network Enhanced • Responsible Disclosure
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;