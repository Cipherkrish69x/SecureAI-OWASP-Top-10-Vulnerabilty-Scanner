import React from 'react';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  TrendingUp, 
  Brain, 
  Target,
  Clock,
  Zap
} from 'lucide-react';
import { ScanResult } from '../types/vulnerability';

interface DashboardProps {
  scanResults: ScanResult[];
  onStartScan: () => void;
}

const Dashboard: React.FC<DashboardProps> = ({ scanResults, onStartScan }) => {
  const criticalVulns = scanResults.filter(r => r.vulnerability.severity === 'Critical').length;
  const highVulns = scanResults.filter(r => r.vulnerability.severity === 'High').length;
  const mediumVulns = scanResults.filter(r => r.vulnerability.severity === 'Medium').length;
  const lowVulns = scanResults.filter(r => r.vulnerability.severity === 'Low').length;

  const totalVulns = scanResults.length;
  const openVulns = scanResults.filter(r => r.status === 'Open').length;
  const fixedVulns = scanResults.filter(r => r.status === 'Fixed').length;

  const stats = [
    {
      title: 'Total Vulnerabilities',
      value: totalVulns,
      icon: Shield,
      color: 'bg-blue-500',
      trend: '+12% from last scan'
    },
    {
      title: 'Critical Issues',
      value: criticalVulns,
      icon: AlertTriangle,
      color: 'bg-red-500',
      trend: 'Immediate attention required'
    },
    {
      title: 'Fixed Issues',
      value: fixedVulns,
      icon: CheckCircle,
      color: 'bg-green-500',
      trend: `${Math.round((fixedVulns / totalVulns) * 100) || 0}% resolution rate`
    },
    {
      title: 'AI Recommendations',
      value: scanResults.filter(r => r.aiRecommendation).length,
      icon: Brain,
      color: 'bg-purple-500',
      trend: 'Enhanced with AI insights'
    }
  ];

  const owaspCategories = [
    'A01:2021 – Broken Access Control',
    'A02:2021 – Cryptographic Failures',
    'A03:2021 – Injection',
    'A04:2021 – Insecure Design',
    'A05:2021 – Security Misconfiguration',
    'A06:2021 – Vulnerable Components',
    'A07:2021 – Identification and Authentication Failures',
    'A08:2021 – Software and Data Integrity Failures',
    'A09:2021 – Security Logging and Monitoring Failures',
    'A10:2021 – Server-Side Request Forgery'
  ];

  return (
    <div className="space-y-8">
      {/* Hero Section */}
      <div className="bg-gradient-to-r from-blue-600 to-purple-700 rounded-2xl p-8 text-white">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-3xl font-bold mb-2">AI-Powered Security Assessment</h2>
            <p className="text-blue-100 text-lg mb-6">
              Comprehensive vulnerability scanning based on OWASP Top 10 with intelligent AI analysis
            </p>
            <button
              onClick={onStartScan}
              className="bg-white text-blue-600 px-6 py-3 rounded-lg font-semibold hover:bg-blue-50 transition-colors flex items-center space-x-2"
            >
              <Zap className="h-5 w-5" />
              <span>Start New Scan</span>
            </button>
          </div>
          <div className="hidden md:block">
            <div className="bg-white/10 backdrop-blur-sm rounded-xl p-6">
              <Target className="h-16 w-16 text-white mb-4" />
              <div className="text-center">
                <div className="text-2xl font-bold">OWASP</div>
                <div className="text-sm text-blue-100">Top 10 Coverage</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <div key={index} className="bg-white rounded-xl p-6 shadow-sm border border-slate-200">
              <div className="flex items-center justify-between mb-4">
                <div className={`p-3 rounded-lg ${stat.color}`}>
                  <Icon className="h-6 w-6 text-white" />
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-slate-900">{stat.value}</div>
                  <div className="text-sm text-slate-500">{stat.title}</div>
                </div>
              </div>
              <div className="text-sm text-slate-600">{stat.trend}</div>
            </div>
          );
        })}
      </div>

      {/* Vulnerability Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="bg-white rounded-xl p-6 shadow-sm border border-slate-200">
          <h3 className="text-lg font-semibold text-slate-900 mb-6">Vulnerability Severity Distribution</h3>
          <div className="space-y-4">
            {[
              { label: 'Critical', count: criticalVulns, color: 'bg-red-500', total: totalVulns },
              { label: 'High', count: highVulns, color: 'bg-orange-500', total: totalVulns },
              { label: 'Medium', count: mediumVulns, color: 'bg-yellow-500', total: totalVulns },
              { label: 'Low', count: lowVulns, color: 'bg-blue-500', total: totalVulns }
            ].map((item) => (
              <div key={item.label} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className={`w-3 h-3 rounded-full ${item.color}`}></div>
                  <span className="text-sm font-medium text-slate-700">{item.label}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-slate-900 font-semibold">{item.count}</span>
                  <div className="w-24 bg-slate-200 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${item.color}`}
                      style={{ width: `${item.total > 0 ? (item.count / item.total) * 100 : 0}%` }}
                    ></div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl p-6 shadow-sm border border-slate-200">
          <h3 className="text-lg font-semibold text-slate-900 mb-6">OWASP Top 10 Coverage</h3>
          <div className="space-y-3">
            {owaspCategories.slice(0, 6).map((category, index) => (
              <div key={index} className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span className="text-sm text-slate-700">{category.split('–')[0]}</span>
                </div>
                <span className="text-xs text-slate-500">Covered</span>
              </div>
            ))}
            <div className="pt-2">
              <button className="text-sm text-blue-600 hover:text-blue-700 font-medium">
                View all categories →
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="bg-white rounded-xl p-6 shadow-sm border border-slate-200">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-slate-900">Recent Scan Activity</h3>
          <Clock className="h-5 w-5 text-slate-400" />
        </div>
        {scanResults.length > 0 ? (
          <div className="space-y-4">
            {scanResults.slice(0, 3).map((result) => (
              <div key={result.id} className="flex items-center justify-between py-3 border-b border-slate-100 last:border-b-0">
                <div className="flex items-center space-x-3">
                  <div className={`p-2 rounded-lg ${
                    result.vulnerability.severity === 'Critical' ? 'bg-red-100' :
                    result.vulnerability.severity === 'High' ? 'bg-orange-100' :
                    result.vulnerability.severity === 'Medium' ? 'bg-yellow-100' :
                    'bg-blue-100'
                  }`}>
                    <AlertTriangle className={`h-4 w-4 ${
                      result.vulnerability.severity === 'Critical' ? 'text-red-600' :
                      result.vulnerability.severity === 'High' ? 'text-orange-600' :
                      result.vulnerability.severity === 'Medium' ? 'text-yellow-600' :
                      'text-blue-600'
                    }`} />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-slate-900">{result.vulnerability.name}</div>
                    <div className="text-xs text-slate-500">{result.url}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className={`text-sm font-medium ${
                    result.vulnerability.severity === 'Critical' ? 'text-red-600' :
                    result.vulnerability.severity === 'High' ? 'text-orange-600' :
                    result.vulnerability.severity === 'Medium' ? 'text-yellow-600' :
                    'text-blue-600'
                  }`}>
                    {result.vulnerability.severity}
                  </div>
                  <div className="text-xs text-slate-500">
                    {result.timestamp.toLocaleDateString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-slate-500">
            <Shield className="h-12 w-12 mx-auto mb-4 text-slate-300" />
            <p>No scans completed yet. Start your first security assessment!</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;