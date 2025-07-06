import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  TrendingUp, 
  Globe, 
  Target,
  Activity,
  Zap,
  Eye
} from 'lucide-react';

interface ThreatData {
  id: string;
  name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  trend: 'up' | 'down' | 'stable';
  description: string;
  count: number;
}

const ThreatIntelligence: React.FC = () => {
  const [threatData, setThreatData] = useState<ThreatData[]>([
    {
      id: '1',
      name: 'SQL Injection Attacks',
      severity: 'Critical',
      trend: 'up',
      description: 'Increased SQL injection attempts targeting authentication systems',
      count: 2847
    },
    {
      id: '2',
      name: 'XSS Exploits',
      severity: 'High',
      trend: 'up',
      description: 'Cross-site scripting attacks using obfuscated payloads',
      count: 1923
    },
    {
      id: '3',
      name: 'Broken Access Control',
      severity: 'Critical',
      trend: 'stable',
      description: 'Privilege escalation attempts in web applications',
      count: 1456
    },
    {
      id: '4',
      name: 'Cryptographic Failures',
      severity: 'High',
      trend: 'down',
      description: 'Weak encryption implementations being exploited',
      count: 987
    }
  ]);

  const [globalStats, setGlobalStats] = useState({
    totalThreats: 12847,
    activeCampaigns: 156,
    newVulnerabilities: 23,
    riskScore: 78
  });

  useEffect(() => {
    // Simulate real-time threat intelligence updates
    const interval = setInterval(() => {
      setThreatData(prev => prev.map(threat => ({
        ...threat,
        count: threat.count + Math.floor(Math.random() * 10) - 5
      })));

      setGlobalStats(prev => ({
        ...prev,
        totalThreats: prev.totalThreats + Math.floor(Math.random() * 20) - 10,
        riskScore: Math.max(0, Math.min(100, prev.riskScore + Math.floor(Math.random() * 6) - 3))
      }));
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'text-red-600 bg-red-100';
      case 'High': return 'text-orange-600 bg-orange-100';
      case 'Medium': return 'text-yellow-600 bg-yellow-100';
      case 'Low': return 'text-blue-600 bg-blue-100';
      default: return 'text-slate-600 bg-slate-100';
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up': return <TrendingUp className="h-4 w-4 text-red-500" />;
      case 'down': return <TrendingUp className="h-4 w-4 text-green-500 transform rotate-180" />;
      default: return <Activity className="h-4 w-4 text-blue-500" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Global Threat Overview */}
      <div className="bg-gradient-to-r from-slate-800 to-slate-900 rounded-2xl p-6 text-white">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h3 className="text-2xl font-bold mb-2">Global Threat Intelligence</h3>
            <p className="text-slate-300">Real-time security threat monitoring and analysis</p>
          </div>
          <div className="flex items-center space-x-2 bg-white/10 backdrop-blur-sm rounded-lg px-4 py-2">
            <Eye className="h-5 w-5" />
            <span className="text-sm font-medium">Live Monitoring</span>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4">
            <div className="flex items-center space-x-2 mb-2">
              <Shield className="h-5 w-5 text-blue-400" />
              <span className="text-sm text-slate-300">Total Threats</span>
            </div>
            <div className="text-2xl font-bold">{globalStats.totalThreats.toLocaleString()}</div>
          </div>
          
          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4">
            <div className="flex items-center space-x-2 mb-2">
              <Target className="h-5 w-5 text-orange-400" />
              <span className="text-sm text-slate-300">Active Campaigns</span>
            </div>
            <div className="text-2xl font-bold">{globalStats.activeCampaigns}</div>
          </div>
          
          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4">
            <div className="flex items-center space-x-2 mb-2">
              <Zap className="h-5 w-5 text-purple-400" />
              <span className="text-sm text-slate-300">New Vulnerabilities</span>
            </div>
            <div className="text-2xl font-bold">{globalStats.newVulnerabilities}</div>
          </div>
          
          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4">
            <div className="flex items-center space-x-2 mb-2">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              <span className="text-sm text-slate-300">Risk Score</span>
            </div>
            <div className="text-2xl font-bold">{globalStats.riskScore}/100</div>
          </div>
        </div>
      </div>

      {/* Active Threats */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200">
        <div className="p-6 border-b border-slate-200">
          <h4 className="text-lg font-semibold text-slate-900">Active Threat Landscape</h4>
          <p className="text-slate-600">Current threats being monitored by our AI systems</p>
        </div>
        
        <div className="p-6">
          <div className="space-y-4">
            {threatData.map((threat) => (
              <div key={threat.id} className="flex items-center justify-between p-4 bg-slate-50 rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className={`p-2 rounded-lg ${getSeverityColor(threat.severity)}`}>
                    <AlertTriangle className="h-5 w-5" />
                  </div>
                  <div>
                    <h5 className="font-semibold text-slate-900">{threat.name}</h5>
                    <p className="text-sm text-slate-600">{threat.description}</p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-4">
                  <div className="text-right">
                    <div className="text-lg font-bold text-slate-900">{threat.count.toLocaleString()}</div>
                    <div className="text-xs text-slate-500">detections</div>
                  </div>
                  <div className="flex items-center space-x-1">
                    {getTrendIcon(threat.trend)}
                  </div>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                    {threat.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* AI Threat Prediction */}
      <div className="bg-gradient-to-br from-purple-50 to-blue-50 rounded-xl p-6 border border-purple-200">
        <div className="flex items-center space-x-3 mb-4">
          <div className="p-3 bg-purple-600 rounded-lg">
            <Target className="h-6 w-6 text-white" />
          </div>
          <div>
            <h4 className="text-lg font-semibold text-slate-900">AI Threat Prediction</h4>
            <p className="text-slate-600">Machine learning predictions for emerging threats</p>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white p-4 rounded-lg shadow-sm">
            <h5 className="font-medium text-slate-900 mb-2">Predicted Attack Vector</h5>
            <p className="text-sm text-slate-700">API endpoint exploitation via parameter pollution</p>
            <div className="mt-2 text-xs text-purple-600 font-medium">85% confidence</div>
          </div>
          
          <div className="bg-white p-4 rounded-lg shadow-sm">
            <h5 className="font-medium text-slate-900 mb-2">Emerging Vulnerability</h5>
            <p className="text-sm text-slate-700">JWT token manipulation in authentication flows</p>
            <div className="mt-2 text-xs text-purple-600 font-medium">78% confidence</div>
          </div>
          
          <div className="bg-white p-4 rounded-lg shadow-sm">
            <h5 className="font-medium text-slate-900 mb-2">Risk Assessment</h5>
            <p className="text-sm text-slate-700">Increased activity in financial sector targeting</p>
            <div className="mt-2 text-xs text-purple-600 font-medium">92% confidence</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatIntelligence;