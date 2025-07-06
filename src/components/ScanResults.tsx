import React, { useState } from 'react';
import { 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Brain, 
  Code, 
  ExternalLink,
  Copy,
  Eye,
  Filter,
  Download
} from 'lucide-react';
import { ScanResult } from '../types/vulnerability';

interface ScanResultsProps {
  results: ScanResult[];
}

const ScanResults: React.FC<ScanResultsProps> = ({ results }) => {
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');

  const filteredResults = results.filter(result => {
    const severityMatch = filterSeverity === 'all' || result.vulnerability.severity === filterSeverity;
    const statusMatch = filterStatus === 'all' || result.status === filterStatus;
    return severityMatch && statusMatch;
  });

  const severityStats = {
    Critical: results.filter(r => r.vulnerability.severity === 'Critical').length,
    High: results.filter(r => r.vulnerability.severity === 'High').length,
    Medium: results.filter(r => r.vulnerability.severity === 'Medium').length,
    Low: results.filter(r => r.vulnerability.severity === 'Low').length,
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'text-red-600 bg-red-100';
      case 'High': return 'text-orange-600 bg-orange-100';
      case 'Medium': return 'text-yellow-600 bg-yellow-100';
      case 'Low': return 'text-blue-600 bg-blue-100';
      default: return 'text-slate-600 bg-slate-100';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Open': return 'text-red-600 bg-red-100';
      case 'Fixed': return 'text-green-600 bg-green-100';
      case 'False Positive': return 'text-slate-600 bg-slate-100';
      default: return 'text-slate-600 bg-slate-100';
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const exportResults = () => {
    const csvContent = [
      ['URL', 'Vulnerability', 'Severity', 'Status', 'OWASP Category', 'Confidence', 'Date'],
      ...results.map(r => [
        r.url,
        r.vulnerability.name,
        r.vulnerability.severity,
        r.status,
        r.vulnerability.owaspCategory,
        `${r.confidence}%`,
        r.timestamp.toLocaleDateString()
      ])
    ].map(row => row.join(',')).join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnerability-scan-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (results.length === 0) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-16 w-16 text-slate-300 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-slate-900 mb-2">No Scan Results</h3>
        <p className="text-slate-600">
          Run a vulnerability scan to see results here.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Results Header */}
      <div className="bg-white rounded-xl p-6 shadow-sm border border-slate-200">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-2xl font-bold text-slate-900">Scan Results</h2>
            <p className="text-slate-600">{results.length} vulnerabilities found</p>
          </div>
          <button
            onClick={exportResults}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Download className="h-4 w-4" />
            <span>Export CSV</span>
          </button>
        </div>

        {/* Severity Summary */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {Object.entries(severityStats).map(([severity, count]) => (
            <div key={severity} className="text-center p-4 bg-slate-50 rounded-lg">
              <div className={`text-2xl font-bold ${getSeverityColor(severity).split(' ')[0]}`}>
                {count}
              </div>
              <div className="text-sm text-slate-600">{severity}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl p-6 shadow-sm border border-slate-200">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-slate-900">Filter Results</h3>
          <Filter className="h-5 w-5 text-slate-400" />
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Severity</label>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2">Status</label>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Statuses</option>
              <option value="Open">Open</option>
              <option value="Fixed">Fixed</option>
              <option value="False Positive">False Positive</option>
            </select>
          </div>
        </div>
      </div>

      {/* Results List */}
      <div className="space-y-4">
        {filteredResults.map((result) => (
          <div key={result.id} className="bg-white rounded-xl p-6 shadow-sm border border-slate-200">
            <div className="flex items-start justify-between mb-4">
              <div className="flex-1">
                <div className="flex items-center space-x-3 mb-2">
                  <h3 className="text-lg font-semibold text-slate-900">{result.vulnerability.name}</h3>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(result.vulnerability.severity)}`}>
                    {result.vulnerability.severity}
                  </span>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(result.status)}`}>
                    {result.status}
                  </span>
                </div>
                <div className="flex items-center space-x-4 text-sm text-slate-600 mb-2">
                  <span>URL: {result.url}</span>
                  <span>OWASP: {result.vulnerability.owaspCategory}</span>
                  <span>Confidence: {result.confidence}%</span>
                </div>
                <p className="text-sm text-slate-700">{result.vulnerability.description}</p>
              </div>
              <button
                onClick={() => setSelectedResult(selectedResult?.id === result.id ? null : result)}
                className="ml-4 p-2 text-slate-400 hover:text-slate-600 transition-colors"
              >
                <Eye className="h-5 w-5" />
              </button>
            </div>

            {selectedResult?.id === result.id && (
              <div className="mt-6 pt-6 border-t border-slate-200 space-y-6">
                {/* Vulnerability Details */}
                <div>
                  <h4 className="font-semibold text-slate-900 mb-2">Vulnerability Details</h4>
                  <div className="bg-slate-50 p-4 rounded-lg">
                    <p className="text-sm text-slate-700 mb-2"><strong>Impact:</strong> {result.vulnerability.impact}</p>
                    <p className="text-sm text-slate-700 mb-2"><strong>Evidence:</strong> {result.evidence}</p>
                    {result.vulnerability.cweId && (
                      <p className="text-sm text-slate-700"><strong>CWE ID:</strong> {result.vulnerability.cweId}</p>
                    )}
                  </div>
                </div>

                {/* AI Recommendation */}
                {result.aiRecommendation && (
                  <div>
                    <h4 className="font-semibold text-slate-900 mb-2 flex items-center space-x-2">
                      <Brain className="h-5 w-5 text-purple-600" />
                      <span>AI-Powered Recommendation</span>
                    </h4>
                    <div className="bg-purple-50 p-4 rounded-lg">
                      <p className="text-sm text-slate-700">{result.aiRecommendation}</p>
                    </div>
                  </div>
                )}

                {/* Fix Code */}
                {result.fixCode && (
                  <div>
                    <h4 className="font-semibold text-slate-900 mb-2 flex items-center space-x-2">
                      <Code className="h-5 w-5 text-green-600" />
                      <span>Suggested Fix</span>
                    </h4>
                    <div className="bg-slate-900 p-4 rounded-lg relative">
                      <pre className="text-sm text-green-400 overflow-x-auto">
                        <code>{result.fixCode}</code>
                      </pre>
                      <button
                        onClick={() => copyToClipboard(result.fixCode!)}
                        className="absolute top-2 right-2 p-1 text-slate-400 hover:text-white transition-colors"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                )}

                {/* Remediation */}
                <div>
                  <h4 className="font-semibold text-slate-900 mb-2">Remediation Steps</h4>
                  <div className="bg-green-50 p-4 rounded-lg">
                    <p className="text-sm text-slate-700">{result.vulnerability.remediation}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {filteredResults.length === 0 && (
        <div className="text-center py-8 text-slate-500">
          <p>No results match the selected filters.</p>
        </div>
      )}
    </div>
  );
};

export default ScanResults;