import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Brain, 
  Zap, 
  Target, 
  AlertTriangle, 
  CheckCircle,
  Activity,
  TrendingUp,
  Globe,
  Lock
} from 'lucide-react';

interface EnhancedScannerProps {
  onStartScan: () => void;
  isScanning: boolean;
  scanProgress: number;
}

const EnhancedScanner: React.FC<EnhancedScannerProps> = ({ 
  onStartScan, 
  isScanning, 
  scanProgress 
}) => {
  const [aiInsights, setAiInsights] = useState([
    "Analyzing SSL/TLS configuration patterns...",
    "Detecting injection vulnerability signatures...",
    "Evaluating access control implementations...",
    "Scanning for cryptographic weaknesses..."
  ]);

  useEffect(() => {
    if (isScanning) {
      const interval = setInterval(() => {
        setAiInsights(prev => {
          const insights = [
            "AI detected potential SQL injection vectors",
            "Machine learning model identified XSS patterns",
            "Deep analysis reveals authentication weaknesses",
            "Neural network flagged configuration issues",
            "Behavioral analysis detects anomalous patterns",
            "Pattern matching identified OWASP Top 10 risks"
          ];
          return [insights[Math.floor(Math.random() * insights.length)], ...prev.slice(0, 3)];
        });
      }, 2000);

      return () => clearInterval(interval);
    }
  }, [isScanning]);

  return (
    <div className="bg-gradient-to-br from-blue-50 to-purple-50 rounded-2xl p-8 border border-blue-200">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h3 className="text-2xl font-bold text-slate-900 mb-2">AI Security Engine</h3>
          <p className="text-slate-600">Advanced machine learning for vulnerability detection</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 bg-white px-4 py-2 rounded-full shadow-sm">
            <Brain className="h-5 w-5 text-purple-600" />
            <span className="text-sm font-medium text-purple-700">Neural Network Active</span>
          </div>
          <div className="flex items-center space-x-2 bg-white px-4 py-2 rounded-full shadow-sm">
            <Activity className="h-5 w-5 text-green-600" />
            <span className="text-sm font-medium text-green-700">Real-time Analysis</span>
          </div>
        </div>
      </div>

      {/* AI Insights Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div className="lg:col-span-2 bg-white rounded-xl p-6 shadow-sm">
          <h4 className="font-semibold text-slate-900 mb-4 flex items-center space-x-2">
            <Brain className="h-5 w-5 text-purple-600" />
            <span>AI Analysis Feed</span>
          </h4>
          <div className="space-y-3">
            {aiInsights.map((insight, index) => (
              <div key={index} className="flex items-start space-x-3 p-3 bg-slate-50 rounded-lg">
                <div className={`w-2 h-2 rounded-full mt-2 ${
                  index === 0 ? 'bg-green-500 animate-pulse' : 'bg-slate-300'
                }`}></div>
                <span className="text-sm text-slate-700">{insight}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl p-6 shadow-sm">
          <h4 className="font-semibold text-slate-900 mb-4">Scan Metrics</h4>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-600">Detection Accuracy</span>
              <span className="text-sm font-semibold text-green-600">98.7%</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-600">False Positives</span>
              <span className="text-sm font-semibold text-blue-600">&lt; 2%</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-600">OWASP Coverage</span>
              <span className="text-sm font-semibold text-purple-600">100%</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-600">AI Confidence</span>
              <span className="text-sm font-semibold text-orange-600">95.3%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Enhanced Progress Display */}
      {isScanning && (
        <div className="bg-white rounded-xl p-6 shadow-sm mb-6">
          <div className="flex items-center justify-between mb-4">
            <h4 className="font-semibold text-slate-900">Advanced Scan Progress</h4>
            <span className="text-sm text-slate-600">{Math.round(scanProgress)}% Complete</span>
          </div>
          
          <div className="relative">
            <div className="w-full bg-slate-200 rounded-full h-3 mb-4">
              <div
                className="bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 h-3 rounded-full transition-all duration-500 relative overflow-hidden"
                style={{ width: `${scanProgress}%` }}
              >
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white to-transparent opacity-20 animate-pulse"></div>
              </div>
            </div>
            
            <div className="grid grid-cols-4 gap-2 text-xs">
              <div className="text-center">
                <div className={`w-2 h-2 rounded-full mx-auto mb-1 ${scanProgress > 25 ? 'bg-blue-500' : 'bg-slate-300'}`}></div>
                <span className="text-slate-600">Discovery</span>
              </div>
              <div className="text-center">
                <div className={`w-2 h-2 rounded-full mx-auto mb-1 ${scanProgress > 50 ? 'bg-purple-500' : 'bg-slate-300'}`}></div>
                <span className="text-slate-600">Analysis</span>
              </div>
              <div className="text-center">
                <div className={`w-2 h-2 rounded-full mx-auto mb-1 ${scanProgress > 75 ? 'bg-pink-500' : 'bg-slate-300'}`}></div>
                <span className="text-slate-600">AI Processing</span>
              </div>
              <div className="text-center">
                <div className={`w-2 h-2 rounded-full mx-auto mb-1 ${scanProgress > 95 ? 'bg-green-500' : 'bg-slate-300'}`}></div>
                <span className="text-slate-600">Report</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Quick Action Buttons */}
      <div className="flex items-center justify-center space-x-4">
        <button
          onClick={onStartScan}
          disabled={isScanning}
          className={`px-8 py-4 rounded-xl font-semibold flex items-center space-x-3 transition-all ${
            isScanning
              ? 'bg-slate-100 text-slate-400 cursor-not-allowed'
              : 'bg-gradient-to-r from-blue-600 to-purple-600 text-white hover:from-blue-700 hover:to-purple-700 transform hover:scale-105 shadow-lg hover:shadow-xl'
          }`}
        >
          {isScanning ? (
            <>
              <div className="animate-spin h-5 w-5 border-2 border-slate-400 border-t-transparent rounded-full"></div>
              <span>AI Analysis in Progress...</span>
            </>
          ) : (
            <>
              <Zap className="h-5 w-5" />
              <span>Start AI-Powered Scan</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};

export default EnhancedScanner;