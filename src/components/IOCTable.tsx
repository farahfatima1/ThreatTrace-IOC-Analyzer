import React, { useState } from 'react';
import { IOCItem, IOCType, RiskLevel } from '../types';
import {
  Search,
  Copy,
  Check,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileSpreadsheet,
} from 'lucide-react';

interface IOCTableProps {
  items: IOCItem[];
  onExportCSV: () => void;
  onOpenUpload?: () => void;
}

export const IOCTable: React.FC<IOCTableProps> = ({ items, onExportCSV, onOpenUpload }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<IOCType | 'all'>('all');
  const [selectedRisk, setSelectedRisk] = useState<RiskLevel | 'all'>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const filteredItems = items.filter((item) => {
    if (selectedType !== 'all' && item.type !== selectedType) return false;
    if (selectedRisk !== 'all' && item.riskLevel !== selectedRisk) return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        item.value.toLowerCase().includes(q) ||
        item.matchedRule.toLowerCase().includes(q) ||
        item.ruleAssessment.description.toLowerCase().includes(q)
      );
    }

    return true;
  });

  const suspiciousCount = items.filter((i) => i.riskLevel === 'suspicious').length;
  const reviewCount = items.filter((i) => i.riskLevel === 'needs_review').length;
  const lowRiskCount = items.filter((i) => i.riskLevel === 'low_risk').length;

  return (
    <div className="bg-neutral-900 border border-neutral-800 rounded-xl overflow-hidden">
      {/* Toolbar */}
      <div className="p-4 border-b border-neutral-800 flex flex-wrap items-center justify-between gap-3 bg-neutral-950/50">
        {/* Segmented Risk Filter Tabs */}
        <div className="flex items-center gap-1 p-1 bg-neutral-950 border border-neutral-800 rounded-lg text-xs font-medium">
          <button
            onClick={() => setSelectedRisk('all')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              selectedRisk === 'all'
                ? 'bg-neutral-800 text-white'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            All ({items.length})
          </button>
          <button
            onClick={() => setSelectedRisk('suspicious')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              selectedRisk === 'suspicious'
                ? 'bg-red-950/60 text-red-300'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            Suspicious ({suspiciousCount})
          </button>
          <button
            onClick={() => setSelectedRisk('needs_review')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              selectedRisk === 'needs_review'
                ? 'bg-amber-950/60 text-amber-300'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            Needs Review ({reviewCount})
          </button>
          <button
            onClick={() => setSelectedRisk('low_risk')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              selectedRisk === 'low_risk'
                ? 'bg-emerald-950/60 text-emerald-300'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            Low Risk ({lowRiskCount})
          </button>
        </div>

        {/* Search, Type Select & Export CSV */}
        <div className="flex flex-wrap items-center gap-2 flex-1 justify-end min-w-[260px]">
          <div className="relative flex-1 max-w-xs min-w-[180px]">
            <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-neutral-500" />
            <input
              type="text"
              placeholder="Search indicator or rule..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-neutral-950 border border-neutral-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-neutral-200 placeholder-neutral-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value as IOCType | 'all')}
            className="bg-neutral-950 border border-neutral-800 rounded-lg px-2.5 py-1.5 text-xs text-neutral-200 focus:outline-none focus:border-blue-500 cursor-pointer"
          >
            <option value="all">All Types</option>
            <option value="ip">IPs ({items.filter((i) => i.type === 'ip').length})</option>
            <option value="domain">Domains ({items.filter((i) => i.type === 'domain').length})</option>
            <option value="url">URLs ({items.filter((i) => i.type === 'url').length})</option>
            <option value="hash">Hashes ({items.filter((i) => i.type === 'hash').length})</option>
          </select>

          <button
            onClick={onExportCSV}
            disabled={items.length === 0}
            className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-neutral-950 hover:bg-neutral-800 border border-neutral-800 text-neutral-200 disabled:opacity-40 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Results Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-neutral-950/70 border-b border-neutral-800 text-neutral-400 font-semibold">
              <th className="py-3 px-4 w-40">Risk Level</th>
              <th className="py-3 px-4 w-24">Type</th>
              <th className="py-3 px-4">Indicator</th>
              <th className="py-3 px-4">Reason (Rule Assessment)</th>
              <th className="py-3 px-4 w-16 text-right">Copy</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-800/60">
            {filteredItems.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-12 text-center text-neutral-400">
                  {items.length === 0 ? (
                    <div className="space-y-2">
                      <p className="text-sm font-semibold text-neutral-200">No indicators loaded</p>
                      <p className="text-xs text-neutral-400">
                        Upload a .log or .txt file above to extract and inspect IPs, domains, URLs, and hashes.
                      </p>
                      {onOpenUpload && (
                        <button
                          onClick={onOpenUpload}
                          className="mt-1 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors cursor-pointer"
                        >
                          Upload .log or .txt File
                        </button>
                      )}
                    </div>
                  ) : (
                    <p className="text-sm">No indicators match your current filter.</p>
                  )}
                </td>
              </tr>
            ) : (
              filteredItems.map((item) => {
                const isSuspicious = item.riskLevel === 'suspicious';
                const isNeedsReview = item.riskLevel === 'needs_review';

                return (
                  <tr key={item.id} className="hover:bg-neutral-800/35 transition-colors">
                    {/* Risk Badge */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      {isSuspicious ? (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-red-950/50 border border-red-800/60 text-red-400 font-semibold text-xs">
                          <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                          <span>Suspicious</span>
                        </span>
                      ) : isNeedsReview ? (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-950/50 border border-amber-800/60 text-amber-400 font-semibold text-xs">
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                          <span>Needs Review</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-950/50 border border-emerald-800/60 text-emerald-400 font-semibold text-xs">
                          <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                          <span>Low Risk</span>
                        </span>
                      )}
                    </td>

                    {/* Type */}
                    <td className="py-3 px-4 font-mono">
                      <span className="text-xs font-semibold text-neutral-300 uppercase">
                        {item.type}
                      </span>
                      {item.hashAlgorithm && (
                        <span className="block text-[11px] text-neutral-400 font-sans">
                          {item.hashAlgorithm}
                        </span>
                      )}
                    </td>

                    {/* Indicator Value */}
                    <td className="py-3 px-4 font-mono max-w-md">
                      <span
                        className={`block truncate text-xs ${
                          isSuspicious
                            ? 'text-red-300 font-semibold'
                            : isNeedsReview
                            ? 'text-amber-200'
                            : 'text-neutral-200'
                        }`}
                        title={item.value}
                      >
                        {item.value}
                      </span>
                    </td>

                    {/* Plain-English Rule & Reason */}
                    <td className="py-3 px-4">
                      <div className="text-neutral-200 font-medium">{item.matchedRule}</div>
                      <div className="text-neutral-400 text-[11px] mt-0.5 line-clamp-2" title={item.ruleAssessment.evidence}>
                        {item.ruleAssessment.description}
                      </div>
                    </td>

                    {/* Copy Button */}
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleCopy(item.id, item.value)}
                        className="p-1.5 rounded-md text-neutral-400 hover:text-white hover:bg-neutral-800 transition-colors cursor-pointer"
                        title="Copy indicator"
                      >
                        {copiedId === item.id ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="px-4 py-2.5 bg-neutral-950/70 border-t border-neutral-800 flex flex-wrap items-center justify-between gap-2 text-xs text-neutral-400">
        <span>
          Showing {filteredItems.length} of {items.length} unique indicators
        </span>
        <span>
          Local pattern assessment only · Not verified against external threat feeds
        </span>
      </div>
    </div>
  );
};
