import React from 'react';
import { SummaryStats } from '../types';
import { AlertTriangle, Layers, ShieldCheck, ShieldAlert } from 'lucide-react';

interface MetricsOverviewProps {
  stats: SummaryStats;
}

export const MetricsOverview: React.FC<MetricsOverviewProps> = ({ stats }) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Total Indicators */}
      <div className="p-4 rounded-xl bg-neutral-900 border border-neutral-800 flex flex-col justify-between">
        <div className="flex items-center justify-between text-neutral-400">
          <span className="text-xs font-medium text-neutral-400">Total Indicators</span>
          <Layers className="w-4 h-4 text-blue-400" />
        </div>
        <div className="mt-2 flex items-baseline justify-between gap-2">
          <span className="text-2xl font-bold font-mono tabular-nums text-white">{stats.total}</span>
          <span className="text-xs text-neutral-400 truncate">
            {stats.byType.ip} IP · {stats.byType.domain} Dom · {stats.byType.url} URL · {stats.byType.hash} Hash
          </span>
        </div>
      </div>

      {/* Suspicious */}
      <div className="p-4 rounded-xl bg-neutral-900 border border-red-900/40 flex flex-col justify-between">
        <div className="flex items-center justify-between text-red-400">
          <span className="text-xs font-medium">Suspicious</span>
          <ShieldAlert className="w-4 h-4 text-red-400" />
        </div>
        <div className="mt-2 flex items-baseline justify-between gap-2">
          <span className="text-2xl font-bold font-mono tabular-nums text-red-400">{stats.suspicious}</span>
          <span className="text-xs text-neutral-400">Flagged by local rules</span>
        </div>
      </div>

      {/* Needs Review */}
      <div className="p-4 rounded-xl bg-neutral-900 border border-amber-900/40 flex flex-col justify-between">
        <div className="flex items-center justify-between text-amber-400">
          <span className="text-xs font-medium">Needs Review</span>
          <AlertTriangle className="w-4 h-4 text-amber-400" />
        </div>
        <div className="mt-2 flex items-baseline justify-between gap-2">
          <span className="text-2xl font-bold font-mono tabular-nums text-amber-400">{stats.needsReview}</span>
          <span className="text-xs text-neutral-400">External items to check</span>
        </div>
      </div>

      {/* Low Risk */}
      <div className="p-4 rounded-xl bg-neutral-900 border border-emerald-900/40 flex flex-col justify-between">
        <div className="flex items-center justify-between text-emerald-400">
          <span className="text-xs font-medium">Low Risk</span>
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="mt-2 flex items-baseline justify-between gap-2">
          <span className="text-2xl font-bold font-mono tabular-nums text-emerald-400">{stats.lowRisk}</span>
          <span className="text-xs text-neutral-400">Private or trusted</span>
        </div>
      </div>
    </div>
  );
};
