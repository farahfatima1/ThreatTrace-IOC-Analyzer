import React from 'react';
import { Shield, Upload } from 'lucide-react';

interface HeaderProps {
  onOpenUpload: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onOpenUpload }) => {
  return (
    <header className="sticky top-0 z-30 flex items-center justify-between gap-8 px-6 py-3.5 bg-neutral-950/90 backdrop-blur-md border-b border-neutral-800">
      {/* Zone 1: Brand Title */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-blue-600/10 border border-blue-500/20 text-blue-400">
          <Shield className="w-4 h-4" />
        </div>
        <a
          href="/"
          className="text-base font-bold tracking-tight text-white whitespace-nowrap shrink-0 hover:text-neutral-200 transition-colors"
        >
          ThreatTrace
        </a>
      </div>

      {/* Zone 2: Simple Context */}
      <div className="hidden md:flex items-center gap-3 text-xs text-neutral-400">
        <span>IOC Analyzer</span>
        <span aria-hidden="true">·</span>
        <span>No API Key Needed</span>
        <span aria-hidden="true">·</span>
        <span>Local Rule Assessment</span>
      </div>

      {/* Zone 3: Single Primary Action */}
      <div className="flex items-center shrink-0">
        <button
          onClick={onOpenUpload}
          className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-500 active:bg-blue-700 transition-colors whitespace-nowrap shrink-0 cursor-pointer flex items-center gap-1.5"
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Upload Log</span>
        </button>
      </div>
    </header>
  );
};
