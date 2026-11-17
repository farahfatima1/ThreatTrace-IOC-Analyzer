import React, { useState, useEffect, useRef, useMemo } from 'react';
import { Header } from './components/Header';
import { MetricsOverview } from './components/MetricsOverview';
import { IOCTable } from './components/IOCTable';
import { extractIOCs } from './utils/iocExtractor';
import { exportToCSV } from './utils/exportUtils';
import { IOCItem, SummaryStats } from './types';
import { Upload, CheckCircle2, X, Info, ChevronDown, ChevronUp, Trash2 } from 'lucide-react';

export default function App() {
  const [fileName, setFileName] = useState<string>('');
  const [rawText, setRawText] = useState<string>('');
  const [isPasteOpen, setIsPasteOpen] = useState(false);
  const [showRulesGuide, setShowRulesGuide] = useState(false);
  const [items, setItems] = useState<IOCItem[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Extract unique IOCs and apply local rule assessments whenever input text changes
  useEffect(() => {
    if (!rawText.trim()) {
      setItems([]);
      return;
    }
    setItems(extractIOCs(rawText));
  }, [rawText]);

  // Compute summary counts
  const summaryStats: SummaryStats = useMemo(() => {
    const byType = { ip: 0, domain: 0, url: 0, hash: 0 };
    let suspicious = 0;
    let needsReview = 0;
    let lowRisk = 0;

    for (const item of items) {
      byType[item.type] += 1;
      if (item.riskLevel === 'suspicious') suspicious++;
      else if (item.riskLevel === 'needs_review') needsReview++;
      else lowRisk++;
    }

    return {
      total: items.length,
      suspicious,
      needsReview,
      lowRisk,
      byType,
    };
  }, [items]);

  // Handle file upload (.log or .txt)
  const handleFile = (file: File) => {
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = (e.target?.result as string) || '';
      setRawText(content);
      const count = extractIOCs(content).length;
      setNotice(`Loaded "${file.name}" — extracted ${count} unique indicators.`);
    };
    reader.readAsText(file);
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleClear = () => {
    setFileName('');
    setRawText('');
    setNotice(null);
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100 font-sans selection:bg-blue-600/30 selection:text-white flex flex-col">
      <Header onOpenUpload={() => fileInputRef.current?.click()} />

      <main className="flex-1 w-full max-w-6xl mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Status Banner */}
        {notice && (
          <div className="px-4 py-3 rounded-xl text-xs flex items-center justify-between gap-3 border bg-emerald-950/30 border-emerald-800/50 text-emerald-300">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span className="font-medium">{notice}</span>
            </div>
            <button
              onClick={() => setNotice(null)}
              className="p-1 rounded hover:bg-white/10 text-neutral-400 hover:text-white cursor-pointer"
              aria-label="Dismiss notice"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Step 1: Upload Log File or Paste Text */}
        <section className="p-5 bg-neutral-900 border border-neutral-800 rounded-xl space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="text-base font-bold text-white">1. Load a Log or Text File</h1>
              <p className="text-xs text-neutral-400 mt-0.5">
                Upload a <code className="text-blue-400 font-mono">.log</code> or{' '}
                <code className="text-blue-400 font-mono">.txt</code> file to automatically extract unique IPs, domains, URLs, and file hashes.
              </p>
            </div>

            {rawText && (
              <button
                onClick={handleClear}
                className="px-2.5 py-1.5 rounded-lg bg-neutral-950 hover:bg-neutral-800 border border-neutral-800 text-xs text-neutral-400 hover:text-red-300 transition-colors cursor-pointer flex items-center gap-1"
                title="Clear current log"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            )}
          </div>

          <input
            ref={fileInputRef}
            type="file"
            accept=".log,.txt,.csv"
            className="hidden"
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                handleFile(e.target.files[0]);
              }
            }}
          />

          <div
            onDragEnter={handleDrag}
            onDragOver={handleDrag}
            onDragLeave={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors ${
              dragActive
                ? 'border-blue-500 bg-blue-950/20'
                : 'border-neutral-700 bg-neutral-950 hover:border-neutral-600'
            }`}
          >
            <div className="flex flex-col items-center justify-center space-y-2">
              <div className="w-9 h-9 rounded-lg bg-neutral-800 flex items-center justify-center text-blue-400">
                <Upload className="w-4 h-4" />
              </div>
              <p className="text-xs font-semibold text-neutral-200">
                Drop your <code className="text-blue-400 font-mono">.log</code> or{' '}
                <code className="text-blue-400 font-mono">.txt</code> file here, or click to browse
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-neutral-400">
            <span>
              Active source:{' '}
              <strong className="text-neutral-200 font-mono">
                {fileName || 'No file loaded'}
              </strong>
            </span>
            <button
              onClick={() => setIsPasteOpen(!isPasteOpen)}
              className="text-blue-400 hover:text-blue-300 font-medium cursor-pointer"
            >
              {isPasteOpen ? 'Hide Paste Box' : 'Paste Raw Log Text'}
            </button>
          </div>

          {isPasteOpen && (
            <textarea
              value={rawText}
              onChange={(e) => {
                setRawText(e.target.value);
                setFileName(e.target.value.trim() ? 'Pasted Log Text' : '');
              }}
              placeholder="Paste log lines or security telemetry here..."
              rows={5}
              className="w-full bg-neutral-950 border border-neutral-800 rounded-lg p-3 text-xs text-neutral-200 font-mono focus:outline-none focus:border-blue-500 leading-relaxed placeholder-neutral-600"
            />
          )}
        </section>

        {/* Step 2: Summary Overview */}
        <section className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-bold text-white">2. Summary Overview</h2>
            <span className="text-xs text-neutral-400 flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-blue-400 shrink-0" />
              <span>Rule-based local checks (no API key or external lookup)</span>
            </span>
          </div>
          <MetricsOverview stats={summaryStats} />
        </section>

        {/* Step 3: Results Table */}
        <section className="space-y-3">
          <h2 className="text-sm font-bold text-white">3. Extracted Indicators</h2>
          <IOCTable
            items={items}
            onExportCSV={() => exportToCSV(items, (fileName || 'ioc_report').replace(/\.[^/.]+$/, ''))}
            onOpenUpload={() => fileInputRef.current?.click()}
          />
        </section>

        {/* Simple Collapsible Rules Reference */}
        <section className="border border-neutral-800 rounded-xl bg-neutral-900 overflow-hidden">
          <button
            onClick={() => setShowRulesGuide(!showRulesGuide)}
            className="w-full px-5 py-3.5 flex items-center justify-between text-xs font-semibold text-neutral-200 hover:bg-neutral-800/40 transition-colors cursor-pointer"
          >
            <span>How Local Assessment Rules Work</span>
            {showRulesGuide ? (
              <ChevronUp className="w-4 h-4 text-neutral-400" />
            ) : (
              <ChevronDown className="w-4 h-4 text-neutral-400" />
            )}
          </button>

          {showRulesGuide && (
            <div className="px-5 pb-4 pt-1 border-t border-neutral-800 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-neutral-400">
              <div>
                <h3 className="font-semibold text-red-400 mb-1">Suspicious (Red)</h3>
                <p className="leading-relaxed">
                  Flagged for structural warning signs such as direct IP URLs, executable download paths, credential keywords in URLs, dynamic DNS, high-abuse TLDs, or defanged log markers.
                </p>
              </div>
              <div>
                <h3 className="font-semibold text-amber-400 mb-1">Needs Review (Yellow)</h3>
                <p className="leading-relaxed">
                  Public IPs, standard external domains, web links, and unknown file hashes. These are not confirmed threats—review them against your internal firewall logs or asset inventory.
                </p>
              </div>
              <div>
                <h3 className="font-semibold text-emerald-400 mb-1">Low Risk (Green)</h3>
                <p className="leading-relaxed">
                  Internal private networks (RFC 1918), trusted public DNS resolvers, recognized vendor domains, and zero-byte empty file hashes.
                </p>
              </div>
            </div>
          )}
        </section>
      </main>

      <footer className="mt-auto border-t border-neutral-900 bg-neutral-950 py-4 px-6 text-xs text-neutral-400">
        <div className="max-w-6xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <span>ThreatTrace — IOC Analyzer</span>
          <span>100% Local Processing · No API Key Required</span>
        </div>
      </footer>
    </div>
  );
}
