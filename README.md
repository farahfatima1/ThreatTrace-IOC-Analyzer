# ThreatTrace – IOC Analyzer

A rule-based cybersecurity tool that extracts and analyzes Indicators of Compromise (IOCs) from log and text files.

## Features
- Extract IP addresses, domains, and URLs.
- Detect MD5 and SHA-256 hashes.
- Classify indicators as Suspicious, Needs Review, or Low Risk.
- Export results to CSV.
- Local processing without an API key.

## Technologies
- React
- TypeScript
- Node.js
- Express
- Vite

## Installation

```bash
git clone https://github.com/farahfatima1/ThreatTrace-IOC-Analyzer.git
cd ThreatTrace-IOC-Analyzer
npm install
npm run dev
```

Open `http://localhost:3000` in your browser.

## Note
ThreatTrace uses local detection rules. It does not currently perform live VirusTotal lookups or confirm malicious activity.

## Author
**Farah Fatima**

GitHub: [farahfatima1](https://github.com/farahfatima1)
