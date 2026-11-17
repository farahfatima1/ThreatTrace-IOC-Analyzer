import { ExtractionOptions, HashAlgorithm, IOCItem } from '../types';
import { assessIOC } from './iocRules';

// Common non-domain file extensions to exclude from domain extractor
const FILE_EXTENSIONS = new Set([
  'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'vbs', 'sh', 'py', 'pyc',
  'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'rtf', 'txt', 'log',
  'zip', 'rar', '7z', 'tar', 'gz', 'iso', 'img', 'bin',
  'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'ico',
  'mp3', 'mp4', 'wav', 'avi', 'mov', 'mkv',
  'json', 'xml', 'yaml', 'yml', 'html', 'htm', 'css', 'js', 'ts', 'tsx', 'jsx', 'sql', 'config', 'ini'
]);

export function refangString(str: string): string {
  if (!str) return '';
  return str
    .replace(/\b(?:hxxps?|h\*\*ps?|h\[xx\]ps?):\/\//gi, (m) => m.toLowerCase().startsWith('hxxps') ? 'https://' : 'http://')
    .replace(/\b(?:fxp):\/\//gi, 'ftp://')
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\{\.\}/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[@\]/g, '@')
    .replace(/\[slash\]/gi, '/')
    .replace(/\\\./g, '.');
}

export function defangString(str: string): string {
  if (!str) return '';
  let result = str.replace(/https:\/\//gi, 'hxxps://').replace(/http:\/\//gi, 'hxxp://');
  result = result.replace(/\./g, '[.]');
  return result;
}

export function extractIOCs(rawText: string, options: ExtractionOptions = { extractIps: true, extractDomains: true, extractUrls: true, extractHashes: true }): IOCItem[] {
  if (!rawText || !rawText.trim()) return [];

  const refanged = refangString(rawText);
  const seen = new Set<string>();
  const iocs: IOCItem[] = [];

  // 1. URLs
  if (options.extractUrls) {
    const urlRegex = /(?:https?|ftp):\/\/[^\s"'<>\`\(\)\[\]\{\}]+[^\s"'<>\`\(\)\[\]\{\}\.,:;?!]/gi;
    let match: RegExpExecArray | null;
    while ((match = urlRegex.exec(refanged)) !== null) {
      let url = match[0].trim().replace(/[.,;?!)]+$/, '');
      if (url.length > 8 && !seen.has(`url:${url.toLowerCase()}`)) {
        seen.add(`url:${url.toLowerCase()}`);
        const assessment = assessIOC({
          type: 'url',
          value: url,
          originalRaw: match[0],
        });
        iocs.push({
          id: `ioc-url-${iocs.length + 1}`,
          type: 'url',
          value: url,
          originalRaw: match[0],
          defanged: defangString(url),
          riskLevel: assessment.riskLevel,
          ruleAssessment: assessment.ruleAssessment,
          matchedRule: assessment.matchedRule,
        });
      }
    }
  }

  // 2. Hashes (check SHA-256 (64), then SHA-1 (40), then MD5 (32))
  if (options.extractHashes) {
    // SHA-256 (64 hex)
    const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
    let match: RegExpExecArray | null;
    const sha256Matches = new Set<string>();

    while ((match = sha256Regex.exec(refanged)) !== null) {
      const hash = match[0].toLowerCase();
      if (!seen.has(`hash:${hash}`)) {
        seen.add(`hash:${hash}`);
        sha256Matches.add(hash);
        const assessment = assessIOC({
          type: 'hash',
          value: hash,
          originalRaw: match[0],
          hashAlgorithm: 'SHA-256',
        });
        iocs.push({
          id: `ioc-hash-${iocs.length + 1}`,
          type: 'hash',
          value: hash,
          originalRaw: match[0],
          defanged: hash,
          hashAlgorithm: 'SHA-256',
          riskLevel: assessment.riskLevel,
          ruleAssessment: assessment.ruleAssessment,
          matchedRule: assessment.matchedRule,
        });
      }
    }

    // SHA-1 (40 hex)
    const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
    while ((match = sha1Regex.exec(refanged)) !== null) {
      const hash = match[0].toLowerCase();
      let isSub = false;
      for (const h of sha256Matches) {
        if (h.includes(hash)) {
          isSub = true;
          break;
        }
      }
      if (!isSub && !seen.has(`hash:${hash}`)) {
        seen.add(`hash:${hash}`);
        const assessment = assessIOC({
          type: 'hash',
          value: hash,
          originalRaw: match[0],
          hashAlgorithm: 'SHA-1',
        });
        iocs.push({
          id: `ioc-hash-${iocs.length + 1}`,
          type: 'hash',
          value: hash,
          originalRaw: match[0],
          defanged: hash,
          hashAlgorithm: 'SHA-1',
          riskLevel: assessment.riskLevel,
          ruleAssessment: assessment.ruleAssessment,
          matchedRule: assessment.matchedRule,
        });
      }
    }

    // MD5 (32 hex)
    const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
    while ((match = md5Regex.exec(refanged)) !== null) {
      const hash = match[0].toLowerCase();
      let isSub = false;
      for (const h of sha256Matches) {
        if (h.includes(hash)) {
          isSub = true;
          break;
        }
      }
      if (!isSub && !seen.has(`hash:${hash}`)) {
        seen.add(`hash:${hash}`);
        const assessment = assessIOC({
          type: 'hash',
          value: hash,
          originalRaw: match[0],
          hashAlgorithm: 'MD5',
        });
        iocs.push({
          id: `ioc-hash-${iocs.length + 1}`,
          type: 'hash',
          value: hash,
          originalRaw: match[0],
          defanged: hash,
          hashAlgorithm: 'MD5',
          riskLevel: assessment.riskLevel,
          ruleAssessment: assessment.ruleAssessment,
          matchedRule: assessment.matchedRule,
        });
      }
    }
  }

  // 3. IPv4 Addresses
  if (options.extractIps) {
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    let match: RegExpExecArray | null;
    while ((match = ipRegex.exec(refanged)) !== null) {
      const ip = match[0].trim();
      if (!seen.has(`ip:${ip}`)) {
        seen.add(`ip:${ip}`);
        const assessment = assessIOC({
          type: 'ip',
          value: ip,
          originalRaw: match[0],
        });
        iocs.push({
          id: `ioc-ip-${iocs.length + 1}`,
          type: 'ip',
          value: ip,
          originalRaw: match[0],
          defanged: defangString(ip),
          riskLevel: assessment.riskLevel,
          ruleAssessment: assessment.ruleAssessment,
          matchedRule: assessment.matchedRule,
          isPrivate: assessment.isPrivate,
        });
      }
    }
  }

  // 4. Domains
  if (options.extractDomains) {
    const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/g;
    let match: RegExpExecArray | null;
    while ((match = domainRegex.exec(refanged)) !== null) {
      let domain = match[0].toLowerCase().trim().replace(/[.,;?!]+$/, '');
      const tld = domain.split('.').pop() || '';

      if (FILE_EXTENSIONS.has(tld)) continue;
      if (domain === 'localhost' || domain.endsWith('.local') || domain.endsWith('.internal') || domain.endsWith('.arpa')) continue;
      if (tld.length < 2 || /^\d+$/.test(tld)) continue;

      if (!seen.has(`domain:${domain}`)) {
        seen.add(`domain:${domain}`);
        const assessment = assessIOC({
          type: 'domain',
          value: domain,
          originalRaw: match[0],
        });
        iocs.push({
          id: `ioc-domain-${iocs.length + 1}`,
          type: 'domain',
          value: domain,
          originalRaw: match[0],
          defanged: defangString(domain),
          riskLevel: assessment.riskLevel,
          ruleAssessment: assessment.ruleAssessment,
          matchedRule: assessment.matchedRule,
        });
      }
    }
  }

  return iocs;
}
