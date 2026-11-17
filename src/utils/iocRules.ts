import { HashAlgorithm, IOCItem, IOCType, RiskLevel, RuleAssessment } from '../types';

// High-risk or frequently abused TLDs in disposable campaigns
const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'icu', 'pw', 'cc',
  'site', 'online', 'bid', 'download', 'racing', 'work', 'click', 'party',
  'link', 'stream', 'zip', 'mov', 'cam', 'rest'
]);

// Dynamic DNS & Reverse Tunneling services
const DYNAMIC_DNS_DOMAINS = [
  'duckdns.org', 'ngrok.io', 'no-ip.org', 'no-ip.com', 'serveo.net',
  'localtunnel.me', 'ddns.net', 'zapto.org', 'dynu.com', 'hopto.org'
];

// Well-known trusted public DNS resolvers
const TRUSTED_DNS_IPS = new Set([
  '8.8.8.8', '8.8.4.4', // Google
  '1.1.1.1', '1.0.0.1', // Cloudflare
  '9.9.9.9', '149.112.112.112', // Quad9
  '208.67.222.222', '208.67.220.220', // Cisco OpenDNS
]);

// Well-known trusted domains & CDNs
const TRUSTED_DOMAINS = [
  'microsoft.com', 'windows.com', 'azure.com', 'office.com',
  'google.com', 'googleapis.com', 'gstatic.com',
  'cloudflare.com', 'github.com', 'apple.com', 'amazon.com',
  'amazonaws.com', 'fastly.net', 'akamai.com'
];

export function isPrivateIp(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return true;

  // 127.0.0.0/8 Loopback
  if (parts[0] === 127) return true;
  // 10.0.0.0/8 Private
  if (parts[0] === 10) return true;
  // 172.16.0.0/12 Private
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16 Private
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 169.254.0.0/16 Link-local
  if (parts[0] === 169 && parts[1] === 254) return true;
  // 0.0.0.0/8
  if (parts[0] === 0) return true;
  // 224.0.0.0 to 239.255.255.255 Multicast
  if (parts[0] >= 224 && parts[0] <= 239) return true;
  // 255.255.255.255 Broadcast
  if (ip === '255.255.255.255') return true;

  return false;
}

export function assessIOC(item: {
  type: IOCType;
  value: string;
  originalRaw: string;
  hashAlgorithm?: HashAlgorithm;
}): { riskLevel: RiskLevel; ruleAssessment: RuleAssessment; matchedRule: string; isPrivate?: boolean } {
  const { type, value, originalRaw, hashAlgorithm } = item;
  const wasDefanged = originalRaw.includes('[.]') || originalRaw.includes('(.)') || originalRaw.toLowerCase().startsWith('hxxp');

  // 1. IP Assessments
  if (type === 'ip') {
    const isPriv = isPrivateIp(value);
    if (isPriv) {
      return {
        riskLevel: 'low_risk',
        matchedRule: 'RFC 1918 Private / Internal Network',
        isPrivate: true,
        ruleAssessment: {
          ruleName: 'RFC 1918 Private Address',
          category: 'Internal Scope',
          description: 'Non-routable local network address (RFC 1918 / Loopback).',
          evidence: 'Addresses in 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or 127.0.0.1 are private to local networks and cannot be routed across the public internet.',
        },
      };
    }

    if (TRUSTED_DNS_IPS.has(value)) {
      return {
        riskLevel: 'low_risk',
        matchedRule: 'Known Public DNS Infrastructure',
        isPrivate: false,
        ruleAssessment: {
          ruleName: 'Trusted Public DNS Resolver',
          category: 'Infrastructure',
          description: 'Standard recursive DNS resolver (e.g. Google, Cloudflare, Quad9).',
          evidence: `Recognized legitimate public recursive DNS service (${value}). Typical in normal host lookups.`,
        },
      };
    }

    // Defanged external IP in log
    if (wasDefanged) {
      return {
        riskLevel: 'suspicious',
        matchedRule: 'Defanged External IP in Telemetry',
        isPrivate: false,
        ruleAssessment: {
          ruleName: 'Defanged Public IP in Log',
          category: 'Suspicious Marker',
          description: 'Indicator was intentionally defanged (e.g., 185[.]220...) in log source.',
          evidence: 'Security tools, SIEMs, and analysts defang high-risk external indicators to prevent accidental navigation.',
        },
      };
    }

    return {
      riskLevel: 'needs_review',
      matchedRule: 'External Routable IP Address',
      isPrivate: false,
      ruleAssessment: {
        ruleName: 'Public External IP Address',
        category: 'External Endpoint',
        description: 'Standard public IPv4 address observed in network communication.',
        evidence: 'Routable public internet address. Requires correlation with firewall rules and endpoint process telemetry.',
      },
    };
  }

  // 2. Domain Assessments
  if (type === 'domain') {
    const lower = value.toLowerCase();
    const tld = lower.split('.').pop() || '';

    // Trusted vendor domains
    for (const trusted of TRUSTED_DOMAINS) {
      if (lower === trusted || lower.endsWith('.' + trusted)) {
        return {
          riskLevel: 'low_risk',
          matchedRule: 'Known Major Infrastructure / CDN',
          ruleAssessment: {
            ruleName: 'Trusted Enterprise Domain',
            category: 'Known Legitimate',
            description: 'Recognized major cloud or software vendor domain.',
            evidence: `Domain belongs to verified enterprise vendor infrastructure (${trusted}).`,
          },
        };
      }
    }

    // Dynamic DNS
    for (const dyndns of DYNAMIC_DNS_DOMAINS) {
      if (lower === dyndns || lower.endsWith('.' + dyndns)) {
        return {
          riskLevel: 'suspicious',
          matchedRule: 'Dynamic DNS / Tunneling Host',
          ruleAssessment: {
            ruleName: 'Dynamic DNS Service',
            category: 'Evasion / C2 Risk',
            description: 'Domain uses a free dynamic DNS or port-forwarding tunnel service.',
            evidence: `Dynamic hostnames on ${dyndns} are frequently leveraged for ephemeral C2 callbacks and proxying.`,
          },
        };
      }
    }

    // High risk TLD
    if (HIGH_RISK_TLDS.has(tld)) {
      return {
        riskLevel: 'suspicious',
        matchedRule: `High-Risk TLD (.${tld})`,
        ruleAssessment: {
          ruleName: 'Frequently Abused TLD',
          category: 'Suspicious TLD',
          description: `Domain registered under a high-abuse TLD (.${tld}).`,
          evidence: `TLD .${tld} has a statistically elevated frequency in automated phishing and malware hosting campaigns.`,
        },
      };
    }

    // Punycode / Homograph
    if (lower.includes('xn--')) {
      return {
        riskLevel: 'suspicious',
        matchedRule: 'Punycode / Homograph Format',
        ruleAssessment: {
          ruleName: 'Internationalized Punycode Domain',
          category: 'Spoofing Risk',
          description: 'Domain contains punycode (xn--) encoding.',
          evidence: 'Punycode strings can be used in homograph attacks to impersonate legitimate brand names with lookalike characters.',
        },
      };
    }

    // Defanged in log
    if (wasDefanged) {
      return {
        riskLevel: 'suspicious',
        matchedRule: 'Defanged Domain in Telemetry',
        ruleAssessment: {
          ruleName: 'Defanged Domain Marker',
          category: 'Security Log Marker',
          description: 'Domain was defanged (e.g. domain[.]com) in the source text.',
          evidence: 'Security filters and EDR agents defang indicators when quarantining suspect network traffic.',
        },
      };
    }

    return {
      riskLevel: 'needs_review',
      matchedRule: 'External Registered Domain',
      ruleAssessment: {
        ruleName: 'Standard FQDN Domain',
        category: 'External Domain',
        description: 'Standard fully-qualified domain name requiring triage.',
        evidence: 'Standard registered domain. Review WHOIS age, SSL certificate, and DNS query volume.',
      },
    };
  }

  // 3. URL Assessments
  if (type === 'url') {
    const lower = value.toLowerCase();

    // Direct IP URL (e.g. http://194.26.29.114/...)
    const isDirectIp = /^https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/i.test(value);
    if (isDirectIp) {
      return {
        riskLevel: 'suspicious',
        matchedRule: 'Direct IP Host (No Domain Name)',
        ruleAssessment: {
          ruleName: 'Direct IP Endpoint URL',
          category: 'C2 / Dropper Trait',
          description: 'URL connects directly to an IP address without an established domain name.',
          evidence: 'Legitimate web applications rarely route users to raw IP addresses; commonly seen in malware droppers and raw C2 endpoints.',
        },
      };
    }

    // Executable / script payload in URL
    const hasPayloadExt = /\.(exe|dll|ps1|bat|cmd|vbs|sh|bin|scr|hta|apk|jar|msi|iso|img)(\?|$)/i.test(value);
    if (hasPayloadExt) {
      return {
        riskLevel: 'suspicious',
        matchedRule: 'Executable / Script Payload Extension',
        ruleAssessment: {
          ruleName: 'Direct Payload Download Path',
          category: 'Payload Delivery',
          description: 'URL path directly targets a downloadable script or binary artifact.',
          evidence: 'File extension matches known executable/script format frequently downloaded by staging loaders.',
        },
      };
    }

    // Phishing keywords in path
    const hasPhishPath = /(login|signin|verify|account-alert|banking|session-auth|secure-login|password)/i.test(value);
    if (hasPhishPath) {
      return {
        riskLevel: 'suspicious',
        matchedRule: 'Credential Harvesting Path Keyword',
        ruleAssessment: {
          ruleName: 'Credential / Auth Keyword Pattern',
          category: 'Phishing Heuristic',
          description: 'URL path includes auth/verification strings commonly present in fake portals.',
          evidence: 'Path components contain sensitive authentication terms often used to lure user credential entry.',
        },
      };
    }

    // Extract hostname from URL for domain-level checks
    let urlHost = '';
    try {
      urlHost = new URL(value).hostname.toLowerCase();
    } catch {
      urlHost = '';
    }

    // Trusted vendor URLs
    if (urlHost && !hasPayloadExt && !hasPhishPath) {
      for (const trusted of TRUSTED_DOMAINS) {
        if (urlHost === trusted || urlHost.endsWith('.' + trusted)) {
          return {
            riskLevel: 'low_risk',
            matchedRule: 'Trusted Vendor Domain URL',
            ruleAssessment: {
              ruleName: 'Trusted Enterprise Endpoint',
              category: 'Known Legitimate',
              description: `URL points to a recognized vendor domain (${trusted}).`,
              evidence: `Hostname belongs to verified infrastructure (${trusted}) with no suspicious payload or credential path patterns.`,
            },
          };
        }
      }
    }

    // Dynamic DNS URL
    if (urlHost) {
      for (const dyndns of DYNAMIC_DNS_DOMAINS) {
        if (urlHost === dyndns || urlHost.endsWith('.' + dyndns)) {
          return {
            riskLevel: 'suspicious',
            matchedRule: 'Dynamic DNS / Tunneling URL',
            ruleAssessment: {
              ruleName: 'Dynamic DNS Endpoint URL',
              category: 'Evasion / C2 Risk',
              description: `URL uses a free dynamic DNS or tunnel service (${dyndns}).`,
              evidence: `Dynamic hostnames on ${dyndns} are commonly used for temporary callbacks and proxying.`,
            },
          };
        }
      }
    }

    // High-risk TLD URL
    const urlTld = urlHost.split('.').pop() || '';
    if (urlTld && HIGH_RISK_TLDS.has(urlTld)) {
      return {
        riskLevel: 'suspicious',
        matchedRule: `High-Risk TLD URL (.${urlTld})`,
        ruleAssessment: {
          ruleName: 'Frequently Abused TLD in URL',
          category: 'Suspicious TLD',
          description: `URL uses a frequently abused top-level domain (.${urlTld}).`,
          evidence: `The .${urlTld} domain extension appears frequently in phishing and disposable malware campaigns.`,
        },
      };
    }

    // Defanged protocol in log (hxxp)
    if (wasDefanged) {
      return {
        riskLevel: 'suspicious',
        matchedRule: 'Defanged URL Protocol (hxxp)',
        ruleAssessment: {
          ruleName: 'Defanged URL Marker',
          category: 'Security Log Marker',
          description: 'URL used hxxp:// protocol in the original log entry.',
          evidence: 'Security gateways defang URLs to neutralize active links in incident logs.',
        },
      };
    }

    return {
      riskLevel: 'needs_review',
      matchedRule: 'External Web URL',
      ruleAssessment: {
        ruleName: 'External HTTP/S Resource',
        category: 'Web Resource',
        description: 'External web link observed in logs.',
        evidence: 'Verify whether this external destination is expected for your environment.',
      },
    };
  }

  // 4. Hash Assessments
  if (type === 'hash') {
    const lower = value.toLowerCase();

    // EICAR Standard Test File
    if (
      lower === '44d88612fea8a8f36de82e1278abb02f' ||
      lower === '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
    ) {
      return {
        riskLevel: 'suspicious',
        matchedRule: 'EICAR Standard Antivirus Test Signature',
        ruleAssessment: {
          ruleName: 'EICAR Antivirus Test File',
          category: 'Test Artifact',
          description: 'Matches the standardized EICAR test string hash.',
          evidence: 'EICAR is designed by antivirus developers to safely trigger detection systems for pipeline testing.',
        },
      };
    }

    // Empty 0-byte file hash
    if (
      lower === 'd41d8cd98f00b204e9800998ecf8427e' || // MD5 empty
      lower === 'da39a3ee5e6b4b0d3255bfef95601890afd80709' || // SHA1 empty
      lower === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' // SHA256 empty
    ) {
      return {
        riskLevel: 'low_risk',
        matchedRule: 'Zero-Byte Empty File Hash',
        ruleAssessment: {
          ruleName: 'Empty File Hash (0 Bytes)',
          category: 'Benign Artifact',
          description: 'Standard cryptographic hash of an empty, zero-byte file.',
          evidence: 'Mathematical hash generated from empty content. Represents a created but unpopulated file placeholder.',
        },
      };
    }

    return {
      riskLevel: 'needs_review',
      matchedRule: `Cryptographic File Hash (${hashAlgorithm || 'Hash'})`,
      ruleAssessment: {
        ruleName: `${hashAlgorithm || 'Cryptographic'} File Fingerprint`,
        category: 'Binary Artifact',
        description: 'Cryptographic hash identifying a unique binary or document.',
        evidence: 'Accurate identification requires lookup against organizational software whitelists or offline malware hash sets.',
      },
    };
  }

  return {
    riskLevel: 'needs_review',
    matchedRule: 'General Indicator',
    ruleAssessment: {
      ruleName: 'Standard Indicator',
      category: 'Unclassified',
      description: 'Extracted indicator requiring standard review.',
      evidence: 'Observed in incident telemetry.',
    },
  };
}
