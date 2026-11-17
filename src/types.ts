export type IOCType = 'ip' | 'domain' | 'url' | 'hash';

export type HashAlgorithm = 'MD5' | 'SHA-1' | 'SHA-256';

export type RiskLevel = 'suspicious' | 'needs_review' | 'low_risk';

export interface RuleAssessment {
  ruleName: string;
  category: string;
  description: string;
  evidence: string;
}

export interface IOCItem {
  id: string;
  type: IOCType;
  value: string;
  originalRaw: string;
  defanged: string;
  hashAlgorithm?: HashAlgorithm;
  riskLevel: RiskLevel;
  ruleAssessment: RuleAssessment;
  matchedRule: string;
  isPrivate?: boolean;
}

export interface SummaryStats {
  total: number;
  suspicious: number;
  needsReview: number;
  lowRisk: number;
  byType: {
    ip: number;
    domain: number;
    url: number;
    hash: number;
  };
}

export interface ExtractionOptions {
  extractIps: boolean;
  extractDomains: boolean;
  extractUrls: boolean;
  extractHashes: boolean;
}
