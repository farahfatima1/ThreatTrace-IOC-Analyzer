import { IOCItem } from '../types';

export function exportToCSV(items: IOCItem[], filenamePrefix = 'threattrace_ioc_report'): void {
  if (!items.length) return;

  const headers = [
    'Indicator',
    'Defanged',
    'Type',
    'Hash_Algorithm',
    'Risk_Label',
    'Assessment_Rule',
    'Rule_Category',
    'Rule_Evidence',
    'Network_Scope',
    'Assessment_Type'
  ];

  const escapeCSV = (field: any) => {
    if (field === null || field === undefined) return '""';
    const str = String(field).replace(/"/g, '""');
    return `"${str}"`;
  };

  const rows = items.map((item) => {
    let riskText = 'Needs Review';
    if (item.riskLevel === 'suspicious') riskText = 'Potentially Suspicious';
    else if (item.riskLevel === 'low_risk') riskText = 'Low Risk / Informational';

    return [
      escapeCSV(item.value),
      escapeCSV(item.defanged),
      escapeCSV(item.type.toUpperCase()),
      escapeCSV(item.hashAlgorithm || ''),
      escapeCSV(riskText),
      escapeCSV(item.matchedRule),
      escapeCSV(item.ruleAssessment.category),
      escapeCSV(item.ruleAssessment.evidence),
      escapeCSV(item.isPrivate ? 'Internal (RFC 1918)' : 'External / Public'),
      escapeCSV('Local Rule-Based Assessment (No API Key)')
    ].join(',');
  });

  const csvContent = [headers.join(','), ...rows].join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  link.setAttribute('href', url);
  link.setAttribute('download', `${filenamePrefix}_${timestamp}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
