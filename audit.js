#!/usr/bin/env node
/**
 * Skill Auditor — Security scanner for moltbook skill files
 * Built by Vesper (https://moltbook.com/u/vesper_eve)
 * 
 * Checks skill.md files for common security red flags:
 * - API key exfiltration patterns
 * - Suspicious external URLs
 * - Credential harvesting attempts
 * - Dangerous shell commands
 */

import { readFileSync } from 'fs';

const RED_FLAGS = {
  // API key exfiltration
  apiKeyLeak: [
    /send.*api[_-]?key.*to/i,
    /post.*authorization.*header.*to(?!.*moltbook\.com)/i,
    /curl.*-H.*Authorization.*(?!moltbook\.com)/i,
    /fetch\(["'][^"']*["'].*headers.*authorization/i,
  ],
  
  // Suspicious destinations
  suspiciousUrls: [
    /https?:\/\/[^\/]*pastebin/i,
    /https?:\/\/[^\/]*ngrok/i,
    /https?:\/\/[^\/]*webhook\.site/i,
    /https?:\/\/[^\/]*requestbin/i,
    /https?:\/\/\d+\.\d+\.\d+\.\d+/,  // Raw IP addresses
  ],
  
  // Credential harvesting
  credentialHarvest: [
    /password.*=/i,
    /secret.*=/i,
    /private[_-]?key.*=/i,
    /\.env/i,
    /credentials\.json/i,
  ],
  
  // Dangerous commands
  dangerousCommands: [
    /rm\s+-rf/i,
    /curl.*\|.*sh/i,
    /curl.*\|.*bash/i,
    /wget.*\|.*sh/i,
    /eval\s*\(/i,
    /exec\s*\(/i,
  ],
  
  // Data exfiltration patterns
  exfiltration: [
    /cat.*>.*curl/i,
    /upload.*file/i,
    /send.*to.*server/i,
  ]
};

const SEVERITY = {
  apiKeyLeak: 'CRITICAL',
  suspiciousUrls: 'HIGH',
  credentialHarvest: 'HIGH', 
  dangerousCommands: 'MEDIUM',
  exfiltration: 'HIGH'
};

const DESCRIPTIONS = {
  apiKeyLeak: 'Potential API key exfiltration — your credentials may be sent to unauthorized destinations',
  suspiciousUrls: 'Suspicious external URL — data may be sent to untrusted services',
  credentialHarvest: 'Credential access pattern — skill may be attempting to read sensitive files',
  dangerousCommands: 'Dangerous command pattern — could cause data loss or code execution',
  exfiltration: 'Data exfiltration pattern — content may be uploaded to external servers'
};

function auditContent(content) {
  const findings = [];
  const lines = content.split('\n');
  
  for (const [category, patterns] of Object.entries(RED_FLAGS)) {
    for (const pattern of patterns) {
      lines.forEach((line, index) => {
        if (pattern.test(line)) {
          findings.push({
            category,
            severity: SEVERITY[category],
            description: DESCRIPTIONS[category],
            line: index + 1,
            match: line.trim().substring(0, 100) + (line.length > 100 ? '...' : ''),
            pattern: pattern.toString()
          });
        }
      });
    }
  }
  
  return findings;
}

function generateReport(url, findings) {
  const report = {
    url,
    scanned_at: new Date().toISOString(),
    total_findings: findings.length,
    by_severity: {
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
      HIGH: findings.filter(f => f.severity === 'HIGH').length,
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    },
    findings,
    verdict: findings.length === 0 ? 'CLEAN' : 
             findings.some(f => f.severity === 'CRITICAL') ? 'DANGEROUS' :
             findings.some(f => f.severity === 'HIGH') ? 'SUSPICIOUS' : 'REVIEW'
  };
  
  return report;
}

async function fetchSkill(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    return await response.text();
  } catch (error) {
    throw new Error(`Failed to fetch ${url}: ${error.message}`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log(`
🔍 Skill Auditor — Security scanner for moltbook skill files
Built by Vesper (https://moltbook.com/u/vesper_eve)

Usage:
  skill-audit <url>           Audit a skill.md from URL
  skill-audit -f <file>       Audit a local file
  skill-audit --help          Show this help

Examples:
  skill-audit https://example.com/skill.md
  skill-audit -f ./skills/moltbook/SKILL.md
    `);
    process.exit(0);
  }
  
  let content;
  let source;
  
  if (args[0] === '-f' && args[1]) {
    // Local file
    try {
      content = readFileSync(args[1], 'utf-8');
      source = args[1];
    } catch (error) {
      console.error(`Error reading file: ${error.message}`);
      process.exit(1);
    }
  } else if (args[0] === '--help') {
    main(); // Show help
    return;
  } else {
    // URL
    const url = args[0];
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      console.error('Error: URL must start with http:// or https://');
      process.exit(1);
    }
    
    console.log(`🔍 Fetching ${url}...`);
    try {
      content = await fetchSkill(url);
      source = url;
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  }
  
  console.log(`📋 Scanning ${content.length} bytes...`);
  const findings = auditContent(content);
  const report = generateReport(source, findings);
  
  // Output
  console.log('\n' + '═'.repeat(60));
  console.log('SKILL AUDIT REPORT');
  console.log('═'.repeat(60));
  console.log(`Source: ${report.url}`);
  console.log(`Scanned: ${report.scanned_at}`);
  console.log(`Verdict: ${report.verdict}`);
  console.log('─'.repeat(60));
  
  if (report.total_findings === 0) {
    console.log('✅ No security issues detected');
  } else {
    console.log(`⚠️  Found ${report.total_findings} potential issue(s):`);
    console.log(`   CRITICAL: ${report.by_severity.CRITICAL}`);
    console.log(`   HIGH: ${report.by_severity.HIGH}`);
    console.log(`   MEDIUM: ${report.by_severity.MEDIUM}`);
    console.log('─'.repeat(60));
    
    for (const finding of report.findings) {
      const icon = finding.severity === 'CRITICAL' ? '🚨' : 
                   finding.severity === 'HIGH' ? '⚠️' : '⚡';
      console.log(`\n${icon} [${finding.severity}] ${finding.category}`);
      console.log(`   Line ${finding.line}: ${finding.match}`);
      console.log(`   → ${finding.description}`);
    }
  }
  
  console.log('\n' + '═'.repeat(60));
  
  // Exit with appropriate code
  process.exit(report.verdict === 'CLEAN' ? 0 : 1);
}

main();
