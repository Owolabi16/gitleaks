#!/usr/bin/env python3
"""
Gitleaks Context Parser
Extracts context around detected secrets and generates GitHub Actions summary
"""

import json
import subprocess
import sys
import os
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import re

class GitLeaksContextParser:
    def __init__(self, report_path: str, mode: str = 'full'):
        self.report_path = report_path
        self.mode = mode
        self.summary_path = os.environ.get('GITHUB_STEP_SUMMARY', 'gitleaks-summary.md')
        self.findings = []
        self.context_lines = 3  # Lines before and after
        
    def parse_report(self) -> List[Dict]:
        """Parse the Gitleaks JSON report"""
        try:
            with open(self.report_path, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and 'results' in data:
                    return data['results']
                else:
                    return []
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error reading report: {e}")
            return []
    
    def get_file_context(self, commit: str, file_path: str, line_number: int) -> Tuple[List[str], int]:
        """Extract context lines around the secret"""
        try:
            # Try to get the file content at the specific commit
            cmd = ['git', 'show', f'{commit}:{file_path}']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()
            
            # Calculate context boundaries
            start = max(0, line_number - self.context_lines - 1)
            end = min(len(lines), line_number + self.context_lines)
            
            context_lines = []
            for i in range(start, end):
                context_lines.append({
                    'number': i + 1,
                    'content': lines[i] if i < len(lines) else '',
                    'is_match': i == line_number - 1
                })
            
            return context_lines, line_number
            
        except subprocess.CalledProcessError:
            # File might be deleted or commit might be unreachable
            return [], 0
    
    def get_commit_info(self, commit: str) -> Dict[str, str]:
        """Get commit metadata"""
        try:
            cmd = ['git', 'show', '--no-patch', '--format=%an|%ae|%ad|%s', commit]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            parts = result.stdout.strip().split('|')
            
            return {
                'author': parts[0] if len(parts) > 0 else 'Unknown',
                'email': parts[1] if len(parts) > 1 else '',
                'date': parts[2] if len(parts) > 2 else '',
                'message': parts[3] if len(parts) > 3 else ''
            }
        except subprocess.CalledProcessError:
            return {
                'author': 'Unknown',
                'email': '',
                'date': '',
                'message': ''
            }
    
    def format_severity_emoji(self, rule_id: str) -> str:
        """Get emoji based on rule severity"""
        critical_patterns = ['private[_-]key', 'aws[_-]access', 'github[_-]pat', 'api[_-]key']
        high_patterns = ['password', 'token', 'secret', 'credential']
        
        rule_lower = rule_id.lower()
        
        if any(pattern in rule_lower for pattern in critical_patterns):
            return '🔴'
        elif any(pattern in rule_lower for pattern in high_patterns):
            return '🟠'
        else:
            return '🟡'
    
    def format_finding(self, finding: Dict) -> str:
        """Format a single finding with context"""
        commit = finding.get('Commit', '')
        file_path = finding.get('File', '')
        line_number = finding.get('StartLine', 0)
        rule_id = finding.get('RuleID', 'unknown')
        description = finding.get('Description', '')
        
        # Get context
        context_lines, actual_line = self.get_file_context(commit, file_path, line_number)
        commit_info = self.get_commit_info(commit)
        
        # Format the finding
        severity = self.format_severity_emoji(rule_id)
        
        output = f"\n### {severity} Secret Detected: {rule_id}\n\n"
        output += f"**File:** `{file_path}`  \n"
        output += f"**Line:** {line_number}  \n"
        output += f"**Commit:** [{commit[:7]}](../../commit/{commit})  \n"
        output += f"**Author:** {commit_info['author']}  \n"
        output += f"**Date:** {commit_info['date']}  \n"
        
        if description:
            output += f"**Description:** {description}  \n"
        
        output += "\n<details>\n<summary>📋 View Context</summary>\n\n"
        
        if context_lines:
            # Determine file extension for syntax highlighting
            ext = Path(file_path).suffix.lstrip('.')
            lang_map = {
                'py': 'python', 'js': 'javascript', 'ts': 'typescript',
                'go': 'go', 'java': 'java', 'rb': 'ruby', 'php': 'php',
                'yml': 'yaml', 'yaml': 'yaml', 'json': 'json', 'xml': 'xml',
                'sh': 'bash', 'bash': 'bash', 'env': 'bash'
            }
            lang = lang_map.get(ext, ext or 'text')
            
            output += f"```{lang}\n"
            for line in context_lines:
                marker = '>>> ' if line['is_match'] else '    '
                output += f"{line['number']:4d} | {marker}{line['content']}\n"
            output += "```\n"
        else:
            output += "*Context unavailable (file may be deleted)*\n"
        
        output += "\n</details>\n"
        
        # Add remediation hint
        output += "\n**🔧 Remediation:**\n"
        if 'aws' in rule_id.lower():
            output += "- Rotate the AWS credentials immediately\n"
            output += "- Use AWS IAM roles or environment variables instead\n"
        elif 'github' in rule_id.lower():
            output += "- Revoke the token in GitHub Settings > Developer settings\n"
            output += "- Use GitHub Actions secrets for CI/CD\n"
        elif 'private' in rule_id.lower() and 'key' in rule_id.lower():
            output += "- Generate new key pair immediately\n"
            output += "- Never commit private keys to version control\n"
        else:
            output += "- Rotate/revoke this secret immediately\n"
            output += "- Use environment variables or secret management tools\n"
        
        return output
    
    def generate_summary(self):
        """Generate the GitHub Actions summary"""
        findings = self.parse_report()
        
        if not findings:
            summary = "## ✅ No Secrets Detected\n\n"
            summary += f"**Scan Mode:** {self.mode}\n"
            summary += f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        else:
            summary = f"## 🚨 Gitleaks Security Report\n\n"
            summary += f"**Total Findings:** {len(findings)}  \n"
            summary += f"**Scan Mode:** {self.mode}  \n"
            summary += f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            
            # Group by severity
            critical = []
            high = []
            medium = []
            
            for finding in findings:
                rule_id = finding.get('RuleID', '').lower()
                if any(term in rule_id for term in ['private_key', 'aws_access', 'github_pat']):
                    critical.append(finding)
                elif any(term in rule_id for term in ['password', 'token', 'secret']):
                    high.append(finding)
                else:
                    medium.append(finding)
            
            # Summary stats
            if critical:
                summary += f"- 🔴 **Critical:** {len(critical)}\n"
            if high:
                summary += f"- 🟠 **High:** {len(high)}\n"
            if medium:
                summary += f"- 🟡 **Medium:** {len(medium)}\n"
            
            summary += "\n---\n"
            
            # Add findings
            for finding in findings:
                summary += self.format_finding(finding)
                summary += "\n---\n"
            
            # Add footer
            summary += "\n## 📚 Next Steps\n\n"
            summary += "1. **Immediate:** Rotate all detected secrets\n"
            summary += "2. **Short-term:** Remove secrets from git history using BFG or git-filter-branch\n"
            summary += "3. **Long-term:** Implement pre-commit hooks to prevent future leaks\n\n"
            summary += "For more information, see [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)\n"
        
        # Write to GitHub Actions summary
        with open(self.summary_path, 'w') as f:
            f.write(summary)
        
        # Also save as artifact
        with open('gitleaks-summary.md', 'w') as f:
            f.write(summary)
        
        print(f"✅ Summary generated: {len(findings)} findings processed")
        
        return len(findings)

def main():
    parser = argparse.ArgumentParser(description='Parse Gitleaks report with context')
    parser.add_argument('--report', required=True, help='Path to Gitleaks JSON report')
    parser.add_argument('--mode', default='full', choices=['full', 'diff-only'], help='Scan mode')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.report):
        print(f"Report file not found: {args.report}")
        with open(os.environ.get('GITHUB_STEP_SUMMARY', 'gitleaks-summary.md'), 'w') as f:
            f.write("## ⚠️ No Gitleaks Report Found\n\nThe scan may have failed or found no results.")
        return
    
    parser = GitLeaksContextParser(args.report, args.mode)
    findings_count = parser.generate_summary()
    
    # Exit with non-zero if critical findings exist (optional)
    # sys.exit(1 if findings_count > 0 else 0)

if __name__ == "__main__":
    main()
