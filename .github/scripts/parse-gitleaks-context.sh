#!/bin/bash
# Gitleaks Context Parser - Bash Version
# Extracts context around detected secrets and generates GitHub Actions summary

set -euo pipefail

# Default values
REPORT_PATH=""
MODE="full"
CONTEXT_LINES=3
SUMMARY_PATH="${GITHUB_STEP_SUMMARY:-gitleaks-summary.md}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --report)
            REPORT_PATH="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if report file exists
if [[ ! -f "$REPORT_PATH" ]]; then
    echo "Report file not found: $REPORT_PATH"
    echo "## ⚠️ No Gitleaks Report Found" > "$SUMMARY_PATH"
    echo "" >> "$SUMMARY_PATH"
    echo "The scan may have failed or found no results." >> "$SUMMARY_PATH"
    exit 0
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed"
    echo "Install it with: apt-get install jq"
    exit 1
fi

# Function to get file context
get_file_context() {
    local commit="$1"
    local file_path="$2"
    local line_number="$3"
    local temp_file=$(mktemp)
    
    # Try to get the file content at the specific commit
    if git show "${commit}:${file_path}" > "$temp_file" 2>/dev/null; then
        # Calculate line range
        local start_line=$((line_number - CONTEXT_LINES))
        local end_line=$((line_number + CONTEXT_LINES))
        
        # Ensure start_line is at least 1
        if [[ $start_line -lt 1 ]]; then
            start_line=1
        fi
        
        # Extract lines with line numbers
        local current_line=$start_line
        while IFS= read -r line && [[ $current_line -le $end_line ]]; do
            if [[ $current_line -eq $line_number ]]; then
                printf "%4d | >>> %s\n" "$current_line" "$line"
            else
                printf "%4d |     %s\n" "$current_line" "$line"
            fi
            ((current_line++))
        done < <(sed -n "${start_line},${end_line}p" "$temp_file")
        
        rm -f "$temp_file"
        return 0
    else
        rm -f "$temp_file"
        return 1
    fi
}

# Function to get commit info
get_commit_info() {
    local commit="$1"
    local info
    
    if info=$(git show --no-patch --format='%an|%ae|%ad|%s' "$commit" 2>/dev/null); then
        echo "$info"
    else
        echo "Unknown|||"
    fi
}

# Function to determine severity emoji
get_severity_emoji() {
    local rule_id="$1"
    local rule_lower=$(echo "$rule_id" | tr '[:upper:]' '[:lower:]')
    
    # Critical patterns
    if [[ "$rule_lower" =~ (private[_-]key|aws[_-]access|github[_-]pat|api[_-]key) ]]; then
        echo "🔴"
    # High severity patterns
    elif [[ "$rule_lower" =~ (password|token|secret|credential) ]]; then
        echo "🟠"
    else
        echo "🟡"
    fi
}

# Function to get file extension for syntax highlighting
get_language() {
    local file_path="$1"
    local extension="${file_path##*.}"
    
    case "$extension" in
        py) echo "python" ;;
        js) echo "javascript" ;;
        ts) echo "typescript" ;;
        go) echo "go" ;;
        java) echo "java" ;;
        rb) echo "ruby" ;;
        php) echo "php" ;;
        yml|yaml) echo "yaml" ;;
        json) echo "json" ;;
        xml) echo "xml" ;;
        sh|bash) echo "bash" ;;
        env) echo "bash" ;;
        *) echo "$extension" ;;
    esac
}

# Function to format a single finding
format_finding() {
    local finding="$1"
    local output=""
    
    # Extract fields from JSON
    local commit=$(echo "$finding" | jq -r '.Commit // ""')
    local file_path=$(echo "$finding" | jq -r '.File // ""')
    local line_number=$(echo "$finding" | jq -r '.StartLine // 0')
    local rule_id=$(echo "$finding" | jq -r '.RuleID // "unknown"')
    local description=$(echo "$finding" | jq -r '.Description // ""')
    
    # Get additional info
    local severity=$(get_severity_emoji "$rule_id")
    local commit_info=$(get_commit_info "$commit")
    local author=$(echo "$commit_info" | cut -d'|' -f1)
    local date=$(echo "$commit_info" | cut -d'|' -f3)
    
    # Format the finding
    output+="### ${severity} Secret Detected: ${rule_id}\n\n"
    output+="**File:** \`${file_path}\`  \n"
    output+="**Line:** ${line_number}  \n"
    output+="**Commit:** [${commit:0:7}](../../commit/${commit})  \n"
    output+="**Author:** ${author}  \n"
    output+="**Date:** ${date}  \n"
    
    if [[ -n "$description" ]]; then
        output+="**Description:** ${description}  \n"
    fi
    
    output+="\n<details>\n<summary>📋 View Context</summary>\n\n"
    
    # Get file context
    local context_output=$(mktemp)
    if get_file_context "$commit" "$file_path" "$line_number" > "$context_output"; then
        local language=$(get_language "$file_path")
        output+="\`\`\`${language}\n"
        output+="$(cat "$context_output")\n"
        output+="\`\`\`\n"
    else
        output+="*Context unavailable (file may be deleted)*\n"
    fi
    rm -f "$context_output"
    
    output+="\n</details>\n\n"
    
    # Add remediation hints
    output+="**🔧 Remediation:**\n"
    
    local rule_lower=$(echo "$rule_id" | tr '[:upper:]' '[:lower:]')
    if [[ "$rule_lower" =~ aws ]]; then
        output+="- Rotate the AWS credentials immediately\n"
        output+="- Use AWS IAM roles or environment variables instead\n"
    elif [[ "$rule_lower" =~ github ]]; then
        output+="- Revoke the token in GitHub Settings > Developer settings\n"
        output+="- Use GitHub Actions secrets for CI/CD\n"
    elif [[ "$rule_lower" =~ private && "$rule_lower" =~ key ]]; then
        output+="- Generate new key pair immediately\n"
        output+="- Never commit private keys to version control\n"
    else
        output+="- Rotate/revoke this secret immediately\n"
        output+="- Use environment variables or secret management tools\n"
    fi
    
    echo -e "$output"
}

# Main processing
main() {
    # Count findings
    local findings_count=$(jq 'length' "$REPORT_PATH")
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S UTC')
    
    echo "✅ Summary generated: ${findings_count} findings processed"
    
    # Start building summary
    local summary=""
    
    if [[ $findings_count -eq 0 ]]; then
        summary+="## ✅ No Secrets Detected\n\n"
        summary+="**Scan Mode:** ${MODE}\n"
        summary+="**Timestamp:** ${timestamp}\n"
    else
        summary+="## 🚨 Gitleaks Security Report\n\n"
        summary+="**Total Findings:** ${findings_count}  \n"
        summary+="**Scan Mode:** ${MODE}  \n"
        summary+="**Timestamp:** ${timestamp}\n\n"
        
        # Count by severity
        local critical_count=0
        local high_count=0
        local medium_count=0
        
        # Process each finding for counting
        while IFS= read -r finding; do
            local rule_id=$(echo "$finding" | jq -r '.RuleID // ""' | tr '[:upper:]' '[:lower:]')
            
            if [[ "$rule_id" =~ (private[_-]key|aws[_-]access|github[_-]pat|api[_-]key) ]]; then
                ((critical_count++))
            elif [[ "$rule_id" =~ (password|token|secret|credential) ]]; then
                ((high_count++))
            else
                ((medium_count++))
            fi
        done < <(jq -c '.[]' "$REPORT_PATH")
        
        # Add severity summary
        if [[ $critical_count -gt 0 ]]; then
            summary+="- 🔴 **Critical:** ${critical_count}\n"
        fi
        if [[ $high_count -gt 0 ]]; then
            summary+="- 🟠 **High:** ${high_count}\n"
        fi
        if [[ $medium_count -gt 0 ]]; then
            summary+="- 🟡 **Medium:** ${medium_count}\n"
        fi
        
        summary+="\n---\n\n"
        
        # Process each finding for detailed output
        while IFS= read -r finding; do
            summary+=$(format_finding "$finding")
            summary+="\n---\n\n"
        done < <(jq -c '.[]' "$REPORT_PATH")
        
        # Add footer
        summary+="## 📚 Next Steps\n\n"
        summary+="1. **Immediate:** Rotate all detected secrets\n"
        summary+="2. **Short-term:** Remove secrets from git history using BFG or git-filter-branch\n"
        summary+="3. **Long-term:** Implement pre-commit hooks to prevent future leaks\n\n"
        summary+="For more information, see [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)\n"
    fi
    
    # Write summary to files
    echo -e "$summary" > "$SUMMARY_PATH"
    echo -e "$summary" > "gitleaks-summary.md"
}

# Run main function
main
