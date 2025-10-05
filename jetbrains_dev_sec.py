import argparse
import git
import re
import json
import os
import math
from typing import List, Dict

# Secret detection heuristics 

SECRET_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS Access Key ID
    re.compile(r'secret[_-]?key\s*=\s*[\'"][^\'"]+[\'"]', re.IGNORECASE),
    re.compile(r'password\s*=\s*[\'"][^\'"]+[\'"]', re.IGNORECASE),
]
aws_key = "AKIA1234567890EXAMPLE"

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def detect_secrets(text: str) -> List[Dict]:
    """Detect secrets using regex and entropy."""
    findings = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append({
                "type": "Pattern match",
                "value": match.group(),
                "rationale": f"Matched pattern: {pattern.pattern}",
                "confidence": 0.9
            })

    # Entropy-based detection (tune threshold as needed)
    for word in text.split():
        if len(word) > 20 and shannon_entropy(word) > 4.0:
            findings.append({
                "type": "High entropy string",
                "value": word,
                "rationale": "High entropy detected (possible secret)",
                "confidence": 0.7
            })
    return findings

# LLM Analysis Stub

def analyze_with_llm(snippet: str) -> Dict:
    """
    Placeholder for LLM analysis.
    Replace with real API call if you have an OpenAI/HuggingFace key.
    """
    # Example: return a mock response
    return {
        "llm_explanation": "This code snippet may contain a secret. Please review.",
        "confidence": 0.8
    }

def scan_commits(repo_path: str, n: int) -> List[Dict]:
    repo = git.Repo(repo_path)
    commits = list(repo.iter_commits('HEAD', max_count=n))
    findings = []

    for commit in commits:
        diff = commit.diff(commit.parents[0]) if commit.parents else commit.diff(NULL_TREE)
        for diff_item in diff:
            if diff_item.a_blob and diff_item.b_blob:
                # Changed file
                try:
                    a_text = diff_item.a_blob.data_stream.read().decode(errors="ignore")
                    b_text = diff_item.b_blob.data_stream.read().decode(errors="ignore")
                except Exception:
                    continue
                changes = b_text
                file_path = diff_item.b_path
            elif diff_item.b_blob:
                # New file
                try:
                    b_text = diff_item.b_blob.data_stream.read().decode(errors="ignore")
                except Exception:
                    continue
                changes = b_text
                file_path = diff_item.b_path
            else:
                continue

            # Heuristic secret detection
            secrets = detect_secrets(changes)
            for secret in secrets:
                # LLM analysis (stubbed)
                llm_result = analyze_with_llm(secret["value"])
                findings.append({
                    "commit_hash": commit.hexsha,
                    "file_path": file_path,
                    "snippet": secret["value"],
                    "finding_type": secret["type"],
                    "rationale": secret["rationale"],
                    "confidence": secret["confidence"],
                    "llm_explanation": llm_result["llm_explanation"],
                    "llm_confidence": llm_result["confidence"]
                })

        message_secrets = detect_secrets(commit.message)
        for secret in message_secrets:
            llm_result = analyze_with_llm(secret["value"])
            findings.append({
                "commit_hash": commit.hexsha,
                "file_path": "(commit message)",
                "snippet": secret["value"],
                "finding_type": secret["type"],
                "rationale": secret["rationale"],
                "confidence": secret["confidence"],
                "llm_explanation": llm_result["llm_explanation"],
                "llm_confidence": llm_result["confidence"]
            })

    return findings
NULL_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

def main():
    parser = argparse.ArgumentParser(description="JetBrains Dev Sec - AI-powered security reviewer")
    parser.add_argument('--repo', required=True, help='Path to the Git repository')
    parser.add_argument('--n', type=int, required=True, help='Number of commits to scan')
    parser.add_argument('--out', required=True, help='Output JSON report file')
    args = parser.parse_args()

    if not os.path.isdir(args.repo):
        print(f"Repository path {args.repo} does not exist or is not a directory.")
        return

    print(f"Scanning {args.repo} for last {args.n} commits...")

    findings = scan_commits(args.repo, args.n)

    report = {
        "repo": args.repo,
        "num_commits_scanned": args.n,
        "findings": findings
    }

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Scan complete. Report saved to {args.out}. {len(findings)} findings detected.")

if __name__ == "__main__":
    main()
