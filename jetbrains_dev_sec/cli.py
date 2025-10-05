import argparse
from jetbrains_dev_sec.scanner import scan_commits
from jetbrains_dev_sec.report import write_report

def main():
    parser = argparse.ArgumentParser(description="JetBrains Dev Sec CLI")
    parser.add_argument('--repo', required=True, help='Path to the Git repository')
    parser.add_argument('--n', type=int, required=True, help='Number of commits to scan')
    parser.add_argument('--out', required=True, help='Output JSON report file')
    args = parser.parse_args()

    findings = scan_commits(args.repo, args.n)
    write_report(args.out, findings)
    print(f"Scan complete. Report saved to {args.out}. {len(findings)} findings detected.")

if __name__ == "__main__":
    main()
