import git
from jetbrains_dev_sec.detector import detect_secrets

NULL_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

def scan_commits(repo_path: str, n: int):
    repo = git.Repo(repo_path)
    commits = list(repo.iter_commits('HEAD', max_count=n))
    findings = []

    for commit in commits:
        diff = commit.diff(commit.parents[0]) if commit.parents else commit.diff(NULL_TREE)
        for diff_item in diff:
            if diff_item.b_blob:
                try:
                    b_text = diff_item.b_blob.data_stream.read().decode(errors="ignore")
                except Exception:
                    continue
                file_path = diff_item.b_path
                secrets = detect_secrets(b_text)
                for secret in secrets:
                    findings.append({
                        "commit_hash": commit.hexsha,
                        "file_path": file_path,
                        "snippet": secret["value"],
                        "finding_type": secret["type"],
                        "rationale": secret["rationale"],
                        "confidence": secret["confidence"]
                    })
        # Also scan commit message
        message_secrets = detect_secrets(commit.message)
        for secret in message_secrets:
            findings.append({
                "commit_hash": commit.hexsha,
                "file_path": "(commit message)",
                "snippet": secret["value"],
                "finding_type": secret["type"],
                "rationale": secret["rationale"],
                "confidence": secret["confidence"]
            })
    return findings
