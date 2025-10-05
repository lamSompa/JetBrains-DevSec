import git
from jetbrains_dev_sec.detector import detect_secrets
from jetbrains_dev_sec.llm import analyze_with_llm

def scan_commits(repo_path: str, n: int):
    repo = git.Repo(repo_path)
    commits = list(repo.iter_commits('HEAD', max_count=n))
    findings = []

    for commit in commits:
        print("Commit:", commit.hexsha)
        tree = commit.tree
        for blob in tree.traverse():
            if blob.type == "blob":
                print("Scanning file:", blob.path)
                try:
                    content = blob.data_stream.read().decode("utf-8", errors="ignore")
                except Exception as e:
                    print(f"Error reading {blob.path}: {e}")
                    continue
                print("File content:", repr(content))
                secrets = detect_secrets(content)
                print("Secrets found:", secrets)
                for secret in secrets:
                    llm_result = analyze_with_llm(secret["value"])
                    findings.append({
                        "commit_hash": commit.hexsha,
                        "file_path": blob.path,
                        "snippet": secret["value"],
                        "finding_type": secret["type"],
                        "rationale": secret["rationale"],
                        "confidence": secret["confidence"],
                        "llm_explanation": llm_result["llm_explanation"],
                        "llm_label": llm_result["llm_label"],
                        "llm_confidence": llm_result["llm_confidence"]
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
                "llm_label": llm_result["llm_label"],
                "llm_confidence": llm_result["llm_confidence"]
            })
    return findings
