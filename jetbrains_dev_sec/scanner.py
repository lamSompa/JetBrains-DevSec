import git
from jetbrains_dev_sec.detector import detect_secrets
from jetbrains_dev_sec.llm import analyze_with_llm
import os

NULL_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

def scan_commits(repo_path: str, n: int):
    repo = git.Repo(repo_path)
    commits = list(repo.iter_commits('HEAD', max_count=n))
    findings = []

    for commit in commits:
        if commit.parents:
            diff = commit.diff(commit.parents[0])
        else:
            diff = commit.diff(NULL_TREE)
        print("Commit:", commit.hexsha)
        print("Diff length:", len(diff))
        for diff_item in diff:
            b_text = ""
            if diff_item.new_file:
                file_path_on_disk = os.path.join(repo.working_tree_dir, diff_item.b_path)
                try:
                    with open(file_path_on_disk, "r", encoding="utf-8", errors="ignore") as f:
                        b_text = f.read()
                except Exception as e:
                    print(f"Error reading {file_path_on_disk}: {e}")
                    continue
            elif diff_item.b_blob:
                diff_item.b_blob.data_stream.seek(0)
                b_text = diff_item.b_blob.data_stream.read().decode(errors="ignore")
            else:
                continue
            print("Diff file:", diff_item.b_path)
            print("Diff content:", repr(b_text))
            secrets = detect_secrets(b_text)
            print("Secrets found:", secrets)
            file_path = diff_item.b_path
            for secret in secrets:
                llm_result = analyze_with_llm(secret["value"])
                findings.append({
                    "commit_hash": commit.hexsha,
                    "file_path": file_path,
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
