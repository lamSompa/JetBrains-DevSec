import git
from jetbrains_dev_sec.scanner import scan_commits

def test_scan_commits(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    repo = git.Repo.init(str(repo_dir))

    # First commit: add a normal file
    normal_file = repo_dir / "normal.py"
    normal_file.write_text('print("hello")')
    repo.index.add([str(normal_file)])
    repo.index.commit("Initial commit")

    # Second commit: add a NEW file with a secret
    secret_file = repo_dir / "secrets.py"
    secret_file.write_text('api_key = "AKIA1234567890EXAMPLE"')
    repo.index.add([str(secret_file)])
    repo.index.commit("Add fake API key")

    findings = scan_commits(str(repo_dir), 2)
    print("Findings:", findings)
    assert any("AKIA" in finding["snippet"] for finding in findings)
