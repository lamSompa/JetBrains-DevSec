
---

# JetBrains DevSec LLM-Powered Secret Scanner

A Python CLI tool that scans the last N commits of a Git repository for secrets and sensitive data using a combination of heuristics (regex/entropy) and a Large Language Model (LLM) for validation.  
It analyzes code diffs and commit messages, reducing false positives and generating a detailed JSON report for security review.

---

## Live Demo

**Not applicable (CLI tool)**

---

## Project Overview

- **Scan Git History:** Analyze the last N commits of any Git repository for secrets or sensitive data.
- **Heuristic Detection:** Use regex patterns and entropy checks to flag likely secrets (API keys, tokens, passwords, etc.).
- **LLM Validation:** Classify and explain findings using a HuggingFace zero-shot classification model (can be swapped for any LLM).
- **Commit Message Analysis:** Detect secrets not only in code but also in commit messages.
- **JSON Reporting:** Output a detailed, review-ready JSON report with commit hash, file path, code snippet, finding type, rationale, and confidence.
- **Minimal CLI:** Simple command-line interface for quick integration into CI/CD or developer workflows.
- **Tested & Reliable:** Includes unit tests for all major modules.

---

## Features

- **Scan Last N Commits:** Specify how many recent commits to analyze.
- **Regex & Entropy Heuristics:** Catch a wide range of secret types with minimal false positives.
- **LLM-Powered Triage:** Use a language model to classify and explain each finding.
- **Commit Message Scanning:** No secrets slip through in commit logs.
- **Detailed JSON Report:** Easy to review, audit, and integrate into other tools.
- **Test Coverage:** Unit tests for detector, LLM, and scanner modules.

---

## Tech Stack

- **Python 3.8+**
- **GitPython** (for Git repo access)
- **transformers** (HuggingFace LLM integration)
- **pytest** (testing)
- **Standard Python libraries** (os, re, json, etc.)

---

## Installation & Setup

```bash
git clone https://github.com/lamSompa/JetBrains-DevSec.git
cd JetBrains-DevSec
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Example Usage

```bash
python -m jetbrains_dev_sec.cli --repo . --n 5 --out report.json
```

- `--repo`: Path to the Git repository to scan (can be `.` for current directory)
- `--n`: Number of most recent commits to scan
- `--out`: Output path for the JSON report

---

## Running Tests

```bash
PYTHONPATH=. pytest
```

---

## Output

The tool generates a JSON report with entries like:

```json
[
  {
    "commit_hash": "abc123...",
    "file_path": "src/secrets.py",
    "snippet": "api_key = \"AKIA...\"",
    "finding_type": "Pattern match",
    "rationale": "Matched pattern: api[_-]?key",
    "confidence": 0.9,
    "llm_explanation": "Top label: API key (confidence: 0.92)",
    "llm_label": "API key",
    "llm_confidence": 0.92
  }
]
```

---

## Project Structure

```
JetBrains-DevSec/
├── jetbrains_dev_sec/
│   ├── __init__.py
│   ├── cli.py
│   ├── detector.py
│   ├── llm.py
│   ├── report.py
│   └── scanner.py
├── tests/
│   ├── test_detector.py
│   ├── test_llm.py
│   └── test_scanner.py
├── requirements.txt
├── README.md
└── ...
```

---

## Clean Code & Best Practices

- **Separation of Concerns:** Detection, LLM, CLI, and reporting are modularized.
- **Error Handling:** File and model errors are caught and logged.
- **Consistent Naming:** Functions and variables use clear, descriptive names.
- **Testing:** All core logic is covered by unit tests.
- **Extensible:** Easy to add new secret patterns or swap out the LLM.

---

## License

This project is for demonstration and educational purposes only.  
Not affiliated with JetBrains.

---

**Made by lamSompa**

---
