import json

def write_report(filename, findings):
    report = {
        "findings": findings
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
