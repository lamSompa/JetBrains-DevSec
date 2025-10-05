import re
import math

SECRET_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS Access Key ID
    re.compile(r'secret[_-]?key\s*=\s*[\'"][^\'"]+[\'"]', re.IGNORECASE),
    re.compile(r'password\s*=\s*[\'"][^\'"]+[\'"]', re.IGNORECASE),
    re.compile(r'api[_-]?key\s*=\s*[\'"][^\'"]+[\'"]', re.IGNORECASE),
]

def shannon_entropy(data: str) -> float:
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def detect_secrets(text: str):
    findings = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append({
                "type": "Pattern match",
                "value": match.group(),
                "rationale": f"Matched pattern: {pattern.pattern}",
                "confidence": 0.9
            })
    for word in text.split():
        if len(word) > 20 and shannon_entropy(word) > 4.0:
            findings.append({
                "type": "High entropy string",
                "value": word,
                "rationale": "High entropy detected (possible secret)",
                "confidence": 0.7
            })
    return findings
