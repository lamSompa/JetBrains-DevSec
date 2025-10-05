from jetbrains_dev_sec.detector import detect_secrets

def test_detect_fake_aws_key():
    code = 'aws_key = "AKIA1234567890EXAMPLE"'
    findings = detect_secrets(code)
    assert any("AKIA" in finding["value"] for finding in findings)
