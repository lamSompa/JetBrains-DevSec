from jetbrains_dev_sec.llm import analyze_with_llm

def test_llm_detects_secret():
    snippet = "password = 'supersecret123'"
    result = analyze_with_llm(snippet)
    assert "llm_label" in result
    assert "confidence" in result or "llm_confidence" in result
    assert isinstance(result["llm_label"], str)
    assert 0 <= result["llm_confidence"] <= 1
