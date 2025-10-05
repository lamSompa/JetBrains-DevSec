from transformers import pipeline

# Load the zero-shot-classification pipeline
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

def analyze_with_llm(snippet: str):
    """
    Uses Hugging Face zero-shot-classification to judge if a snippet is likely a secret.
    Returns a rationale and confidence.
    """
    candidate_labels = ["contains secret", "safe code", "password", "API key", "token", "random string"]
    result = classifier(snippet, candidate_labels)
    top_label = result['labels'][0]
    top_score = result['scores'][0]
    return {
        "llm_explanation": f"Top label: {top_label} (confidence: {top_score:.2f})",
        "llm_label": top_label,
        "llm_confidence": float(top_score)
    }
