import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
BASE_DIRECTORY = Path(__file__).resolve().parent

MODEL_PATH = (
    BASE_DIRECTORY
    / "models"
    / "phishing_email_model.joblib"
)


def load_email_model():
    try:
        return joblib.load(MODEL_PATH)

    except FileNotFoundError:
        print(
            "Warning: The trained email model "
            "was not found."
        )

        return None

    except Exception as error:
        print(
            "Unable to load email model:",
            error,
        )

        return None


EMAIL_MODEL = load_email_model()
SUSPICIOUS_WORDS = {
    "urgent": 8,
    "immediately": 8,
    "suspended": 12,
    "verify": 8,
    "password": 15,
    "otp": 15,
    "pin": 15,
    "cvv": 20,
    "winner": 10,
    "prize": 10,
    "refund": 8,
    "click here": 8,
    "confirm account": 12,
    "update account": 10,
    "bank account": 12,
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
}


def calculate_verdict(risk_score):
    if risk_score >= 70:
        return "phishing"

    if risk_score >= 35:
        return "suspicious"

    return "safe"


def analyze_url(url):
    risk_score = 0
    indicators = []

    normalized_url = url.strip()

    if "://" not in normalized_url:
        normalized_url = f"http://{normalized_url}"

    try:
        parsed_url = urlparse(normalized_url)
        hostname = (parsed_url.hostname or "").lower()
    except ValueError:
        return {
            "risk_score": 100,
            "verdict": "phishing",
            "confidence": 95,
            "indicators": [
                {
                    "indicator": "Invalid or malformed URL",
                    "category": "url",
                    "weight": 100,
                }
            ],
        }

    def add_indicator(condition, message, weight):
        nonlocal risk_score

        if condition:
            risk_score += weight

            indicators.append(
                {
                    "indicator": message,
                    "category": "url",
                    "weight": weight,
                }
            )

    is_ip_address = bool(
        re.fullmatch(
            r"\d{1,3}(?:\.\d{1,3}){3}",
            hostname,
        )
    )

    add_indicator(
        hostname in URL_SHORTENERS,
        "URL-shortening service hides the final destination",
        30,
    )

    add_indicator(
        is_ip_address,
        "Raw IP address is used instead of a domain name",
        35,
    )

    add_indicator(
        "@" in normalized_url,
        "URL contains an @ redirect pattern",
        25,
    )

    add_indicator(
        len(normalized_url) > 100,
        "URL is unusually long",
        15,
    )

    add_indicator(
        hostname.count(".") >= 4,
        "URL contains excessive subdomains",
        15,
    )

    add_indicator(
        "xn--" in hostname,
        "Punycode domain may imitate a trusted domain",
        25,
    )

    add_indicator(
        parsed_url.scheme != "https",
        "URL does not use HTTPS",
        10,
    )

    sensitive_terms = [
        "login",
        "verify",
        "secure",
        "account",
        "password",
        "update",
    ]

    add_indicator(
        any(
            term in normalized_url.lower()
            for term in sensitive_terms
        ),
        "URL contains sensitive-action terminology",
        10,
    )

    risk_score = min(risk_score, 100)

    confidence = min(
        95,
        55 + (len(indicators) * 8),
    )

    return {
        "risk_score": risk_score,
        "verdict": calculate_verdict(risk_score),
        "confidence": confidence,
        "indicators": indicators,
    }


def extract_urls(email_body):
    url_pattern = r'https?://[^\s<>"\']+'

    extracted_urls = re.findall(
        url_pattern,
        email_body,
        flags=re.IGNORECASE,
    )

    return [
        url.rstrip(".,);]")
        for url in extracted_urls
    ]

def predict_email_with_ml(subject, body):
    if EMAIL_MODEL is None:
        return {
            "available": False,
            "prediction": "unavailable",
            "phishing_probability": 0,
            "safe_probability": 0,
        }

    combined_email_text = (
        f"{subject} {body}"
    ).strip()

    probabilities = (
        EMAIL_MODEL.predict_proba(
            [combined_email_text]
        )[0]
    )

    class_names = list(
        EMAIL_MODEL.classes_
    )

    phishing_index = class_names.index(
        "phishing"
    )

    safe_index = class_names.index(
        "safe"
    )

    phishing_probability = round(
        float(
            probabilities[phishing_index]
        ) * 100,
        2,
    )

    safe_probability = round(
        float(
            probabilities[safe_index]
        ) * 100,
        2,
    )

    prediction = EMAIL_MODEL.predict(
        [combined_email_text]
    )[0]

    return {
        "available": True,
        "prediction": prediction,
        "phishing_probability":
            phishing_probability,
        "safe_probability":
            safe_probability,
    }
def analyze_email(email_data):
    sender = email_data.get("sender", "").strip()
    subject = email_data.get("subject", "").strip()
    body = email_data.get("body", "").strip()

    combined_text = f"{subject} {body}".lower()

    ml_result = predict_email_with_ml(
        subject,
        body,
    )

    risk_score = 0
    indicators = []

    def add_indicator(
        condition,
        message,
        category,
        weight,
    ):
        nonlocal risk_score

        if condition:
            risk_score += weight

            indicators.append(
                {
                    "indicator": message,
                    "category": category,
                    "weight": weight,
                }
            )

    matched_words = [
        word
        for word in SUSPICIOUS_WORDS
        if word in combined_text
    ]

    suspicious_word_score = sum(
        SUSPICIOUS_WORDS[word]
        for word in matched_words
    )

    if matched_words:
        applied_weight = min(suspicious_word_score, 35)
        risk_score += applied_weight

        indicators.append(
            {
                "indicator": (
                    "Suspicious language detected: "
                    + ", ".join(matched_words)
                ),
                "category": "content",
                "weight": applied_weight,
            }
        )

    add_indicator(
        bool(
            re.search(
                r"\b(password|otp|pin|cvv)\b",
                combined_text,
            )
        ),
        "Email requests authentication or payment information",
        "credential_request",
        25,
    )

    add_indicator(
        body.count("!") >= 3,
        "Email contains excessive exclamation marks",
        "formatting",
        8,
    )

    add_indicator(
        subject.isupper() and len(subject) >= 6,
        "Subject uses aggressive uppercase formatting",
        "urgency",
        8,
    )

    add_indicator(
        bool(sender) and "@" not in sender,
        "Sender email address is malformed",
        "sender",
        15,
    )

    extracted_urls = extract_urls(body)

    for extracted_url in extracted_urls[:5]:
        url_result = analyze_url(extracted_url)

        if url_result["risk_score"] >= 35:
            url_weight = min(
                30,
                round(url_result["risk_score"] / 2),
            )

            risk_score += url_weight

            indicators.append(
                {
                    "indicator": (
                        f"Suspicious embedded URL: {extracted_url}"
                    ),
                    "category": "url",
                    "weight": url_weight,
                }
            )

    rule_risk_score = min(
        risk_score,
        100,
    )

    if ml_result["available"]:
        ml_risk_score = ml_result[
            "phishing_probability"
        ]

        hybrid_risk_score = round(
            (rule_risk_score * 0.70)
            + (ml_risk_score * 0.30)
        )

        if (
            ml_result["prediction"]
            == "phishing"
        ):
            indicators.append(
                {
                    "indicator": (
                        "Machine-learning model "
                        "detected phishing language "
                        f"with {ml_risk_score}% "
                        "probability"
                    ),
                    "category": "other",
                    "weight": round(
                        ml_risk_score * 0.30
                    ),
                }
            )
    else:
        ml_risk_score = 0
        hybrid_risk_score = (
            rule_risk_score
        )

    hybrid_risk_score = min(
        hybrid_risk_score,
        100,
    )

    confidence = min(
        97,
        55 + (len(indicators) * 7),
    )

    return {
        "risk_score": hybrid_risk_score,
        "rule_risk_score": rule_risk_score,
        "ml_risk_score": ml_risk_score,

        "verdict": calculate_verdict(
            hybrid_risk_score
        ),

        "confidence": confidence,
        "indicators": indicators,
        "extracted_urls": extracted_urls,
        "ml_analysis": ml_result,

        "detection_method":
            "hybrid-ml-rule-fusion-v2",
    }