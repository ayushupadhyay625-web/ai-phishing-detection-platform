import ipaddress
import re

from pathlib import Path

from urllib.parse import (
    parse_qs,
    unquote,
    urlparse,
)

import joblib


BASE_DIRECTORY = (
    Path(__file__).resolve().parent
)

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
    "verification": 8,
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
    "account closure": 12,
    "unusual activity": 8,
    "security alert": 8,
}


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
}


SUSPICIOUS_HOST_TERMS = {
    "account",
    "alert",
    "auth",
    "bank",
    "billing",
    "confirm",
    "credential",
    "login",
    "password",
    "payment",
    "recover",
    "secure",
    "security",
    "signin",
    "support",
    "unlock",
    "update",
    "verification",
    "verify",
    "wallet",
}


SUSPICIOUS_PATH_TERMS = {
    "account",
    "authenticate",
    "bank",
    "billing",
    "card",
    "confirm",
    "credential",
    "login",
    "otp",
    "password",
    "payment",
    "pin",
    "recover",
    "reset",
    "secure",
    "signin",
    "suspended",
    "unlock",
    "update",
    "verification",
    "verify",
}


SENSITIVE_QUERY_TERMS = {
    "account",
    "card",
    "confirm",
    "credential",
    "cvv",
    "login",
    "otp",
    "password",
    "payment",
    "pin",
    "redirect",
    "session",
    "token",
    "verify",
}


SUSPICIOUS_FILE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".jar",
    ".zip",
    ".rar",
    ".iso",
}


def calculate_verdict(risk_score):
    if risk_score >= 70:
        return "phishing"

    if risk_score >= 35:
        return "suspicious"

    return "safe"


def is_ip_hostname(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def count_matching_terms(
    text,
    terms,
):
    normalized_text = text.lower()

    return sorted(
        term
        for term in terms
        if term in normalized_text
    )


def analyze_url(url):
    risk_score = 0
    indicators = []

    original_url = (
        str(url or "").strip()
    )

    if not original_url:
        return {
            "risk_score": 100,
            "verdict": "phishing",
            "confidence": 95,
            "indicators": [
                {
                    "indicator":
                        "URL is empty or missing",
                    "category": "url",
                    "weight": 100,
                }
            ],
        }

    normalized_url = original_url

    scheme_was_missing = (
        "://" not in normalized_url
    )

    if scheme_was_missing:
        normalized_url = (
            f"http://{normalized_url}"
        )

    try:
        parsed_url = urlparse(
            normalized_url
        )

        hostname = (
            parsed_url.hostname or ""
        ).lower()

        port = parsed_url.port

    except ValueError:
        return {
            "risk_score": 100,
            "verdict": "phishing",
            "confidence": 95,
            "indicators": [
                {
                    "indicator":
                        "Invalid or malformed URL",
                    "category": "url",
                    "weight": 100,
                }
            ],
        }

    def add_indicator(
        condition,
        message,
        weight,
    ):
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

    if not hostname:
        add_indicator(
            True,
            "URL does not contain a valid hostname",
            100,
        )

        risk_score = min(
            risk_score,
            100,
        )

        return {
            "risk_score": risk_score,
            "verdict":
                calculate_verdict(
                    risk_score
                ),
            "confidence": 95,
            "indicators": indicators,
        }

    decoded_url = unquote(
        normalized_url
    ).lower()

    decoded_path = unquote(
        parsed_url.path or ""
    ).lower()

    decoded_query = unquote(
        parsed_url.query or ""
    ).lower()

    hostname_parts = [
        part
        for part in hostname.split(".")
        if part
    ]

    registered_domain_guess = (
        ".".join(hostname_parts[-2:])
        if len(hostname_parts) >= 2
        else hostname
    )

    is_ip_address = (
        is_ip_hostname(hostname)
    )

    hostname_terms = (
        count_matching_terms(
            hostname,
            SUSPICIOUS_HOST_TERMS,
        )
    )

    path_terms = (
        count_matching_terms(
            decoded_path,
            SUSPICIOUS_PATH_TERMS,
        )
    )

    query_terms = (
        count_matching_terms(
            decoded_query,
            SENSITIVE_QUERY_TERMS,
        )
    )

    parsed_query = parse_qs(
        parsed_url.query,
        keep_blank_values=True,
    )

    query_keys = {
        key.lower()
        for key in parsed_query
    }

    sensitive_query_keys = sorted(
        query_keys.intersection(
            SENSITIVE_QUERY_TERMS
        )
    )

    add_indicator(
        registered_domain_guess
        in URL_SHORTENERS,
        (
            "URL-shortening service hides "
            "the final destination"
        ),
        35,
    )

    add_indicator(
        is_ip_address,
        (
            "Raw IP address is used instead "
            "of a domain name"
        ),
        40,
    )

    add_indicator(
        scheme_was_missing,
        (
            "URL scheme was missing and had "
            "to be inferred"
        ),
        8,
    )

    add_indicator(
        parsed_url.scheme.lower()
        not in {"http", "https"},
        "URL uses an unsupported protocol",
        35,
    )

    add_indicator(
        parsed_url.scheme.lower()
        != "https",
        "URL does not use HTTPS",
        15,
    )

    add_indicator(
        "@" in parsed_url.netloc,
        (
            "URL contains an @ symbol that "
            "may hide the actual destination"
        ),
        30,
    )

    add_indicator(
        len(normalized_url) > 100,
        "URL is unusually long",
        15,
    )

    add_indicator(
        len(normalized_url) > 180,
        "URL length is extremely excessive",
        15,
    )

    add_indicator(
        hostname.count(".") >= 4,
        "URL contains excessive subdomains",
        18,
    )

    add_indicator(
        "xn--" in hostname,
        (
            "Punycode domain may imitate "
            "a trusted domain"
        ),
        30,
    )

    add_indicator(
        hostname.count("-") >= 2,
        (
            "Domain contains multiple hyphens "
            "commonly used in deceptive names"
        ),
        12,
    )

    add_indicator(
        len(hostname) > 45,
        "Domain name is unusually long",
        12,
    )

    add_indicator(
        bool(
            re.search(
                r"%[0-9a-fA-F]{2}",
                original_url,
            )
        ),
        (
            "URL contains encoded characters "
            "that may conceal its destination"
        ),
        15,
    )

    add_indicator(
        "//" in (
            parsed_url.path or ""
        ),
        (
            "URL path contains a secondary "
            "double-slash redirect pattern"
        ),
        18,
    )

    add_indicator(
        port is not None
        and port not in {80, 443},
        (
            "URL uses an unusual network port"
        ),
        18,
    )

    add_indicator(
        any(
            decoded_path.endswith(extension)
            for extension
            in SUSPICIOUS_FILE_EXTENSIONS
        ),
        (
            "URL points to a potentially "
            "dangerous downloadable file"
        ),
        30,
    )

    if hostname_terms:
        hostname_weight = min(
            30,
            12
            + (
                len(hostname_terms)
                * 6
            ),
        )

        add_indicator(
            True,
            (
                "Domain contains suspicious "
                "security-action terminology: "
                + ", ".join(hostname_terms)
            ),
            hostname_weight,
        )

    if path_terms:
        path_weight = min(
            30,
            10
            + (
                len(path_terms)
                * 5
            ),
        )

        add_indicator(
            True,
            (
                "URL path requests a sensitive "
                "action: "
                + ", ".join(path_terms)
            ),
            path_weight,
        )

    if query_terms:
        query_weight = min(
            25,
            8
            + (
                len(query_terms)
                * 4
            ),
        )

        add_indicator(
            True,
            (
                "URL query contains sensitive "
                "parameters: "
                + ", ".join(query_terms)
            ),
            query_weight,
        )

    add_indicator(
        len(sensitive_query_keys) >= 2,
        (
            "URL requests multiple sensitive "
            "values through query parameters"
        ),
        18,
    )

    digit_ratio = (
        sum(
            character.isdigit()
            for character in hostname
        )
        / max(len(hostname), 1)
    )

    add_indicator(
        digit_ratio > 0.30
        and not is_ip_address,
        (
            "Domain contains an unusually "
            "high number of digits"
        ),
        12,
    )

    add_indicator(
        hostname.endswith(".example")
        and bool(
            hostname_terms
            or path_terms
            or query_terms
        ),
        (
            "Reserved demonstration domain "
            "contains simulated phishing patterns"
        ),
        10,
    )

    risk_score = min(
        round(risk_score),
        100,
    )

    if indicators:
        confidence = min(
            97,
            58
            + (len(indicators) * 6)
            + round(risk_score * 0.12),
        )

    else:
        confidence = 72

    return {
        "risk_score": risk_score,
        "verdict":
            calculate_verdict(
                risk_score
            ),
        "confidence": confidence,
        "indicators": indicators,
    }


def extract_urls(email_body):
    url_pattern = (
        r'https?://[^\s<>"\']+'
    )

    extracted_urls = re.findall(
        url_pattern,
        email_body,
        flags=re.IGNORECASE,
    )

    return [
        url.rstrip(".,);]}")
        for url in extracted_urls
    ]


def predict_email_with_ml(
    sender,
    subject,
    body,
):
    if EMAIL_MODEL is None:
        return {
            "available": False,
            "prediction": "unavailable",
            "phishing_probability": 0,
            "safe_probability": 0,
        }

    combined_email_text = (
        f"Sender: {sender}\n"
        f"Subject: {subject}\n"
        f"Body: {body}"
    ).strip()

    try:
        probabilities = (
            EMAIL_MODEL.predict_proba(
                [combined_email_text]
            )[0]
        )

        class_names = list(
            EMAIL_MODEL.classes_
        )

        phishing_index = (
            class_names.index(
                "phishing"
            )
        )

        safe_index = (
            class_names.index("safe")
        )

        phishing_probability = round(
            float(
                probabilities[
                    phishing_index
                ]
            )
            * 100,
            2,
        )

        safe_probability = round(
            float(
                probabilities[
                    safe_index
                ]
            )
            * 100,
            2,
        )

        prediction = (
            EMAIL_MODEL.predict(
                [combined_email_text]
            )[0]
        )

        return {
            "available": True,
            "prediction": prediction,
            "phishing_probability":
                phishing_probability,
            "safe_probability":
                safe_probability,
        }

    except Exception as error:
        print(
            "Email ML prediction failed:",
            error,
        )

        return {
            "available": False,
            "prediction": "unavailable",
            "phishing_probability": 0,
            "safe_probability": 0,
        }


def extract_sender_address(sender):
    sender_match = re.search(
        r"<([^<>]+)>",
        sender,
    )

    if sender_match:
        return (
            sender_match.group(1)
            .strip()
            .lower()
        )

    return sender.strip().lower()


def analyze_email(email_data):
    sender = (
        email_data
        .get("sender", "")
        .strip()
    )

    subject = (
        email_data
        .get("subject", "")
        .strip()
    )

    body = (
        email_data
        .get("body", "")
        .strip()
    )

    combined_text = (
        f"{subject} {body}"
    ).lower()

    sender_address = (
        extract_sender_address(sender)
    )

    ml_result = (
        predict_email_with_ml(
            sender,
            subject,
            body,
        )
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
        applied_weight = min(
            suspicious_word_score,
            35,
        )

        risk_score += applied_weight

        indicators.append(
            {
                "indicator": (
                    "Suspicious language detected: "
                    + ", ".join(
                        matched_words
                    )
                ),
                "category": "content",
                "weight": applied_weight,
            }
        )

    add_indicator(
        bool(
            re.search(
                (
                    r"\b(password|otp|pin|"
                    r"cvv|card number|"
                    r"banking details)\b"
                ),
                combined_text,
            )
        ),
        (
            "Email requests authentication "
            "or payment information"
        ),
        "credential_request",
        25,
    )

    urgency_patterns = [
        "within 24 hours",
        "within 12 hours",
        "final warning",
        "act now",
        "act immediately",
        "account will be closed",
        "permanently suspended",
        "immediate action",
    ]

    add_indicator(
        any(
            pattern in combined_text
            for pattern
            in urgency_patterns
        ),
        (
            "Email creates urgency or "
            "threatens negative consequences"
        ),
        "urgency",
        15,
    )

    add_indicator(
        body.count("!") >= 3,
        (
            "Email contains excessive "
            "exclamation marks"
        ),
        "formatting",
        8,
    )

    add_indicator(
        (
            subject.isupper()
            and len(subject) >= 6
        ),
        (
            "Subject uses aggressive "
            "uppercase formatting"
        ),
        "urgency",
        8,
    )

    valid_sender = bool(
        re.fullmatch(
            (
                r"[A-Za-z0-9._%+-]+"
                r"@[A-Za-z0-9.-]+"
                r"\.[A-Za-z]{2,}"
            ),
            sender_address,
        )
    )

    add_indicator(
        bool(sender)
        and not valid_sender,
        (
            "Sender email address is "
            "malformed"
        ),
        "sender",
        15,
    )

    suspicious_sender_terms = (
        count_matching_terms(
            sender_address,
            SUSPICIOUS_HOST_TERMS,
        )
    )

    add_indicator(
        len(suspicious_sender_terms) >= 2,
        (
            "Sender domain uses multiple "
            "security-related terms"
        ),
        "sender",
        12,
    )

    extracted_urls = (
        extract_urls(body)
    )

    for extracted_url in extracted_urls[:5]:
        url_result = analyze_url(
            extracted_url
        )

        if (
            url_result["risk_score"]
            >= 35
        ):
            url_weight = min(
                35,
                max(
                    15,
                    round(
                        url_result[
                            "risk_score"
                        ]
                        / 2
                    ),
                ),
            )

            risk_score += url_weight

            indicators.append(
                {
                    "indicator": (
                        "Suspicious embedded URL: "
                        f"{extracted_url}"
                    ),
                    "category": "url",
                    "weight": url_weight,
                }
            )

    rule_risk_score = min(
        round(risk_score),
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
        55
        + (len(indicators) * 7),
    )

    return {
        "risk_score":
            hybrid_risk_score,
        "rule_risk_score":
            rule_risk_score,
        "ml_risk_score":
            ml_risk_score,
        "verdict":
            calculate_verdict(
                hybrid_risk_score
            ),
        "confidence": confidence,
        "indicators": indicators,
        "extracted_urls":
            extracted_urls,
        "ml_analysis": ml_result,
        "detection_method":
            "hybrid-ml-rule-fusion-v2",
    }