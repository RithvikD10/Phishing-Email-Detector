from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np
import pandas as pd

MODEL_PATH = Path(__file__).resolve().parent / "models" / "phishing_model.joblib"

SUSPICIOUS_KEYWORDS = {
    "verify": 9,
    "urgent": 8,
    "immediately": 7,
    "suspend": 8,
    "suspicious activity": 10,
    "password": 8,
    "login": 7,
    "credentials": 10,
    "confirm": 5,
    "action required": 8,
    "click here": 9,
    "invoice": 4,
    "payment": 5,
    "gift card": 10,
    "wire transfer": 10,
    "docusign": 4,
    "security alert": 8,
    "mailbox": 7,
    "payroll": 6,
    "expire": 6,
    "expired": 6,
    "limited time": 5,
    "deactivation": 8,
    "reset": 6,
    "unusual sign-in": 10,
}

TRUSTED_DOMAINS = {
    "vt.edu",
    "gmail.com",
    "outlook.com",
    "microsoft.com",
    "google.com",
    "github.com",
    "company.com",
    "studentorg.org",
    "community.org",
    "consulting.co",
}

URL_PATTERN = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[\w.\-+]+@[\w.\-]+\.\w+", re.IGNORECASE)
DIGIT_OBFUSCATION_PATTERN = re.compile(r"[a-zA-Z]+\d+[a-zA-Z]*|[a-zA-Z]*\d+[a-zA-Z]+", re.IGNORECASE)


@dataclass
class DetectionResult:
    label: str
    risk_score: int
    model_probability: float
    keyword_score: float
    indicators: List[str]
    suspicious_terms: List[str]
    url_count: int
    exclamation_count: int
    text: str


def normalize_text(subject: str = "", sender: str = "", body: str = "") -> str:
    subject = (subject or "").strip()
    sender = (sender or "").strip()
    body = (body or "").strip()
    return f"Subject: {subject}\nSender: {sender}\n\n{body}".strip()


def extract_keywords(text: str) -> List[str]:
    lowered = text.lower()
    hits = [phrase for phrase in SUSPICIOUS_KEYWORDS if phrase in lowered]
    return sorted(hits, key=lambda item: SUSPICIOUS_KEYWORDS[item], reverse=True)


def keyword_score(text: str) -> float:
    hits = extract_keywords(text)
    score = sum(SUSPICIOUS_KEYWORDS[item] for item in hits)
    return float(min(score, 100))


def sender_risk(sender: str) -> List[str]:
    indicators: List[str] = []
    sender = (sender or "").strip().lower()

    if not sender:
        indicators.append("No sender address provided.")
        return indicators

    match = EMAIL_PATTERN.search(sender)
    if not match:
        indicators.append("Sender address format looks unusual.")
        return indicators

    domain = sender.split("@")[-1]
    if domain not in TRUSTED_DOMAINS:
        indicators.append(f"Sender domain '{domain}' is not in the trusted domain list.")

    if DIGIT_OBFUSCATION_PATTERN.search(domain):
        indicators.append("Sender domain contains alphanumeric obfuscation patterns.")
    return indicators


def text_indicators(text: str) -> List[str]:
    indicators: List[str] = []
    urls = URL_PATTERN.findall(text)
    lowered = text.lower()

    if urls:
        indicators.append(f"Contains {len(urls)} URL(s).")
    if len(urls) >= 2:
        indicators.append("Multiple links increase the likelihood of a phishing lure.")
    if "http://" in lowered:
        indicators.append("Uses an unsecured HTTP link.")
    if any(char.isupper() for char in text) and sum(1 for c in text if c.isupper()) > max(20, len(text) * 0.1):
        indicators.append("Excessive capitalization can signal urgency tactics.")
    exclamation_count = text.count("!")
    if exclamation_count >= 2:
        indicators.append("Multiple exclamation marks suggest pressure or urgency.")
    if "within twenty four hours" in lowered or "today" in lowered or "one hour" in lowered:
        indicators.append("Contains time pressure language.")
    if "password" in lowered and ("click" in lowered or "link" in lowered):
        indicators.append("Requests credentials alongside a link.")
    return indicators


class PhishingDetector:
    def __init__(self, model_path: Path | None = None) -> None:
        model_file = Path(model_path) if model_path else MODEL_PATH
        if not model_file.exists():
            raise FileNotFoundError(
                f"Model file not found at {model_file}. Run train_model.py first."
            )
        self.pipeline = joblib.load(model_file)

    def predict_proba(self, text: str) -> float:
        probability = self.pipeline.predict_proba([text])[0][1]
        return float(probability)

    def assess(self, subject: str = "", sender: str = "", body: str = "") -> DetectionResult:
        combined_text = normalize_text(subject=subject, sender=sender, body=body)
        model_probability = self.predict_proba(combined_text)
        suspicious_terms = extract_keywords(combined_text)
        k_score = keyword_score(combined_text)

        indicators = []
        indicators.extend(sender_risk(sender))
        indicators.extend(text_indicators(combined_text))

        url_count = len(URL_PATTERN.findall(combined_text))
        exclamation_count = combined_text.count("!")

        structure_score = min(
            35,
            (8 if url_count else 0)
            + (8 if "http://" in combined_text.lower() else 0)
            + (6 if exclamation_count >= 2 else 0)
            + (6 if any("time pressure" in item.lower() for item in indicators) else 0)
            + (7 if any("trusted domain list" in item.lower() for item in indicators) else 0),
        )

        blended_probability = (
            0.65 * model_probability
            + 0.25 * (k_score / 100)
            + 0.10 * (structure_score / 35 if structure_score else 0)
        )
        risk_score = int(round(min(max(blended_probability * 100, 0), 100)))

        if risk_score >= 70:
            label = "Likely Phishing"
        elif risk_score >= 45:
            label = "Suspicious / Needs Review"
        else:
            label = "Likely Legitimate"

        return DetectionResult(
            label=label,
            risk_score=risk_score,
            model_probability=model_probability,
            keyword_score=k_score,
            indicators=indicators,
            suspicious_terms=suspicious_terms[:8],
            url_count=url_count,
            exclamation_count=exclamation_count,
            text=combined_text,
        )

    def batch_assess(self, frame: pd.DataFrame) -> pd.DataFrame:
        required = {"subject", "sender", "body"}
        missing = required.difference(frame.columns)
        if missing:
            raise ValueError(f"Missing required column(s): {', '.join(sorted(missing))}")

        rows: List[Dict[str, object]] = []
        for _, row in frame.iterrows():
            result = self.assess(
                subject=str(row.get("subject", "")),
                sender=str(row.get("sender", "")),
                body=str(row.get("body", "")),
            )
            rows.append(
                {
                    "sender": row.get("sender", ""),
                    "subject": row.get("subject", ""),
                    "risk_score": result.risk_score,
                    "label": result.label,
                    "top_indicators": "; ".join(result.indicators[:3]),
                    "suspicious_terms": ", ".join(result.suspicious_terms[:5]),
                }
            )
        return pd.DataFrame(rows)
