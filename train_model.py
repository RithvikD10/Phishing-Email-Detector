from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "training_data.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_model.joblib"


def build_pipeline() -> Pipeline:
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    ngram_range=(1, 2),
                    stop_words="english",
                    min_df=1,
                    max_features=4000,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )


def main() -> None:
    frame = pd.read_csv(DATA_PATH)
    X_train, X_test, y_train, y_test = train_test_split(
        frame["text"],
        frame["label"],
        test_size=0.25,
        random_state=42,
        stratify=frame["label"],
    )

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    predictions = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)

    print(f"Model saved to: {MODEL_PATH}")
    print(f"Accuracy: {accuracy:.3f}")
    print(classification_report(y_test, predictions, target_names=["legit", "phishing"]))


if __name__ == "__main__":
    main()
